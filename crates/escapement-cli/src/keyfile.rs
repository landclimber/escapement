//! A private account the user owns, kept in a key file, and a private claim prepared but not yet
//! confirmed.
//!
//! The key file holds the account's secret material exactly as LEZ derives the account from it
//! (`ask` → nullifier keys, `(d, z)` → viewing key; the account id is
//! `for_regular_private_account(npk, vpk)`) and the account's last known state (a Borsh `Account`),
//! which the next private transaction spends from (`NullifierWitness::Update`) and which the CLI
//! refreshes after every transaction by decrypting the account's new note. Nothing is proven or sent
//! to an account whose key file was not written first, so claimed funds are never left in an account
//! nobody holds the keys of.
//!
//! Files are written with mode 0600; `create_new` refuses to overwrite an existing file.

use std::{
    fs::OpenOptions,
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use lee::AccountId;
use lee_core::{
    account::Account, encryption::ViewingPublicKey, AuthorizationSecretKey, NullifierPublicKey,
    NullifierSecretKey,
};
use serde_json::{json, Value};

pub const KEY_FILE_FORMAT: &str = "escapement-private-account/1";
pub const PENDING_FORMAT: &str = "escapement-pending-private-claim/1";

/// A regular private account's secret material.
pub struct PrivateKeys {
    pub ask: [u8; 32],
    pub d: [u8; 32],
    pub z: [u8; 32],
}

impl PrivateKeys {
    #[must_use]
    pub fn from_seed_bytes(ask: [u8; 32], d: [u8; 32], z: [u8; 32]) -> Self {
        Self { ask, d, z }
    }

    #[must_use]
    pub fn ask(&self) -> AuthorizationSecretKey {
        AuthorizationSecretKey(self.ask)
    }

    #[must_use]
    pub fn nsk(&self) -> NullifierSecretKey {
        NullifierSecretKey::from(&self.ask())
    }

    #[must_use]
    pub fn npk(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&self.nsk())
    }

    #[must_use]
    pub fn vpk(&self) -> ViewingPublicKey {
        ViewingPublicKey::from_seed(&self.d, &self.z)
    }

    #[must_use]
    pub fn id(&self) -> AccountId {
        AccountId::for_regular_private_account(&self.npk(), &self.vpk())
    }

    /// The public half, as the SDK's target check takes it.
    #[must_use]
    pub fn sdk_keys(&self) -> escapement_sdk::PrivateAccountKeys {
        escapement_sdk::PrivateAccountKeys {
            npk: self.npk(),
            vpk: self.vpk(),
        }
    }
}

fn hex32(v: &Value, field: &str) -> Result<[u8; 32]> {
    let s = v[field]
        .as_str()
        .with_context(|| format!("key file: missing {field}"))?;
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow!("key file: {field} is not 32 bytes"))
}

/// A user-owned private account: its keys and its last known state.
pub struct PrivateAccountFile {
    pub path: PathBuf,
    pub keys: PrivateKeys,
    pub state: Option<Account>,
}

fn write_0600(path: &Path, text: &str, create_new: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).mode(0o600);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    let mut f = options
        .open(path)
        .with_context(|| format!("open {} for writing", path.display()))?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

impl PrivateAccountFile {
    /// Creates a new account with fresh keys and writes it; refuses an existing path.
    pub fn create(path: &Path, keys: PrivateKeys) -> Result<Self> {
        let file = Self {
            path: path.to_path_buf(),
            keys,
            state: None,
        };
        write_0600(path, &file.to_json()?.to_string(), true)?;
        Ok(file)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let v: Value = serde_json::from_str(&text)?;
        if v["format"] != KEY_FILE_FORMAT {
            bail!("{} is not an {KEY_FILE_FORMAT} key file", path.display());
        }
        let keys =
            PrivateKeys::from_seed_bytes(hex32(&v, "ask")?, hex32(&v, "d")?, hex32(&v, "z")?);
        let recorded = v["account"].as_str().unwrap_or_default();
        if recorded != keys.id().to_string() {
            bail!(
                "{}: the keys derive {}, the file says {recorded}",
                path.display(),
                keys.id()
            );
        }
        let state = match v["state_borsh_hex"].as_str() {
            Some(h) => Some(borsh::from_slice::<Account>(&hex::decode(h)?)?),
            None => None,
        };
        Ok(Self {
            path: path.to_path_buf(),
            keys,
            state,
        })
    }

    fn to_json(&self) -> Result<Value> {
        Ok(json!({
            "format": KEY_FILE_FORMAT,
            "account": self.keys.id().to_string(),
            "ask": hex::encode(self.keys.ask),
            "d": hex::encode(self.keys.d),
            "z": hex::encode(self.keys.z),
            "state_borsh_hex": match &self.state {
                Some(s) => Value::String(hex::encode(borsh::to_vec(s)?)),
                None => Value::Null,
            },
        }))
    }

    /// Records the account's new state (after a transaction), keeping mode 0600.
    pub fn save_state(&mut self, state: Account) -> Result<()> {
        self.state = Some(state);
        let tmp = self.path.with_extension("tmp-write");
        let _ = std::fs::remove_file(&tmp);
        write_0600(&tmp, &self.to_json()?.to_string(), true)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// The account's native balance in its last known state (0 for a new account).
    #[must_use]
    pub fn native_balance(&self) -> u128 {
        self.state
            .as_ref()
            .and_then(|s| s.data.native_balance().ok())
            .unwrap_or(0)
    }

    fn pending_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".pending-claim");
        PathBuf::from(p)
    }

    /// Stores a prepared private claim (its one-time factor is secret: mode 0600).
    pub fn save_pending(&self, pending: &PendingClaim) -> Result<()> {
        let path = self.pending_path();
        let _ = std::fs::remove_file(&path);
        write_0600(&path, &pending.to_json().to_string(), true)
    }

    pub fn load_pending(&self) -> Result<PendingClaim> {
        let path = self.pending_path();
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "no prepared private claim at {}: run the claim once without --confirm",
                path.display()
            )
        })?;
        PendingClaim::from_json(&serde_json::from_str(&text)?)
    }

    pub fn clear_pending(&self) {
        let _ = std::fs::remove_file(self.pending_path());
    }
}

/// A private claim shown to the user with its disclosure, awaiting the disclosure's token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingClaim {
    pub schedule: AccountId,
    pub amount: u128,
    pub effective_ts: u64,
    pub factor: [u8; 32],
    pub token_hex: String,
}

impl PendingClaim {
    fn to_json(&self) -> Value {
        json!({
            "format": PENDING_FORMAT,
            "schedule": self.schedule.to_string(),
            "amount": self.amount.to_string(),
            "effective_ts": self.effective_ts,
            "factor": hex::encode(self.factor),
            "disclosure_token": self.token_hex,
        })
    }

    fn from_json(v: &Value) -> Result<Self> {
        if v["format"] != PENDING_FORMAT {
            bail!("not an {PENDING_FORMAT} file");
        }
        Ok(Self {
            schedule: v["schedule"]
                .as_str()
                .context("pending: schedule")?
                .parse::<AccountId>()
                .map_err(|e| anyhow!("pending: schedule: {e:?}"))?,
            amount: v["amount"].as_str().context("pending: amount")?.parse()?,
            effective_ts: v["effective_ts"]
                .as_u64()
                .context("pending: effective_ts")?,
            factor: hex32(v, "factor")?,
            token_hex: v["disclosure_token"]
                .as_str()
                .context("pending: token")?
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn dir() -> PathBuf {
        let base = std::env::var("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
        let d = base.join(format!("keyfile-tests-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn keys(b: u8) -> PrivateKeys {
        PrivateKeys::from_seed_bytes([b; 32], [b.wrapping_add(1); 32], [b.wrapping_add(2); 32])
    }

    #[test]
    fn a_key_file_is_0600_refuses_overwrite_and_round_trips_keys_and_state() {
        let path = dir().join("a.json");
        let _ = std::fs::remove_file(&path);
        let mut f = PrivateAccountFile::create(&path, keys(7)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            PrivateAccountFile::create(&path, keys(8)).is_err(),
            "an existing key file is never overwritten"
        );
        let loaded = PrivateAccountFile::load(&path).unwrap();
        assert_eq!(loaded.keys.id(), keys(7).id());
        assert!(loaded.state.is_none());
        f.save_state(Account::funded(42)).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "saving the state keeps the file private");
        let reloaded = PrivateAccountFile::load(&path).unwrap();
        assert_eq!(reloaded.native_balance(), 42);
        assert_eq!(reloaded.state, Some(Account::funded(42)));
    }

    #[test]
    fn a_tampered_account_id_is_refused() {
        let path = dir().join("b.json");
        let _ = std::fs::remove_file(&path);
        PrivateAccountFile::create(&path, keys(9)).unwrap();
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace(&keys(9).id().to_string(), &keys(10).id().to_string());
        std::fs::write(&path, text).unwrap();
        assert!(PrivateAccountFile::load(&path).is_err());
    }

    #[test]
    fn a_pending_claim_round_trips_and_is_private() {
        let path = dir().join("c.json");
        let _ = std::fs::remove_file(&path);
        let f = PrivateAccountFile::create(&path, keys(11)).unwrap();
        let p = PendingClaim {
            schedule: keys(12).id(),
            amount: 5,
            effective_ts: 6,
            factor: [3; 32],
            token_hex: "ab".into(),
        };
        f.save_pending(&p).unwrap();
        let mode = std::fs::metadata(f.pending_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(f.load_pending().unwrap(), p);
        f.clear_pending();
        assert!(f.load_pending().is_err());
    }
}
