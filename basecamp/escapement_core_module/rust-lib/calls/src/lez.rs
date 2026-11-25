//! LEZ v0.4.0-rc3's public transaction and JSON-RPC, without LEZ's node crates.
//!
//! The encoding is `TransactionMessage<PublicExecution>` as `lee/state_machine/src/public_transaction/message.rs`
//! (tag `v0.4.0-rc3`, commit bafd07be) lays it out, checked below against that file's pinned layout test; the
//! signature is BIP-340 over `SHA-256(prefix ‖ message)` with the raw secp256k1 key (`WitnessSet::for_message`,
//! `PublicKey::new_from_private_key`: x-only, no tweak). Ported from Ferrata's `ferrata_bridge_module` (`lezkey.rs`),
//! which is checked against LEZ's vectors and transactions LEZ's wallet signed.
//!
//! The signing key is held only in [`Key`]: zeroized when dropped, no `Debug`, never serialized.

use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub type Id = [u8; 32];

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn pad32(s: &str) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..s.len()].copy_from_slice(s.as_bytes());
    b
}

const MESSAGE_PUBLIC_PREFIX: &str = "/LEE/v0.3/Message/Public/";
const ACCOUNT_ID_PUBLIC_PREFIX: &str = "/LEE/v0.3/AccountId/Public/";

// ------------------------------------------------------------------------------------------------ keys

/// A public account's signing key (LEZ's `PrivateKey`: a non-zero secp256k1 scalar).
pub struct Key {
    sk: Zeroizing<[u8; 32]>,
    pub pk: [u8; 32],
    pub id: Id,
}

impl Key {
    pub fn from_bytes(sk: &[u8; 32]) -> Result<Self, String> {
        let pk = public_key_of(sk)?;
        Ok(Key { sk: Zeroizing::new(*sk), pk, id: account_id_of(&pk) })
    }

    /// The largest key file read: a key is 64 hex digits, `escapement keygen`'s JSON about 140 bytes.
    pub const MAX_KEY_FILE: u64 = 4096;

    /// A key from a key file: a regular file of at most [`Key::MAX_KEY_FILE`] bytes, read into a buffer wiped on drop.
    /// Anything else (a directory, a device, a pipe, a larger file) is refused before it is read.
    pub fn from_file(path: &str) -> Result<Self, String> {
        use std::io::Read as _;
        let meta = std::fs::metadata(path).map_err(|e| format!("cannot read the key file {path}: {e}"))?;
        if !meta.is_file() {
            return Err(format!("{path} is not a regular file: a key file is a small text file"));
        }
        if meta.len() > Self::MAX_KEY_FILE {
            return Err(format!("{path} is larger than {} bytes: not a key file", Self::MAX_KEY_FILE));
        }
        // Opened without blocking (a FIFO swapped in after the check does not hang the module), then checked again as
        // opened: the file read is the regular, small file the check saw (review R1 Kimi M4).
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.custom_flags(0o4000); // O_NONBLOCK
        }
        let f = opts.open(path).map_err(|e| format!("cannot read the key file {path}: {e}"))?;
        let opened = f.metadata().map_err(|e| format!("cannot read the key file {path}: {e}"))?;
        if !opened.is_file() || opened.len() > Self::MAX_KEY_FILE {
            return Err(format!("{path} changed while it was read: not a key file"));
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(Self::MAX_KEY_FILE as usize + 1));
        f.take(Self::MAX_KEY_FILE + 1).read_to_end(&mut buf).map_err(|e| format!("cannot read the key file {path}: {e}"))?;
        if buf.len() as u64 > Self::MAX_KEY_FILE {
            return Err(format!("{path} is larger than {} bytes: not a key file", Self::MAX_KEY_FILE));
        }
        Self::from_slice(&buf)
    }

    /// A key from text: 64 hex digits (what `escapement keygen` prints as `key`), or a JSON object with `key`.
    pub fn from_text(text: &str) -> Result<Self, String> {
        Self::from_slice(text.as_bytes())
    }

    fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        const BAD: &str = "the key file holds no key: expected 64 hex digits, or JSON with \"key\" (as `escapement keygen` prints)";
        let t = bytes.trim_ascii();
        let mut b = Zeroizing::new([0u8; 32]);
        if t.first() == Some(&b'{') {
            // The parsed copy of the key string is wiped before the value is dropped.
            let mut v: Value = serde_json::from_slice(t).map_err(|_| BAD.to_string())?;
            let decoded = match v.get_mut("key") {
                Some(Value::String(k)) => {
                    let r = decode_key_hex(k.as_bytes(), &mut b);
                    zeroize::Zeroize::zeroize(k);
                    r
                }
                _ => Err(()),
            };
            decoded.map_err(|_| BAD.to_string())?;
        } else {
            decode_key_hex(t, &mut b).map_err(|_| BAD.to_string())?;
        }
        Self::from_bytes(&b)
    }

    /// A fresh key from the operating system's randomness.
    pub fn fresh() -> Result<Self, String> {
        loop {
            let mut b = Zeroizing::new([0u8; 32]);
            getrandom::getrandom(b.as_mut()).map_err(|e| format!("no randomness from the operating system: {e}"))?;
            if let Ok(k) = Self::from_bytes(&b) {
                return Ok(k);
            }
        }
    }

    /// The key as 64 hex digits, for the module's own key file (mode 0600) only.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.sk.as_ref()))
    }

    /// BIP-340 over `hash32` with the operating system's randomness as `aux`.
    pub fn sign(&self, hash32: &[u8; 32]) -> Result<[u8; 64], String> {
        #[cfg(test)]
        SIGNATURES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut aux = [0u8; 32];
        getrandom::getrandom(&mut aux).map_err(|e| format!("no randomness from the operating system: {e}"))?;
        sign(&self.sk, hash32, &aux)
    }
}

/// Signatures made by [`Key::sign`] (tests: nothing is signed that is not sent).
#[cfg(test)]
pub static SIGNATURES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 64 hex digits (an optional `0x` before them), surrounding whitespace ignored, into `out`.
fn decode_key_hex(text: &[u8], out: &mut [u8; 32]) -> Result<(), ()> {
    let t = text.trim_ascii();
    let h = t.strip_prefix(b"0x").unwrap_or(t);
    if h.len() != 64 {
        return Err(());
    }
    hex::decode_to_slice(h, out).map_err(|_| ())
}

/// The x-only public key of a key (LEZ's `PublicKey::new_from_private_key`).
pub fn public_key_of(sk: &[u8; 32]) -> Result<[u8; 32], String> {
    let k = k256::schnorr::SigningKey::from_bytes(sk).map_err(|_| "not a valid secp256k1 key".to_string())?;
    Ok(k.verifying_key().to_bytes().into())
}

/// LEZ's `AccountId::from(&PublicKey)`.
pub fn account_id_of(pk: &[u8; 32]) -> Id {
    sha256(&[&pad32(ACCOUNT_ID_PUBLIC_PREFIX), pk])
}

/// BIP-340 (LEZ's `Signature::new`).
pub fn sign(sk: &[u8; 32], hash32: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 64], String> {
    let k = k256::schnorr::SigningKey::from_bytes(sk).map_err(|_| "not a valid signing key".to_string())?;
    let sig = k.sign_raw(hash32, aux).map_err(|e| format!("signing: {e}"))?;
    Ok(sig.to_bytes())
}

// ------------------------------------------------------------------------------------------------ the transaction

/// An account as a program sees it: (account id, program id).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Actor {
    pub account: Id,
    pub program: Id,
}

pub struct Fee {
    pub payer: Id,
    pub gas_limit: u64,
    pub tip: u64,
    pub max_fee: u128,
}

/// `TransactionMessage<PublicExecution>`: the signers are the accounts that name a nonce.
pub struct Message {
    pub actors: Vec<Actor>,
    pub to: Actor,
    pub data: Vec<u8>,
    pub fee: Option<Fee>,
    pub nonces: Vec<(Id, u128)>,
}

fn u32le(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_le_bytes());
}

/// The message's borsh: actors (sorted, deduplicated: a `BTreeSet`), the authorized accounts (the nonces' accounts),
/// no promotions, the root call, the fee, the nonces (sorted by account), no admission evidence.
pub fn encode_message(m: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    let mut actors = m.actors.clone();
    actors.sort();
    actors.dedup();
    u32le(&mut out, actors.len());
    for a in &actors {
        out.extend_from_slice(&a.account);
        out.extend_from_slice(&a.program);
    }
    let mut nonces = m.nonces.clone();
    nonces.sort_by(|a, b| a.0.cmp(&b.0));
    nonces.dedup_by(|a, b| a.0 == b.0);
    u32le(&mut out, nonces.len());
    for (id, _) in &nonces {
        out.extend_from_slice(id);
    }
    u32le(&mut out, 0);
    out.extend_from_slice(&m.to.account);
    out.extend_from_slice(&m.to.program);
    u32le(&mut out, m.data.len());
    out.extend_from_slice(&m.data);
    match &m.fee {
        Some(f) => {
            out.push(1);
            out.extend_from_slice(&f.payer);
            out.extend_from_slice(&f.gas_limit.to_le_bytes());
            out.extend_from_slice(&f.tip.to_le_bytes());
            out.extend_from_slice(&f.max_fee.to_le_bytes());
        }
        None => out.push(0),
    }
    u32le(&mut out, nonces.len());
    for (id, n) in &nonces {
        out.extend_from_slice(id);
        out.extend_from_slice(&n.to_le_bytes());
    }
    u32le(&mut out, 0);
    out
}

pub fn message_hash(message: &[u8]) -> [u8; 32] {
    sha256(&[&pad32(MESSAGE_PUBLIC_PREFIX), message])
}

/// `PublicTransaction`'s borsh: the message, then the witness set's (signature, public key) pairs.
pub fn encode_transaction(message: &[u8], witnesses: &[([u8; 64], [u8; 32])]) -> Vec<u8> {
    let mut out = message.to_vec();
    u32le(&mut out, witnesses.len());
    for (sig, pk) in witnesses {
        out.extend_from_slice(sig);
        out.extend_from_slice(pk);
    }
    out
}

/// `LeeTransaction::Public(tx)` as `sendTransaction` takes it (base64 of borsh), and the hash LEZ names it by.
pub fn wire(tx: &[u8]) -> (String, String) {
    use base64::Engine as _;
    let mut b = Vec::with_capacity(tx.len() + 1);
    b.push(0);
    b.extend_from_slice(tx);
    (base64::engine::general_purpose::STANDARD.encode(&b), hex::encode(sha256(&[tx])))
}

pub fn id_string(id: &Id) -> String {
    bs58::encode(id).into_string()
}

pub fn id_from_string(s: &str) -> Result<Id, String> {
    let t = s.trim().trim_start_matches("Public/");
    if t.is_empty() {
        return Err("an account id is empty".into());
    }
    let v = bs58::decode(t).into_vec().map_err(|_| format!("{t:?} is not an account id (base58)"))?;
    v.try_into().map_err(|_| format!("{t:?} is not an account id (32 bytes)"))
}

// ------------------------------------------------------------------------------------------------ JSON-RPC

/// Why a JSON-RPC call has no result: the answer did not arrive (or was not one), or the sequencer refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    Transport(String),
    Refused(String),
}

/// A sequencer's JSON-RPC: `http://` only to a literal loopback address (127.0.0.1 or [::1]), `https://` anywhere.
#[derive(Clone, Debug)]
pub struct Rpc {
    pub url: String,
}

pub fn check_url(url: &str) -> Result<String, String> {
    let u = url.trim();
    let bad = |why: &str| Err(format!("{u:?} is not a sequencer address ({why}): use http://127.0.0.1:PORT or https://HOST[:PORT]/PATH"));
    // Printable ASCII only, and none of the characters that let URL parsers disagree on the host: no user name or
    // password (`@`), no percent-escapes, no backslash, no query or fragment.
    if u.is_empty() || !u.bytes().all(|b| b.is_ascii_graphic()) {
        return bad("spaces or non-ASCII characters");
    }
    if u.contains(['@', '%', '\\', '?', '#']) {
        return bad("it may not contain @, %, \\, ? or #");
    }
    let (scheme, rest) = if let Some(r) = u.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = u.strip_prefix("https://") {
        ("https", r)
    } else {
        return bad("only http:// and https://");
    };
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (host, port) = if let Some(r) = authority.strip_prefix('[') {
        let Some(close) = r.find(']') else { return bad("an unclosed [") };
        let h = &r[..close];
        if h.is_empty() || !h.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.') {
            return bad("an IPv6 address that is not one");
        }
        (h, &r[close + 1..])
    } else {
        let (h, p) = authority.split_at(authority.find(':').unwrap_or(authority.len()));
        if h.is_empty() || !h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
            return bad("a host name of letters, digits, dots and dashes");
        }
        (h, p)
    };
    if !port.is_empty() {
        let digits = port.strip_prefix(':').unwrap_or("x");
        if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) || !(1..=65535).contains(&digits.parse::<u32>().unwrap_or(0)) {
            return bad("a port of 1 to 65535");
        }
    }
    if !path.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._~-".contains(&b)) {
        return bad("a path of letters, digits and / . _ ~ -");
    }
    if scheme == "http" && !matches!(host, "127.0.0.1" | "::1") {
        return Err(format!("{u}: plain http:// is allowed only to this machine's literal address (127.0.0.1 or [::1]); use https:// for a remote sequencer"));
    }
    Ok(u.trim_end_matches('/').to_string())
}

impl Rpc {
    pub fn new(url: &str) -> Result<Self, String> {
        Ok(Rpc { url: check_url(url)? })
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.call_raw(method, params).map_err(|e| match e {
            RpcError::Transport(m) | RpcError::Refused(m) => m,
        })
    }

    /// As [`Rpc::call`], telling apart an answer that did not arrive (transport, HTTP status, not JSON) from the
    /// sequencer's own refusal (a JSON-RPC `error`): review R2 L1.
    pub fn call_raw(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let t = RpcError::Transport;
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(10)))
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .into();
        let mut r = agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .send(&body)
            .map_err(|e| t(format!("the sequencer at {} did not answer ({e}); is it running?", self.url)))?;
        let status = r.status().as_u16();
        let text = r
            .body_mut()
            .with_config()
            .limit(32 << 20)
            .read_to_string()
            .map_err(|e| t(format!("reading the sequencer's answer: {e}")))?;
        if status != 200 {
            return Err(t(format!("{method}: the sequencer at {} answered HTTP {status}", self.url)));
        }
        let v: Value = serde_json::from_str(&text).map_err(|e| t(format!("{method}: the answer is not JSON: {e}")))?;
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError::Refused(format!("{method}: {}", e["message"].as_str().map_or_else(|| e.to_string(), str::to_string))));
        }
        Ok(v["result"].clone())
    }

    pub fn head(&self) -> Result<u64, String> {
        self.call("getLastBlockId", json!([]))?.as_u64().ok_or_else(|| "getLastBlockId: not a number".into())
    }

    /// The actor state of `account` under `program`, if any (empty when the account has none).
    pub fn state(&self, account: &Id, program: &Id) -> Result<Vec<u8>, String> {
        let a = self.call("getAccount", json!([id_string(account)]))?;
        if a.is_null() {
            return Ok(Vec::new());
        }
        state_bytes(&a["data"]["actor_states"][id_string(program)])
    }

    pub fn balance(&self, id: &Id) -> Result<u128, String> {
        amount(&self.call("getAccountBalance", json!([id_string(id)]))?, "getAccountBalance")
    }

    pub fn nonce(&self, id: &Id) -> Result<u128, String> {
        let v = self.call("getAccountsNonces", json!([[id_string(id)]]))?;
        amount(&v[0], "getAccountsNonces")
    }

    pub fn base_fees(&self) -> Result<(u128, u128), String> {
        let f = self.call("getFeeState", json!([]))?;
        Ok((amount(&f["base_fee_exec"], "base_fee_exec")?, amount(&f["base_fee_stor"], "base_fee_stor")?))
    }

    /// The block holding a transaction, once it is in one.
    pub fn block_of(&self, hash: &str) -> Result<Option<u64>, String> {
        let t = self.call("getTransaction", json!([hash]))?;
        Ok(match &t {
            Value::Null => None,
            Value::Array(a) => a.get(1).and_then(Value::as_u64),
            _ => t["block_id"].as_u64(),
        })
    }

    pub fn send(&self, wire: &str) -> Result<Value, RpcError> {
        self.call_raw("sendTransaction", json!([wire]))
    }
}

/// An actor state as the RPC gives it: bytes (each 0..=255) or base64.
fn state_bytes(v: &Value) -> Result<Vec<u8>, String> {
    match v {
        Value::Null => Ok(Vec::new()),
        Value::Array(bytes) => bytes
            .iter()
            .map(|b| b.as_u64().filter(|x| *x < 256).map(|x| x as u8))
            .collect::<Option<Vec<u8>>>()
            .ok_or_else(|| "an actor state that is not bytes".into()),
        Value::String(s) => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(s).map_err(|_| "an actor state that is not base64".into())
        }
        _ => Err("an actor state in an unknown form".into()),
    }
}

/// An amount the RPC sends as a JSON number or a decimal string.
fn amount(v: &Value, what: &str) -> Result<u128, String> {
    match v {
        Value::Number(n) => n.as_u64().map(u128::from).ok_or_else(|| format!("{what}: not an amount")),
        Value::String(s) => s.parse::<u128>().map_err(|_| format!("{what}: not an amount")),
        _ => Err(format!("{what}: no amount")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // LEZ rc3's own pinned layout (public_transaction/message.rs, `a_public_message_has_a_pinned_layout_and_hash`).
    #[test]
    fn lez_rc3_pinned_message_layout() {
        let to = Actor { account: [42; 32], program: [0; 32] };
        let m = Message { actors: vec![to], to, data: vec![0], fee: None, nonces: vec![([42; 32], 1)] };
        let expected: Vec<u8> = [
            &[1, 0, 0, 0][..],
            &[42; 32],
            &[0; 32],
            &[1, 0, 0, 0],
            &[42; 32],
            &[0, 0, 0, 0],
            &[42; 32],
            &[0; 32],
            &[1, 0, 0, 0],
            &[0],
            &[0],
            &[1, 0, 0, 0],
            &[42; 32],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0, 0, 0, 0],
        ]
        .concat();
        let bytes = encode_message(&m);
        assert_eq!(bytes, expected);
        let mut h = Sha256::new();
        h.update(b"/LEE/v0.3/Message/Public/\x00\x00\x00\x00\x00\x00\x00");
        h.update(&expected);
        let digest: [u8; 32] = h.finalize().into();
        assert_eq!(message_hash(&bytes), digest);
    }

    // BIP-340's own vectors.
    #[test]
    fn bip340_vectors() {
        let v = [
            ("0000000000000000000000000000000000000000000000000000000000000003", "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
             "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000",
             "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
        ];
        for (sk, pk, aux, msg, sig) in v {
            let h = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
            let s = sign(&h(sk), &h(msg), &h(aux)).unwrap();
            assert_eq!(hex::encode_upper(s), sig);
            assert_eq!(hex::encode_upper(public_key_of(&h(sk)).unwrap()), pk);
        }
    }

    #[test]
    fn keys_from_text_and_urls() {
        let k = Key::from_text(&format!("{}\n", "01".repeat(32))).unwrap();
        let j = Key::from_text(&format!("{{\"key\":\"{}\",\"account\":\"x\"}}", "01".repeat(32))).unwrap();
        assert_eq!(k.id, j.id);
        assert_eq!(id_from_string(&id_string(&k.id)).unwrap(), k.id);
        assert!(Key::from_text("zz").is_err());
        assert!(Key::from_text(&"00".repeat(32)).is_err());
        assert!(check_url("http://127.0.0.1:3040").is_ok());
        assert!(check_url("http://example.com/rpc").is_err());
        assert!(check_url("https://host.example/rpc").is_ok());
    }

    // Review R1 M2: the host is the authority's, not the text before the first ':' (userinfo bypass).
    #[test]
    fn sequencer_addresses_are_read_strictly() {
        for bad in [
            "http://127.0.0.1:1@evil.example/",
            "http://127.0.0.1:1@127.0.0.2:18555/",
            "https://u@host/",
            "https://user:pw@host.example/rpc",
            "http://127.0.0.1.evil.example/",
            "http://localhost.evil.example:3040/",
            "http://127.0.0.1\\@evil.example/",
            "http://127.0.0.1%40evil.example/",
            "http://127.0.0.1:3040?x=@evil",
            "http://127.0.0.1:3040#@evil",
            "http://127.0.0.1 :3040",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:",
            "http://[::1",
            "http://[::2]:3040",
            "ftp://127.0.0.1",
            "https://",
            // Kimi M2: a trailing dot, a scheme in capitals.
            "http://127.0.0.1./",
            "http://localhost.:3040",
            "HTTP://127.0.0.1:3040",
        ] {
            assert!(check_url(bad).is_err(), "{bad} must be refused");
        }
        // Review R2 nit: `localhost` goes through the resolver; only literal loopback addresses are plain-http hosts.
        for bad in ["http://localhost:3040/", "http://LocalHost:3040"] {
            assert!(check_url(bad).is_err(), "{bad} must be refused");
        }
        for good in ["http://127.0.0.1:3040", "http://[::1]:3040", "https://host.example/rpc", "https://h.example:8443/a/b"] {
            assert!(check_url(good).is_ok(), "{good} must be accepted");
        }
        assert_eq!(check_url("http://[::1]:3040/").unwrap(), "http://[::1]:3040");
    }

    // Review R1 M3/L4: a key file is a small regular file; the JSON and the hex forms still read.
    #[test]
    fn key_files_are_small_regular_files() {
        let d = std::env::temp_dir().join(format!("esc-keyfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = |n: &str| d.join(n).display().to_string();
        std::fs::write(p("hex"), format!("{}\n", "01".repeat(32))).unwrap();
        std::fs::write(p("json"), format!("{{\"key\":\"{}\",\"account\":\"x\"}}", "01".repeat(32))).unwrap();
        std::fs::write(p("big"), format!("{}{}", "01".repeat(32), " ".repeat(5000))).unwrap();
        // `Key` has no Debug (a key is never printed), so the errors are taken out by hand.
        let err = |r: Result<Key, String>| match r {
            Err(e) => e,
            Ok(_) => panic!("expected the key file to be refused"),
        };
        assert_eq!(Key::from_file(&p("hex")).map(|k| k.id).ok(), Key::from_file(&p("json")).map(|k| k.id).ok());
        assert!(Key::from_file(&p("hex")).is_ok());
        assert!(err(Key::from_file(&p("big"))).contains("larger than"));
        assert!(err(Key::from_file(&d.display().to_string())).contains("not a regular file"));
        if std::path::Path::new("/dev/zero").exists() {
            assert!(err(Key::from_file("/dev/zero")).contains("not a regular file"));
        }
        // A FIFO is refused at once (reading it would wait for a writer).
        if std::process::Command::new("mkfifo").arg(p("fifo")).status().map(|s| s.success()).unwrap_or(false) {
            let t0 = std::time::Instant::now();
            assert!(err(Key::from_file(&p("fifo"))).contains("not a regular file"));
            assert!(t0.elapsed() < std::time::Duration::from_secs(2));
        }
        assert!(Key::from_file(&p("missing")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
