//! `escapement`: the Escapement vesting program's CLI over a LEZ v0.4.0-rc3 sequencer's JSON-RPC.
//!
//! ```text
//! escapement keygen                                    a fresh public key (hex) and its account id
//! escapement fund --to-key HEX --amount N              native transfer to a fresh account (admits it)
//! escapement probe                                     head block, clock, fee state
//! escapement deploy ELF [--init-admin] [--keys-out F]  immutable program_loader deployment, header read back
//! escapement configure --admin-key HEX --fee-bps N [--treasury ID] [--token-program ID]
//! escapement token new --supply N                      a token definition, supply to the signer's holding
//! escapement token init-holding --definition ID        the signer's public holding of a token
//! escapement create --beneficiary ID --total N (--linear S,E | --cliff S,C,E,CLIFF | --milestones A,B,..)
//!                   [--token ID [--funding-holding ID]] [--non-cancelable] [--transferable]
//!                   [--cancel-authority ID] [--milestone-authority ID] [--refund-to ID] [--salt HEX] [--fee]
//! escapement show --schedule ID                        terms, tranches, claimable now, next unlock
//! escapement claim --schedule ID [--amount N] --to ID  public claim
//! escapement claim --schedule ID [--amount N] --to-private FILE [--confirm TOKEN]
//!                                                      private claim into a private account you own
//! escapement private-account new --out FILE            a private account's keys, written 0600
//! escapement private-account show --file FILE          its id, last known balances, whether that state is on chain
//! escapement private-account shield --file FILE --amount N           native into it (pays its own fee)
//! escapement private-account init-holding --file FILE --definition ID   a private token holding (fee from its native balance)
//! escapement cancel --schedule ID | make-non-cancelable --schedule ID
//! escapement signal --schedule ID --index I | transfer-beneficiary --schedule ID --to ID
//! escapement withdraw-fees --to ID --amount N          (native fee vault; treasury key)
//! ```
//!
//! **Private claims go only to a private account whose keys you hold.** `private-account new` writes
//! the account's secret material to a 0600 file before anything is proven; every private transaction
//! spends from the state recorded there and records the account's new state (decrypted from its own
//! note) afterwards, so claimed funds are never sent to an account nobody can spend from. A private
//! claim runs in two steps: the first prints the privacy disclosure for this exact claim (amount,
//! one-time alias, fee reserve) and its confirmation token and stores the prepared claim (0600); the
//! second, with `--confirm TOKEN`, rebuilds the same claim, refuses if the disclosure changed, proves
//! and sends it. The SDK's checks run first: the target is a private account derived from the keys
//! given (+Privacy 3), something is claimable (U7, with the next unlock time), and the fee payer
//! covers the fee reserve before anything is proven (U4). The fee is paid inside the proof by the
//! private account itself: out of the claimed credit for native schedules, from its native balance
//! (fund it with `private-account shield`) for token schedules. The reserve is the fee at the current
//! base fees, so no refund has to be received later.
//!
//! `--dry-run` is available on create, claim, cancel, make-non-cancelable, signal,
//! transfer-beneficiary and withdraw-fees (print what would be sent, send nothing); `--no-precheck`
//! (skip the SDK's checks and the local simulation, so the program itself refuses: used by the
//! end-to-end suite to test refusals on chain). Unknown flags are refused.
//!
//! Environment: `LEZ_RPC` (default `http://127.0.0.1:3040`, loopback only: this tool never talks
//! to a public network), `ESCAPEMENT_KEY` (signer and fee payer, hex; default LEZ's published local
//! test key from `lez/sequencer/service/networks/local.json`), `ESCAPEMENT_PROGRAM` (the deployed
//! program's address), `ESCAPEMENT_ELF` (the deployed guest binary, for local simulation and
//! private-claim proving), `ESCAPEMENT_TOKEN_PROGRAM` and `ESCAPEMENT_TOKEN_ELF` (the token program's
//! address and binary, for token schedules). Proofs are real unless `RISC0_DEV_MODE=1`. Each command
//! prints one JSON line to stdout; progress and human-readable summaries go to stderr.

mod keyfile;

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    io::{Read, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use common::{transaction::LeeTransaction, HashType};
use escapement_core::{
    config_pda, math::claimable_at, schedule_pda, single_escrow_pda, Asset, Message,
    MilestoneTranche, ScheduleAccount, ScheduleKind, VestingActorState,
};
use escapement_sdk::{
    builders::{self, Call, Deployment, ScheduleRequest},
    claim::{prepare_public_claim, ClaimContext},
    codes,
    destination::{validate_private_target, AccountLookup, PrivateDestination},
    disclosure::PrivacyDisclosure,
    fees::{check_private_gas, estimate_private_fee, FeeQuote},
    unlock::{next_unlock, utc},
    SdkError,
};
use keyfile::{PendingClaim, PrivateAccountFile, PrivateKeys};
use lee::{
    error::LeeError,
    privacy_preserving_transaction::{
        circuit::ProgramCatalog, Message as PrivateMessage, WitnessSet as PrivateWitnessSet,
    },
    program::Program,
    public_transaction::{Message as PublicMessage, WitnessSet},
    AccountId, Actor, FeeDeclaration, PrivacyPreservingTransaction, PrivateKey, ProvingInput,
    PublicAccountEvidence, PublicExecutionContext, PublicKey, PublicTransaction, Recipient,
    RecipientEncryption, SenderPresentation, Simulation,
};
use lee_core::{
    account::{ActorState, Nonce},
    encryption::{Ciphertext, EncryptedNote, MlKem768EncapsulationKey},
    execution_state::TransactionEntry,
    native_token,
    program::{MessageBody, ProgramHeader, PROGRAM_LOADER_ACCOUNT_ID},
    Commitment, DummyInput, DummyOutput, EncryptionScheme, EphemeralSecretKey, FeeTransfer,
    NullifierWitness, PrivateAccountKind, PrivateWitness, RegularKey, RootCall, SharedSecretKey,
    WitnessKind, DUMMY_COMMITMENT_HASH,
};
use lez_admin_authority::{admin_op, AdminOp};
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use serde_json::json;
use token_core::{Message as TokenMessage, TokenState};

/// LEZ's published local test key (Justfile `wallet-import-test-accounts`), funded by `local.json`.
const DEFAULT_KEY: &str = "7f273098f25b71e6c005a9519f2678da8d1c7f01f6a27778e2d9948abdf901fb";
/// rc3 wallet constants (`lez/wallet/src/account_manager.rs`).
const PADDED_PRIVATE_ACTIONS: usize = 7;
const CIPHERTEXT_PAD_SIZE: u32 = 512;
const MAX_GAS_EXEC: u64 = 10_000_000;

fn random_vec(len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("/dev/urandom");
    bytes
}

fn random_bytes() -> [u8; 32] {
    random_vec(32).try_into().expect("32 bytes")
}

fn id_of(key: &PrivateKey) -> AccountId {
    AccountId::from(&PublicKey::new_from_private_key(key))
}

fn fresh_key() -> PrivateKey {
    loop {
        if let Ok(key) = PrivateKey::try_new(random_bytes()) {
            return key;
        }
    }
}

fn key_from_hex(hex_key: &str) -> Result<PrivateKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim())?
        .try_into()
        .map_err(|_| anyhow!("a key is 32 bytes of hex"))?;
    PrivateKey::try_new(bytes).map_err(|e| anyhow!("invalid key: {e}"))
}

fn key_hex(key: &PrivateKey) -> String {
    hex::encode(key.value())
}

fn image_hex(id: [u32; 8]) -> String {
    hex::encode(id.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<_>>())
}

/// Refuses anything but a loopback URL (parsed strictly: no userinfo tricks).
fn loopback_url(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("LEZ_RPC must be http://127.0.0.1:PORT"))?;
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.contains('@') {
        bail!("LEZ_RPC must not carry userinfo");
    }
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
        bail!("LEZ_RPC host {host} is not loopback: this tool only drives a local sequencer");
    }
    Ok(url.to_string())
}

/// `--flag value` and `--switch` arguments after the command name.
struct Args {
    positional: Vec<String>,
    flags: BTreeMap<String, Option<String>>,
}

impl Args {
    fn parse(raw: &[String]) -> Self {
        let mut positional = Vec::new();
        let mut flags = BTreeMap::new();
        let mut i = 0;
        while i < raw.len() {
            if let Some(name) = raw[i].strip_prefix("--") {
                let value = raw.get(i + 1).filter(|v| !v.starts_with("--")).cloned();
                if value.is_some() {
                    i += 1;
                }
                flags.insert(name.to_string(), value);
            } else {
                positional.push(raw[i].clone());
            }
            i += 1;
        }
        Self { positional, flags }
    }

    fn has(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }

    /// Refuses any flag the command does not take (a typo must never send a different
    /// transaction from the one meant).
    fn check(&self, allowed: &[&str]) -> Result<()> {
        for name in self.flags.keys() {
            if !allowed.contains(&name.as_str()) {
                bail!(
                    "unknown flag --{name} for this command (takes: {})",
                    allowed
                        .iter()
                        .map(|f| format!("--{f}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }
        Ok(())
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags.get(name).and_then(|v| v.as_deref())
    }

    fn need(&self, name: &str) -> Result<&str> {
        self.get(name)
            .with_context(|| format!("--{name} is required"))
    }

    fn account(&self, name: &str) -> Result<AccountId> {
        self.need(name)?
            .parse::<AccountId>()
            .map_err(|e| anyhow!("--{name}: {e:?}"))
    }

    fn opt_account(&self, name: &str) -> Result<Option<AccountId>> {
        self.get(name)
            .map(|v| {
                v.parse::<AccountId>()
                    .map_err(|e| anyhow!("--{name}: {e:?}"))
            })
            .transpose()
    }

    fn u128(&self, name: &str) -> Result<u128> {
        self.need(name)?
            .parse()
            .with_context(|| format!("--{name}: an integer"))
    }

    fn u64s(&self, name: &str) -> Result<Option<Vec<u64>>> {
        self.get(name)
            .map(|v| {
                v.split(',')
                    .map(|p| {
                        p.trim()
                            .parse::<u64>()
                            .map_err(|e| anyhow!("--{name}: {e}"))
                    })
                    .collect()
            })
            .transpose()
    }
}

struct Ctx {
    client: SequencerClient,
    key: PrivateKey,
    me: AccountId,
}

struct Included {
    hash: HashType,
    block_id: u64,
    index: usize,
    reverted: bool,
    bytes: usize,
    wait: Duration,
}

impl Included {
    fn json(&self) -> serde_json::Value {
        json!({
            "hash": self.hash.to_string(), "block": self.block_id, "index": self.index,
            "reverted": self.reverted, "bytes": self.bytes, "wait_s": self.wait.as_secs_f64(),
        })
    }
}

impl Ctx {
    async fn nonce(&self, id: AccountId) -> Result<Nonce> {
        Ok(self
            .client
            .get_accounts_nonces(vec![id])
            .await?
            .into_iter()
            .next()
            .unwrap_or_default())
    }

    async fn balance(&self, id: AccountId) -> Result<u128> {
        Ok(self.client.get_account_balance(id).await?)
    }

    async fn actor_state(&self, actor: Actor) -> Result<ActorState> {
        Ok(self
            .client
            .get_account(actor.account_id)
            .await?
            .map(|a| a.data.actor_state(actor.program_account_id).clone())
            .unwrap_or_default())
    }

    async fn quote(&self) -> Result<FeeQuote> {
        let q = self.client.get_fee_state().await?;
        Ok(FeeQuote {
            base_fee_exec: q.base_fee_exec,
            base_fee_stor: q.base_fee_stor,
        })
    }

    async fn clock_ms(&self) -> Result<u64> {
        let raw = self.actor_state(system_accounts::clock_actor()).await?;
        Ok(clock_core::ClockAccountData::from_bytes(&raw).timestamp)
    }

    async fn schedule(&self, program: AccountId, id: AccountId) -> Result<ScheduleAccount> {
        match VestingActorState::decode(&self.actor_state(Actor::new(id, program)).await?) {
            Some(VestingActorState::Schedule(s)) => Ok(*s),
            other => bail!("no schedule at {id}: {other:?}"),
        }
    }

    async fn states(&self, actors: &[Actor]) -> Result<HashMap<Actor, ActorState>> {
        let mut states = HashMap::new();
        for actor in actors {
            states.insert(*actor, self.actor_state(*actor).await?);
        }
        Ok(states)
    }

    fn build_public(
        &self,
        call: &Call,
        signers: &[&PrivateKey],
        evidence: Vec<PublicAccountEvidence>,
        gas_limit: u64,
        nonces: BTreeMap<AccountId, Nonce>,
        price: u128,
    ) -> PublicTransaction {
        let max_fee = (u128::from(gas_limit) + 1_100_000) * price;
        let fee = FeeDeclaration::new(self.me, gas_limit, 0, max_fee);
        let msg = PublicMessage::new(
            call.root,
            call.message.clone(),
            call.declared.clone(),
            nonces,
            Some(fee),
            evidence,
        );
        let mut keys: Vec<&PrivateKey> = vec![&self.key];
        keys.extend_from_slice(signers);
        let witness = WitnessSet::for_message(&msg, &keys);
        PublicTransaction::new(msg, witness)
    }

    /// Signs with the fee payer (and `signers`), simulates locally unless `precheck` is off, sends
    /// and waits for inclusion. A local refusal is reported with the program's actionable message.
    async fn send_call(
        &self,
        call: &Call,
        signers: &[&PrivateKey],
        evidence: Vec<PublicAccountEvidence>,
        catalog: Option<&ProgramCatalog>,
        precheck: bool,
        default_gas: u64,
    ) -> Result<(Included, Option<u64>)> {
        let quote = self.client.get_fee_state().await?;
        let price = u128::from(
            quote
                .base_fee_exec
                .max(quote.base_fee_stor)
                .saturating_mul(8)
                .max(64),
        );
        let mut ids = vec![self.me];
        ids.extend(signers.iter().map(|k| id_of(k)));
        ids.dedup();
        let nonces_list = self.client.get_accounts_nonces(ids.clone()).await?;
        let nonces: BTreeMap<AccountId, Nonce> = ids.into_iter().zip(nonces_list).collect();
        let mut gas_limit = default_gas;
        let mut simulated = None;
        if precheck {
            let catalog = catalog.context("simulation needs ESCAPEMENT_ELF")?;
            let probe_tx = self.build_public(
                call,
                signers,
                evidence.clone(),
                MAX_GAS_EXEC,
                nonces.clone(),
                price,
            );
            let simulation = Simulation {
                public_actor_states: self.states(&call.declared).await?,
                admitted_accounts: None,
            };
            let (cycles, result) =
                lee::simulate_public_transaction(&probe_tx, &simulation, catalog, MAX_GAS_EXEC);
            if let Err(e) = result {
                if let LeeError::ProgramExitedWithCode { code, cycles } = &e {
                    if let Some(r) = codes::refusal(*code) {
                        bail!(
                            "refused by the program before sending (code {code}, {cycles} cycles): {}",
                            r.message
                        );
                    }
                }
                bail!("refused in simulation, nothing sent: {e}");
            }
            simulated = Some(cycles);
            gas_limit = (cycles + cycles.div_ceil(4)).max(50_000);
        }
        let tx = self.build_public(call, signers, evidence, gas_limit, nonces, price);
        let included = self.send_and_wait(LeeTransaction::Public(tx)).await?;
        Ok((included, simulated))
    }

    async fn send_and_wait(&self, tx: LeeTransaction) -> Result<Included> {
        let bytes = borsh::to_vec(&tx)?.len();
        let local_hash = tx.hash();
        let sent = Instant::now();
        let hash = self
            .client
            .send_transaction(tx)
            .await
            .context("sendTransaction")?;
        if hash != local_hash {
            eprintln!(
                "warning: the sequencer's hash {hash} differs from the local one {local_hash}"
            );
        }
        for _ in 0..600 {
            if let Some((_, block_id)) = self.client.get_transaction(hash).await? {
                let block = self
                    .client
                    .get_block(block_id)
                    .await?
                    .context("the block holding it")?;
                let index = block
                    .body
                    .transactions
                    .iter()
                    .position(|t| t.hash() == hash)
                    .context("the transaction in its block")?;
                let reverted = block.body.reverted.contains(&(index as u64));
                return Ok(Included {
                    hash,
                    block_id,
                    index,
                    reverted,
                    bytes,
                    wait: sent.elapsed(),
                });
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("transaction {hash} not included within 600 s")
    }
}

fn read_elf(var: &str) -> Result<Option<Vec<u8>>> {
    let Ok(path) = std::env::var(var) else {
        return Ok(None);
    };
    Ok(Some(
        std::fs::read(&path).with_context(|| format!("read {var} {path}"))?,
    ))
}

fn program_of(elf: Vec<u8>) -> Result<Program> {
    Program::new(Cow::Owned(elf)).map_err(|e| anyhow!("not a ProgramBinary: {e}"))
}

fn token_program_id() -> Result<Option<AccountId>> {
    std::env::var("ESCAPEMENT_TOKEN_PROGRAM")
        .ok()
        .map(|v| {
            v.parse::<AccountId>()
                .map_err(|e| anyhow!("ESCAPEMENT_TOKEN_PROGRAM: {e:?}"))
        })
        .transpose()
}

/// The programs a local simulation or proof runs: Escapement, the LEZ clock, and the token
/// program when configured.
fn catalog_for(program_id: Option<AccountId>) -> Result<ProgramCatalog> {
    let mut entries: Vec<(AccountId, Program)> =
        vec![(clock_core::clock_account_id(), programs::clock())];
    if let (Some(id), Some(elf)) = (program_id, read_elf("ESCAPEMENT_ELF")?) {
        entries.push((id, program_of(elf)?));
    }
    if let (Some(id), Some(elf)) = (token_program_id()?, read_elf("ESCAPEMENT_TOKEN_ELF")?) {
        entries.push((id, program_of(elf)?));
    }
    Ok(entries.into_iter().collect())
}

fn program_id() -> Result<AccountId> {
    std::env::var("ESCAPEMENT_PROGRAM")
        .context("ESCAPEMENT_PROGRAM (the deployed program's address) is required")?
        .parse::<AccountId>()
        .map_err(|e| anyhow!("ESCAPEMENT_PROGRAM: {e:?}"))
}

fn deployment() -> Result<Deployment> {
    Ok(Deployment {
        program: program_id()?,
        token_program: token_program_id()?,
    })
}

/// A token holding in an actor state of the token program (`None` for anything else; never panics,
/// unlike `TokenState::decode`, which expects token-written bytes).
fn token_holding(state: &[u8]) -> Option<(AccountId, u128)> {
    if state.is_empty() {
        return None;
    }
    match borsh::from_slice::<TokenState>(state) {
        Ok(TokenState::Holding(h)) => Some((h.definition_id, h.balance)),
        _ => None,
    }
}

/// `account`'s balance of `asset` (0 when it holds none).
async fn asset_balance(ctx: &Ctx, asset: Asset, account: AccountId) -> Result<u128> {
    match asset {
        Asset::Native => ctx.balance(account).await,
        Asset::Token { definition } => {
            let program = token_program_id()?.context("ESCAPEMENT_TOKEN_PROGRAM is required")?;
            Ok(
                token_holding(&ctx.actor_state(Actor::new(account, program)).await?)
                    .filter(|(def, _)| *def == definition)
                    .map_or(0, |(_, balance)| balance),
            )
        }
    }
}

fn asset_label(asset: Asset) -> String {
    match asset {
        Asset::Native => "native units".into(),
        Asset::Token { definition } => format!("units of token {definition}"),
    }
}

async fn probe(ctx: &Ctx) -> Result<serde_json::Value> {
    ctx.client.check_health().await.context("checkHealth")?;
    let head = ctx.client.get_last_block_id().await?;
    let block = ctx
        .client
        .get_block(head)
        .await?
        .context("getBlock(head)")?;
    let quote = ctx.quote().await?;
    Ok(json!({
        "head": head,
        "head_timestamp_ms": block.header.timestamp,
        "clock_ms": ctx.clock_ms().await?,
        "base_fee_exec": quote.base_fee_exec, "base_fee_stor": quote.base_fee_stor,
        "signer": ctx.me.to_string(),
        "signer_balance": ctx.balance(ctx.me).await?.to_string(),
    }))
}

async fn fund(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    let to_key = key_from_hex(a.need("to-key")?)?;
    let to = id_of(&to_key);
    let amount = a.u128("amount")?;
    let root = Actor::native_balance(ctx.me);
    let call = Call {
        root,
        declared: vec![root, Actor::native_balance(to)],
        message: borsh::to_vec(&native_token::Message::Transfer { to, amount })?,
    };
    let (included, _) = ctx
        .send_call(
            &call,
            &[],
            vec![PublicAccountEvidence::Key(PublicKey::new_from_private_key(
                &to_key,
            ))],
            None,
            false,
            100_000,
        )
        .await?;
    Ok(
        json!({"tx": included.json(), "to": to.to_string(), "balance": ctx.balance(to).await?.to_string()}),
    )
}

async fn deploy(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    let elf_path = a.positional.first().context("deploy ELF")?;
    let elf = std::fs::read(elf_path).with_context(|| format!("read {elf_path}"))?;
    let program = program_of(elf)?;
    let user_elf = program.user_elf().map_err(|e| anyhow!("{e}"))?;
    let segment_keys: Vec<PrivateKey> = (0..program_loader_core::segment_count(&user_elf))
        .map(|_| fresh_key())
        .collect();
    let segment_ids: Vec<AccountId> = segment_keys.iter().map(id_of).collect();
    let chain =
        program_loader_core::build_segments(&user_elf, &segment_ids).map_err(|e| anyhow!("{e}"))?;
    let mut txs = Vec::new();
    // Tail first: a segment's `next_segment` must already hold a segment.
    for (i, segment) in chain.into_iter().enumerate().rev() {
        let root = Actor::new(segment_ids[i], PROGRAM_LOADER_ACCOUNT_ID);
        let bytes = segment.bytecode.len() as u64;
        let message = program_loader_core::Message::WriteSegment {
            bytecode: segment.bytecode,
            next_segment: segment.next_segment,
        };
        let call = Call {
            root,
            declared: vec![root],
            message: borsh::to_vec(&message)?,
        };
        let (included, _) = ctx
            .send_call(
                &call,
                &[&segment_keys[i]],
                vec![],
                None,
                false,
                2 * bytes + 500_000,
            )
            .await
            .with_context(|| format!("segment {i}"))?;
        eprintln!(
            "segment {i}: block {} reverted {}",
            included.block_id, included.reverted
        );
        txs.push(included.json());
    }
    let header_key = fresh_key();
    let header = id_of(&header_key);
    let root = Actor::new(header, PROGRAM_LOADER_ACCOUNT_ID);
    let message = program_loader_core::Message::CreateHeader {
        first_segment: segment_ids[0],
        immutable: true,
    };
    let call = Call {
        root,
        declared: vec![root],
        message: borsh::to_vec(&message)?,
    };
    let (included, _) = ctx
        .send_call(
            &call,
            &[&header_key],
            vec![],
            None,
            false,
            2 * user_elf.len() as u64 + 1_000_000,
        )
        .await
        .context("header")?;
    txs.push(included.json());
    let state = ctx.actor_state(root).await?;
    let recorded = ProgramHeader::from_loader_actor_state(&state)
        .context("no program header at the header account")?;
    if recorded.image_id != program.id() || !recorded.immutable {
        bail!(
            "header holds image {} immutable {}, expected {} immutable",
            image_hex(recorded.image_id),
            recorded.immutable,
            image_hex(program.id())
        );
    }
    let mut out = json!({"program_address": header.to_string(), "image_id": image_hex(recorded.image_id),
              "immutable": recorded.immutable, "elf_bytes": program.elf().len(), "segments": segment_ids.len(),
              "transactions": txs});
    if a.has("init-admin") {
        // `lez-admin-authority`'s InitGate::Deployer: the program's own (header) account, signed.
        let cfg = config_pda(header);
        let call = Call {
            root: Actor::new(header, header),
            declared: vec![Actor::new(header, header), Actor::new(cfg, header)],
            message: borsh::to_vec(&admin_op::<Message>(AdminOp::Init))?,
        };
        let (included, _) = ctx
            .send_call(&call, &[&header_key], vec![], None, false, 1_000_000)
            .await
            .context("AdminOp::Init")?;
        out["admin_init"] = included.json();
    }
    if let Some(path) = a.get("keys-out") {
        // Local devnet only: the header key is the program's admin seat.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create {path}"))?;
        f.write_all(
            json!({"program": header.to_string(), "header_key": key_hex(&header_key)})
                .to_string()
                .as_bytes(),
        )?;
        out["keys_out"] = json!(path);
    }
    Ok(out)
}

async fn configure(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    let program = program_id()?;
    let admin_key = key_from_hex(a.need("admin-key")?)?;
    let fee_bps: u16 = a.need("fee-bps")?.parse()?;
    let call = Call {
        root: Actor::new(program, program),
        declared: vec![
            Actor::new(program, program),
            Actor::new(config_pda(program), program),
        ],
        message: builders::encode(Message::Configure {
            token_program_id: a.opt_account("token-program")?,
            fee_bps,
            fee_treasury: a.opt_account("treasury")?,
        }),
    };
    let (included, _) = ctx
        .send_call(&call, &[&admin_key], vec![], None, false, 1_000_000)
        .await?;
    Ok(json!({"tx": included.json()}))
}

async fn token(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    let program = token_program_id()?.context("ESCAPEMENT_TOKEN_PROGRAM is required")?;
    let catalog = catalog_for(None)?;
    match a.positional.first().map(String::as_str) {
        Some("new") => {
            a.check(&["supply", "name"])?;
            let def_key = fresh_key();
            let def = id_of(&def_key);
            let supply = a.u128("supply")?;
            let call = Call {
                root: Actor::new(def, program),
                declared: vec![Actor::new(def, program), Actor::new(ctx.me, program)],
                message: borsh::to_vec(&TokenMessage::NewDefinition {
                    name: a.get("name").unwrap_or("VEST-TEST").to_string(),
                    total_supply: supply,
                    mint_authority: None,
                    holding: ctx.me,
                })?,
            };
            let (included, cycles) = ctx
                .send_call(
                    &call,
                    &[&def_key],
                    vec![PublicAccountEvidence::Key(PublicKey::new_from_private_key(
                        &def_key,
                    ))],
                    Some(&catalog),
                    true,
                    500_000,
                )
                .await?;
            let holding = token_holding(&ctx.actor_state(Actor::new(ctx.me, program)).await?);
            Ok(
                json!({"tx": included.json(), "simulated_cycles": cycles, "definition": def.to_string(),
                      "holder": ctx.me.to_string(), "holder_balance": holding.map(|h| h.1.to_string())}),
            )
        }
        Some("init-holding") => {
            a.check(&["definition"])?;
            let def = a.account("definition")?;
            let call = Call {
                root: Actor::new(ctx.me, program),
                declared: vec![Actor::new(ctx.me, program), Actor::new(def, program)],
                message: borsh::to_vec(&TokenMessage::InitializeHolding { definition: def })?,
            };
            let (included, cycles) = ctx
                .send_call(&call, &[], vec![], Some(&catalog), true, 500_000)
                .await?;
            Ok(json!({"tx": included.json(), "simulated_cycles": cycles}))
        }
        _ => bail!("token new --supply N | token init-holding --definition ID"),
    }
}

fn kind_from(a: &Args, total: u128) -> Result<ScheduleKind> {
    if let Some(v) = a.u64s("linear")? {
        let [start_ts, end_ts] = v[..] else {
            bail!("--linear START,END (unix ms)")
        };
        return Ok(ScheduleKind::Linear { start_ts, end_ts });
    }
    if let Some(v) = a.u64s("cliff")? {
        let [start_ts, cliff_ts, end_ts, cliff_amount] = v[..] else {
            bail!("--cliff START,CLIFF,END,CLIFF_AMOUNT")
        };
        return Ok(ScheduleKind::CliffLinear {
            start_ts,
            cliff_ts,
            end_ts,
            cliff_amount: u128::from(cliff_amount),
        });
    }
    if let Some(v) = a.get("milestones") {
        let tranches: Vec<MilestoneTranche> = v
            .split(',')
            .map(|p| {
                Ok(MilestoneTranche {
                    amount: p.trim().parse()?,
                    unlocked: false,
                    unlocked_at_ms: None,
                })
            })
            .collect::<Result<_>>()?;
        if tranches.iter().map(|t| t.amount).sum::<u128>() != total {
            bail!("--milestones must add up to --total");
        }
        return Ok(ScheduleKind::Milestone { tranches });
    }
    bail!("one of --linear, --cliff or --milestones is required")
}

fn print_call(call: &Call) -> serde_json::Value {
    json!({
        "root": format!("{:?}", call.root),
        "declared": call.declared.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>(),
        "message_hex": hex::encode(&call.message),
    })
}

async fn create(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    a.check(&[
        "beneficiary",
        "total",
        "linear",
        "cliff",
        "milestones",
        "token",
        "funding-holding",
        "non-cancelable",
        "transferable",
        "cancel-authority",
        "milestone-authority",
        "refund-to",
        "salt",
        "fee",
        "dry-run",
        "no-precheck",
    ])?;
    let d = deployment()?;
    let total = a.u128("total")?;
    let salt = match a.get("salt") {
        Some(h) => hex::decode(h)?
            .try_into()
            .map_err(|_| anyhow!("--salt: 32 bytes hex"))?,
        None => random_bytes(),
    };
    let asset = match a.opt_account("token")? {
        Some(definition) => {
            if d.token_program.is_none() {
                bail!("--token needs ESCAPEMENT_TOKEN_PROGRAM");
            }
            Asset::Token { definition }
        }
        None => Asset::Native,
    };
    let mut req = ScheduleRequest::new(
        salt,
        asset,
        ctx.me,
        a.account("beneficiary")?,
        total,
        kind_from(a, total)?,
    );
    req.funding_holding = a.opt_account("funding-holding")?;
    req.cancelable = !a.has("non-cancelable");
    req.transferable = a.has("transferable");
    req.refund_to = a.opt_account("refund-to")?;
    req.cancel_authority = a.opt_account("cancel-authority")?;
    req.milestone_authority = a.opt_account("milestone-authority")?;
    let params = req.params();
    let call = builders::create_schedule(&d, ctx.me, &params, a.has("fee"));
    let schedule = schedule_pda(d.program, &ctx.me, &salt);
    let escrow = single_escrow_pda(d.program, &schedule);
    if a.has("dry-run") {
        return Ok(
            json!({"dry_run": true, "schedule": schedule.to_string(), "call": print_call(&call)}),
        );
    }
    let catalog = catalog_for(Some(d.program))?;
    let (included, cycles) = ctx
        .send_call(
            &call,
            &[],
            vec![],
            Some(&catalog),
            !a.has("no-precheck"),
            2_000_000,
        )
        .await?;
    Ok(
        json!({"tx": included.json(), "simulated_cycles": cycles, "schedule": schedule.to_string(),
              "escrow": escrow.to_string(), "escrow_balance": asset_balance(ctx, asset, escrow).await?.to_string()}),
    )
}

async fn show(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    a.check(&["schedule"])?;
    let program = program_id()?;
    let id = a.account("schedule")?;
    let s = ctx.schedule(program, id).await?;
    let now = ctx.clock_ms().await?;
    let (next, reason) = next_unlock(&s, now);
    let tranches: Option<Vec<serde_json::Value>> = match &s.kind {
        ScheduleKind::Milestone { tranches } => Some(
            tranches
                .iter()
                .map(|t| json!({"amount": t.amount.to_string(), "unlocked": t.unlocked, "unlocked_at_ms": t.unlocked_at_ms}))
                .collect(),
        ),
        _ => None,
    };
    Ok(json!({
        "schedule": id.to_string(), "asset": format!("{:?}", s.asset),
        "beneficiary": s.beneficiary.to_string(), "creator": s.creator.to_string(),
        "total": s.total_amount.to_string(), "claimed": s.claimed_amount.to_string(),
        "locked": s.total_amount.saturating_sub(s.claimed_amount).to_string(),
        "claimable_now": claimable_at(&s, now).to_string(), "clock_ms": now,
        "next_unlock_ms": next, "next_unlock_utc": next.map(utc),
        "reason": if claimable_at(&s, now) > 0 { "tokens are claimable now".to_string() } else { reason.describe() },
        "cancelable": s.cancelable, "transferable": s.transferable,
        "cancel_authority": s.cancel_authority.map(|x| x.to_string()),
        "milestone_authority": s.milestone_authority.map(|x| x.to_string()),
        "tranches": tranches,
        "cancelled": s.cancelled.map(|c| json!({"at_ms": c.cancelled_at_ms, "vested": c.vested_at_cancel.to_string(), "refunded": c.refunded_amount.to_string()})),
        "escrow": s.escrow_account.to_string(),
        "escrow_balance": asset_balance(ctx, s.asset, s.escrow_account).await?.to_string(),
    }))
}

async fn simple(ctx: &Ctx, a: &Args, call: Call, program: AccountId) -> Result<serde_json::Value> {
    if a.has("dry-run") {
        return Ok(json!({"dry_run": true, "call": print_call(&call)}));
    }
    let catalog = catalog_for(Some(program))?;
    let (included, cycles) = ctx
        .send_call(
            &call,
            &[],
            vec![],
            Some(&catalog),
            !a.has("no-precheck"),
            1_000_000,
        )
        .await?;
    Ok(json!({"tx": included.json(), "simulated_cycles": cycles}))
}

fn dummy_output() -> DummyOutput {
    let throwaway = MlKem768EncapsulationKey::from_seed(&random_bytes(), &random_bytes());
    let (_, epk) = SharedSecretKey::encapsulate(&throwaway);
    DummyOutput {
        commitment_seed: random_bytes(),
        note: EncryptedNote {
            ciphertext: Ciphertext::from_inner(random_vec(CIPHERTEXT_PAD_SIZE as usize)),
            epk,
        },
    }
}

/// The SDK's view of the chain for the private-target check.
struct KnownAccount {
    id: AccountId,
    public_exists: bool,
}

impl AccountLookup for KnownAccount {
    fn public_account_exists(&self, account_id: AccountId) -> bool {
        account_id == self.id && self.public_exists
    }
}

fn sdk_err(e: SdkError) -> anyhow::Error {
    anyhow!("{e}")
}

/// One privacy-preserving transaction that touches exactly one private account: the user's
/// (destination of any credit and payer of the fee, inside the proof).
struct PrivatePlan {
    root: Actor,
    message: Vec<u8>,
    public_actors: Vec<Actor>,
    /// Whether `ESCAPEMENT_KEY`'s account signs (its nonce is bound): claims and shields do.
    signed: bool,
    /// The one-time alias whose credit is folded into the private account in this transaction.
    promote_to: Option<AccountId>,
    openings: BTreeSet<[u8; 32]>,
    programs: ProgramCatalog,
    /// Native credited to the private account within the transaction (a native claim or shield):
    /// it lands before the fee transfer, so it can pay the fee.
    native_credit_in_tx: u128,
}

/// What the confirmation step decides, given the exact fee reserve.
enum Gate {
    Proceed,
    Stop(serde_json::Value),
}

#[allow(clippy::too_many_lines)]
async fn run_private(
    ctx: &Ctx,
    file: &mut PrivateAccountFile,
    plan: PrivatePlan,
    gate: &mut dyn FnMut(u128, u64) -> Result<Gate>,
) -> Result<serde_json::Value> {
    let id = file.keys.id();
    let query = file
        .state
        .as_ref()
        .map(|s| vec![Commitment::new(&id, s)])
        .unwrap_or_default();
    let (proofs, _, commitment_root) = ctx.client.get_proofs_and_root(query, vec![]).await?;
    let nullifier = match &file.state {
        Some(state) => NullifierWitness::Update {
            account: state.clone(),
            membership_proof: proofs.into_iter().next().flatten().with_context(|| {
                format!(
                    "{}: its recorded state is not committed on this chain (stale file or another chain)",
                    file.path.display()
                )
            })?,
        },
        None => NullifierWitness::Init {
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
    };
    let witness = PrivateWitness {
        vpk: file.keys.vpk(),
        random_seed: random_bytes(),
        kind: WitnessKind::Regular(RegularKey::Authorized(file.keys.ask())),
        nullifier,
        address_openings: plan.openings.clone(),
    };
    let fee_opening = random_bytes();
    let payer_actor = Actor::native_balance(id);
    let inbox = Actor::native_balance(system_accounts::fee_inbox_account_id());
    let mut public_actors = plan.public_actors.clone();
    public_actors.push(inbox);
    let signers: Vec<AccountId> = if plan.signed { vec![ctx.me] } else { vec![] };
    let mut input = ProvingInput {
        root: TransactionEntry::Sync(RootCall {
            to: plan.root,
            message: plan.message.clone(),
        }),
        claims: Vec::new(),
        fee: None,
        public_context: PublicExecutionContext::new(public_actors.clone(), signers.clone()),
        private_witnesses: vec![witness],
        dummy_inputs: std::iter::repeat_with(|| DummyInput {
            nullifier_seed: random_bytes(),
            commitment_root,
            output: dummy_output(),
        })
        .take(PADDED_PRIVATE_ACTIONS - 1)
        .collect(),
        ciphertext_padding: Some(CIPHERTEXT_PAD_SIZE),
        recoveries: vec![RecipientEncryption {
            recipient: Recipient {
                npk: file.keys.npk(),
                vpk: file.keys.vpk(),
                kind: PrivateAccountKind::Regular,
                opening: Some(fee_opening),
            },
            esk: EphemeralSecretKey(random_bytes()),
        }],
        private_promotions: BTreeSet::new(),
    };
    let simulation = Simulation {
        public_actor_states: ctx.states(&public_actors).await?,
        admitted_accounts: None,
    };
    let present = move |actor: Actor| {
        if actor == payer_actor {
            SenderPresentation::Blinded(fee_opening)
        } else {
            SenderPresentation::Blinded(random_bytes())
        }
    };
    let promote_to = plan.promote_to;
    let select = move |_, body: &MessageBody| promote_to == Some(body.to.account_id);
    let cycles = lee::simulate_privacy_preserving_transaction(
        &input,
        &simulation,
        &plan.programs,
        present,
        select,
    )
    .map_err(|e| anyhow!("simulation refused it, nothing proven or sent: {e}"))?;
    // U4: the reserve is the fee at the current base fees (no headroom, so no refund has to be
    // received later), and the payer must cover it before anything is proven.
    let quote = ctx.quote().await?;
    let estimate = estimate_private_fee(cycles, quote, 0);
    check_private_gas(
        &estimate,
        file.native_balance()
            .saturating_add(plan.native_credit_in_tx),
    )
    .map_err(sdk_err)?;
    let reserve = estimate.reserve;
    if let Gate::Stop(v) = gate(reserve, cycles)? {
        return Ok(v);
    }
    input.fee = Some(FeeTransfer {
        payer: id,
        recipient: system_accounts::fee_inbox_account_id(),
        amount: reserve,
        refund_to: None,
    });
    let no_seal = |body: &MessageBody| -> Result<RecipientEncryption, LeeError> {
        Err(LeeError::InvalidInput(format!("no seal for {:?}", body.to)))
    };
    let started = Instant::now();
    let (output, proof) =
        lee::execute_and_prove(input, &simulation, &plan.programs, present, select, no_seal)
            .map_err(|e| anyhow!("proving: {e}"))?;
    let prove_s = started.elapsed().as_secs_f64();
    let proof_bytes = proof.clone().into_inner().len();
    let nonces: BTreeMap<AccountId, Nonce> = if plan.signed {
        BTreeMap::from([(ctx.me, ctx.nonce(ctx.me).await?)])
    } else {
        BTreeMap::new()
    };
    let signer_keys: Vec<&PrivateKey> = if plan.signed { vec![&ctx.key] } else { vec![] };
    let message = PrivateMessage::from_circuit_output(nonces, output.clone());
    let witness_set = PrivateWitnessSet::for_message(&message, proof, &signer_keys);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);
    let tx_bytes = borsh::to_vec(&tx)?;
    let leaks_owner = tx_bytes.windows(32).any(|w| w == id.value().as_slice());
    let included = ctx
        .send_and_wait(LeeTransaction::PrivacyPreserving(tx))
        .await?;
    // The account's new state, from its own note (the regular one, or the fee fallback's if the
    // public part failed), checked against the chain before it is recorded.
    let mut candidates: Vec<_> = output.execution.private_actions.iter().collect();
    if let Some(fallback) = output
        .execution
        .fee
        .as_ref()
        .and_then(|f| f.fallback.as_ref())
    {
        candidates.push(&fallback.action);
    }
    let mut recorded = None;
    for action in candidates {
        let Some(secret) = SharedSecretKey::decapsulate(
            &action.encrypted_post_state.epk,
            &file.keys.d,
            &file.keys.z,
        ) else {
            continue;
        };
        let Some((_, state)) = EncryptionScheme::decrypt(
            &action.encrypted_post_state.ciphertext,
            &secret,
            &action.nullifier,
        ) else {
            continue;
        };
        let (on_chain, _, _) = ctx
            .client
            .get_proofs_and_root(vec![Commitment::new(&id, &state)], vec![])
            .await?;
        if on_chain.first().is_some_and(Option::is_some) {
            recorded = Some(state);
            break;
        }
    }
    let committed = recorded.is_some();
    if let Some(state) = recorded {
        file.save_state(state)?;
    } else {
        eprintln!(
            "warning: no new state of {} found on chain; {} keeps its previous state",
            id,
            file.path.display()
        );
    }
    Ok(json!({
        "tx": included.json(), "fee_reserve": reserve.to_string(), "public_cycles_simulated": cycles,
        "prove_s": prove_s, "proof_bytes": proof_bytes,
        "private_commitment_found": committed, "private_account_id_in_tx_bytes": leaks_owner,
        "account_state_saved": committed,
        "account_native_balance_after": file.native_balance().to_string(),
        "dev_mode": std::env::var("RISC0_DEV_MODE").is_ok_and(|v| v == "1" || v == "true"),
    }))
}

fn holdings_json(file: &PrivateAccountFile) -> serde_json::Value {
    let Some(state) = &file.state else {
        return json!([]);
    };
    let token_program = token_program_id().ok().flatten();
    let holdings: Vec<serde_json::Value> = state
        .data
        .actor_states
        .iter()
        .filter(|(program, _)| Some(**program) == token_program)
        .filter_map(|(program, s)| {
            token_holding(s).map(|(def, bal)| {
                json!({"program": program.to_string(), "definition": def.to_string(), "balance": bal.to_string()})
            })
        })
        .collect();
    json!(holdings)
}

async fn private_account(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    match a.positional.first().map(String::as_str) {
        Some("new") => {
            a.check(&["out"])?;
            let path = std::path::Path::new(a.need("out")?);
            let file = PrivateAccountFile::create(
                path,
                PrivateKeys::from_seed_bytes(random_bytes(), random_bytes(), random_bytes()),
            )?;
            Ok(json!({"account": file.keys.id().to_string(), "key_file": path.display().to_string(),
                      "note": "keep this file: it holds the account's secret keys (mode 0600)"}))
        }
        Some("show") => {
            a.check(&["file"])?;
            let file = PrivateAccountFile::load(std::path::Path::new(a.need("file")?))?;
            let id = file.keys.id();
            let committed = match &file.state {
                Some(s) => ctx
                    .client
                    .get_proofs_and_root(vec![Commitment::new(&id, s)], vec![])
                    .await?
                    .0
                    .first()
                    .is_some_and(Option::is_some),
                None => false,
            };
            Ok(json!({"account": id.to_string(), "native_balance": file.native_balance().to_string(),
                      "token_holdings": holdings_json(&file), "state_committed_on_chain": committed,
                      "new_account": file.state.is_none()}))
        }
        Some("shield") => {
            a.check(&["file", "amount"])?;
            let mut file = PrivateAccountFile::load(std::path::Path::new(a.need("file")?))?;
            let amount = a.u128("amount")?;
            let factor = random_bytes();
            let dest = PrivateDestination::with_factor(&file.keys.sdk_keys(), factor);
            let root = Actor::native_balance(ctx.me);
            let plan = PrivatePlan {
                root,
                message: borsh::to_vec(&native_token::Message::Transfer {
                    to: dest.alias(),
                    amount,
                })?,
                public_actors: vec![root],
                signed: true,
                promote_to: Some(dest.alias()),
                openings: BTreeSet::from([dest.opening()]),
                programs: ProgramCatalog::default(),
                native_credit_in_tx: amount,
            };
            let mut out = run_private(ctx, &mut file, plan, &mut |_, _| Ok(Gate::Proceed)).await?;
            out["alias"] = json!(dest.alias().to_string());
            Ok(out)
        }
        Some("init-holding") => {
            a.check(&["file", "definition"])?;
            let mut file = PrivateAccountFile::load(std::path::Path::new(a.need("file")?))?;
            let def = a.account("definition")?;
            let program = token_program_id()?.context("ESCAPEMENT_TOKEN_PROGRAM is required")?;
            if file.state.is_none() {
                bail!("the account has no native balance to pay the fee yet: run `private-account shield` first");
            }
            let plan = PrivatePlan {
                root: Actor::new(file.keys.id(), program),
                message: borsh::to_vec(&TokenMessage::InitializeHolding { definition: def })?,
                public_actors: vec![Actor::new(def, program)],
                signed: false,
                promote_to: None,
                openings: BTreeSet::new(),
                programs: catalog_for(None)?,
                native_credit_in_tx: 0,
            };
            let mut out = run_private(ctx, &mut file, plan, &mut |_, _| Ok(Gate::Proceed)).await?;
            out["token_holdings_after"] = holdings_json(&file);
            Ok(out)
        }
        _ => bail!("private-account new --out FILE | show --file FILE | shield --file FILE --amount N | init-holding --file FILE --definition ID"),
    }
}

#[allow(clippy::too_many_lines)]
async fn claim(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    a.check(&[
        "schedule",
        "amount",
        "to",
        "to-private",
        "confirm",
        "dry-run",
        "no-precheck",
    ])?;
    let d = deployment()?;
    let program = d.program;
    let id = a.account("schedule")?;
    let s = ctx.schedule(program, id).await?;
    let now = ctx.clock_ms().await?;
    let requested = a.get("amount").map(str::parse::<u128>).transpose()?;
    let quote = ctx.quote().await?;
    let precheck = !a.has("no-precheck");
    if let Some(to) = a.opt_account("to")? {
        let call = builders::claim_public(&d, id, &s, to, requested);
        if precheck {
            let ctx_claim = ClaimContext {
                schedule_account: id,
                schedule: &s,
                signer: ctx.me,
                asset_label: asset_label(s.asset),
                now_ms: now,
                requested,
                quote,
                public_cycles: 110_000,
            };
            let prepared =
                prepare_public_claim(&ctx_claim, to, ctx.me, ctx.balance(ctx.me).await?, 1_000)
                    .map_err(sdk_err)?;
            eprintln!("{}", prepared.summary.render());
            if !prepared.summary.sufficient_gas {
                bail!("the fee payer cannot cover the fee reserve; fund it first");
            }
        }
        if a.has("dry-run") {
            return Ok(json!({"dry_run": true, "call": print_call(&call)}));
        }
        let before = asset_balance(ctx, s.asset, to).await?;
        let escrow_before = asset_balance(ctx, s.asset, s.escrow_account).await?;
        let catalog = catalog_for(Some(program))?;
        let (included, cycles) = ctx
            .send_call(&call, &[], vec![], Some(&catalog), precheck, 1_000_000)
            .await?;
        let after = asset_balance(ctx, s.asset, to).await?;
        let escrow_after = asset_balance(ctx, s.asset, s.escrow_account).await?;
        // `destination_delta` nets out the fee when the destination also pays it (native).
        return Ok(json!({"tx": included.json(), "simulated_cycles": cycles,
                         "escrow_debited": escrow_before.saturating_sub(escrow_after).to_string(),
                         "destination_delta": (after as i128 - before as i128).to_string(),
                         "claimed_total": ctx.schedule(program, id).await?.claimed_amount.to_string()}));
    }

    // Private claim into a private account the user owns (its key file).
    let path = a.get("to-private").context(
        "a claim needs --to ID (public) or --to-private FILE (a private account you own)",
    )?;
    let mut file = PrivateAccountFile::load(std::path::Path::new(path))?;
    let target = file.keys.id();
    // +Privacy 3: the SDK accepts only a private account derived from the keys given.
    let lookup = KnownAccount {
        id: target,
        public_exists: ctx.client.get_account(target).await?.is_some(),
    };
    validate_private_target(target, Some(&file.keys.sdk_keys()), s.beneficiary, &lookup)
        .map_err(sdk_err)?;
    let confirm = a.get("confirm").map(str::to_string);
    let (factor, amount, effective_ts) = match &confirm {
        Some(token) => {
            let p = file.load_pending()?;
            if p.schedule != id {
                bail!(
                    "the prepared claim is for schedule {}, not {id}",
                    p.schedule
                );
            }
            if &p.token_hex != token {
                bail!("--confirm does not match the token of the disclosure that was shown; nothing proven or sent");
            }
            (p.factor, p.amount, p.effective_ts)
        }
        None => {
            let now_claimable = claimable_at(&s, now);
            if precheck && now_claimable == 0 {
                let (next, reason) = next_unlock(&s, now);
                return Err(sdk_err(SdkError::NothingClaimableYet {
                    next_unlock_ms: next,
                    reason,
                }));
            }
            let amount = requested.unwrap_or(now_claimable);
            if precheck && amount > now_claimable {
                return Err(sdk_err(SdkError::ExceedsClaimable {
                    requested: amount,
                    claimable: now_claimable,
                }));
            }
            (random_bytes(), amount, now)
        }
    };
    if s.beneficiary != ctx.me && precheck {
        return Err(sdk_err(SdkError::NotBeneficiary {
            beneficiary: s.beneficiary,
        }));
    }
    let dest = PrivateDestination::with_factor(&file.keys.sdk_keys(), factor);
    let alias = dest.alias();
    if let Asset::Token { definition } = s.asset {
        let token_prog = token_program_id()?.context("ESCAPEMENT_TOKEN_PROGRAM is required")?;
        let has_holding = file.state.as_ref().is_some_and(|st| {
            token_holding(st.data.actor_state(token_prog)).is_some_and(|(def, _)| def == definition)
        });
        if !has_holding && precheck {
            bail!("{target} has no private holding of {definition} yet: run `private-account init-holding --definition {definition}` first (its fee needs a native balance: `private-account shield`)");
        }
    }
    let call = builders::claim_exact(&d, id, &s, alias, amount, effective_ts);
    let plan = PrivatePlan {
        root: call.root,
        message: call.message.clone(),
        public_actors: call.declared.clone(),
        signed: true,
        promote_to: Some(alias),
        openings: BTreeSet::from([dest.opening()]),
        programs: catalog_for(Some(program))?,
        native_credit_in_tx: if s.asset == Asset::Native { amount } else { 0 },
    };
    let dry_run = a.has("dry-run");
    let label = asset_label(s.asset);
    let escrow_before = asset_balance(ctx, s.asset, s.escrow_account).await?;
    let mut gate = |reserve: u128, cycles: u64| -> Result<Gate> {
        // U5: the disclosure names this exact claim, alias and fee reserve; its token binds it.
        let disclosure = PrivacyDisclosure {
            schedule_account: id,
            beneficiary: s.beneficiary,
            amount,
            asset: label.clone(),
            alias,
            fee_reserve: reserve,
        };
        eprintln!("{}", disclosure.render());
        let token = disclosure.token().to_string();
        if dry_run {
            return Ok(Gate::Stop(
                json!({"dry_run": true, "disclosure_token": token,
                "fee_reserve": reserve.to_string(), "public_cycles_simulated": cycles, "call": print_call(&call)}),
            ));
        }
        match &confirm {
            Some(given) if *given == token => Ok(Gate::Proceed),
            Some(_) => bail!(
                "the disclosure changed since it was shown (state or fee moved); run the claim again without --confirm"
            ),
            None => {
                file_pending_save(path, &PendingClaim {
                    schedule: id,
                    amount,
                    effective_ts,
                    factor,
                    token_hex: token.clone(),
                })?;
                Ok(Gate::Stop(json!({"needs_confirmation": true, "disclosure_token": token,
                    "fee_reserve": reserve.to_string(), "public_cycles_simulated": cycles,
                    "amount": amount.to_string(), "alias": alias.to_string(),
                    "hint": "read the disclosure above; rerun with --confirm <disclosure_token>"})))
            }
        }
    };
    let mut out = run_private(ctx, &mut file, plan, &mut gate).await?;
    if out.get("tx").is_some() {
        file.clear_pending();
        let escrow_after = asset_balance(ctx, s.asset, s.escrow_account).await?;
        out["amount"] = json!(amount.to_string());
        out["alias"] = json!(alias.to_string());
        out["escrow_debited"] = json!(escrow_before.saturating_sub(escrow_after).to_string());
        out["claimed_total"] = json!(ctx.schedule(program, id).await?.claimed_amount.to_string());
        out["token_holdings_after"] = holdings_json(&file);
    }
    Ok(out)
}

/// Stores a prepared claim beside the key file (a separate helper so the gate closure does not
/// borrow the loaded file, which `run_private` holds mutably).
fn file_pending_save(path: &str, pending: &PendingClaim) -> Result<()> {
    PrivateAccountFile::load(std::path::Path::new(path))?.save_pending(pending)
}

#[tokio::main]
async fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().collect();
    let command = raw.get(1).cloned().unwrap_or_default();
    let a = Args::parse(raw.get(2..).unwrap_or_default());
    if command == "keygen" {
        a.check(&[])?;
        let k = fresh_key();
        println!(
            "{}",
            json!({"key": key_hex(&k), "account": id_of(&k).to_string()})
        );
        return Ok(());
    }
    let url =
        loopback_url(&std::env::var("LEZ_RPC").unwrap_or_else(|_| "http://127.0.0.1:3040".into()))?;
    let key =
        key_from_hex(&std::env::var("ESCAPEMENT_KEY").unwrap_or_else(|_| DEFAULT_KEY.into()))?;
    let me = id_of(&key);
    let client = SequencerClientBuilder::default().build(&url)?;
    let ctx = Ctx { client, key, me };
    let out = match command.as_str() {
        "probe" => {
            a.check(&[])?;
            probe(&ctx).await?
        }
        "fund" => {
            a.check(&["to-key", "amount"])?;
            fund(&ctx, &a).await?
        }
        "deploy" => {
            a.check(&["init-admin", "keys-out"])?;
            deploy(&ctx, &a).await?
        }
        "configure" => {
            a.check(&["admin-key", "fee-bps", "treasury", "token-program"])?;
            configure(&ctx, &a).await?
        }
        "token" => token(&ctx, &a).await?,
        "private-account" => private_account(&ctx, &a).await?,
        "create" => create(&ctx, &a).await?,
        "show" | "claimable" => show(&ctx, &a).await?,
        "claim" => claim(&ctx, &a).await?,
        "cancel" | "make-non-cancelable" | "signal" | "transfer-beneficiary" => {
            let mut allowed = vec!["schedule", "dry-run", "no-precheck"];
            match command.as_str() {
                "signal" => allowed.push("index"),
                "transfer-beneficiary" => allowed.push("to"),
                _ => {}
            }
            a.check(&allowed)?;
            let d = deployment()?;
            let program = d.program;
            let id = a.account("schedule")?;
            let s = ctx.schedule(program, id).await?;
            let call = match command.as_str() {
                "cancel" => builders::cancel(&d, id, &s),
                "make-non-cancelable" => builders::make_non_cancelable(&d, id, &s),
                "signal" => builders::signal_milestone(&d, id, &s, a.need("index")?.parse()?),
                _ => builders::transfer_beneficiary(&d, id, &s, a.account("to")?),
            };
            // The SDK addresses the seat of the schedule's authority; the signer must be it.
            if call.root.account_id != ctx.me && !a.has("no-precheck") {
                bail!(
                    "this operation is signed by {}; ESCAPEMENT_KEY is {}",
                    call.root.account_id,
                    ctx.me
                );
            }
            let call = Call {
                root: Actor::new(ctx.me, program),
                declared: {
                    let mut v = call.declared.clone();
                    v[0] = Actor::new(ctx.me, program);
                    v
                },
                ..call
            };
            simple(&ctx, &a, call, program).await?
        }
        "withdraw-fees" => {
            a.check(&["to", "amount", "dry-run", "no-precheck"])?;
            let d = deployment()?;
            let call = builders::withdraw_fees(
                &d,
                ctx.me,
                Asset::Native,
                a.account("to")?,
                a.u128("amount")?,
            );
            simple(&ctx, &a, call, d.program).await?
        }
        _ => {
            eprintln!(
                "{}",
                include_str!("main.rs")
                    .lines()
                    .skip(2)
                    .take(24)
                    .map(|l| l.trim_start_matches("//! ").trim_start_matches("//!"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            bail!("unknown command {command:?}");
        }
    };
    println!("{}", json!({"command": command, "result": out}));
    Ok(())
}
