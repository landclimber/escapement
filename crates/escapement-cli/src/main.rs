//! `escapement`: the Escapement vesting program's CLI over a LEZ v0.4.0-rc3 sequencer's JSON-RPC.
//!
//! ```text
//! escapement keygen                                   a fresh public key (hex) and its account id
//! escapement fund --to-key HEX --amount N             native transfer to a fresh account (admits it)
//! escapement probe                                    head block, clock, fee state
//! escapement deploy ELF [--init-admin] [--keys-out F] immutable program_loader deployment, header read back
//! escapement configure --admin-key HEX --fee-bps N [--treasury ID] [--token-program ID]
//! escapement create --beneficiary ID --total N (--linear S,E | --cliff S,C,E,CLIFF | --milestones A,B,..)
//!                   [--non-cancelable] [--transferable] [--cancel-authority ID] [--milestone-authority ID]
//!                   [--refund-to ID] [--salt HEX] [--fee]                    (native asset)
//! escapement show --schedule ID                       terms, claimable now, next unlock
//! escapement claim --schedule ID [--amount N] (--to ID | --private) [--accept-privacy-disclosure]
//! escapement cancel --schedule ID | make-non-cancelable --schedule ID
//! escapement signal --schedule ID --index I | transfer-beneficiary --schedule ID --to ID
//! escapement withdraw-fees --to ID --amount N         (native fee vault; treasury key)
//! ```
//!
//! Every mutating command takes `--dry-run` (print what would be sent, send nothing) and
//! `--no-precheck` (skip the SDK's checks and the local simulation, so the program itself refuses:
//! used by the end-to-end suite to test refusals on chain).
//!
//! Environment: `LEZ_RPC` (default `http://127.0.0.1:3040`, loopback only: this tool never talks
//! to a public network), `ESCAPEMENT_KEY` (signer and fee payer, hex; default LEZ's published local
//! test key from `lez/sequencer/service/networks/local.json`), `ESCAPEMENT_PROGRAM` (the deployed
//! program's address), `ESCAPEMENT_ELF` (the deployed guest binary, for local simulation and
//! private-claim proving). Proofs are real unless `RISC0_DEV_MODE=1`. Each command prints one JSON
//! line to stdout; progress and human-readable summaries go to stderr.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Read,
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
    disclosure::PrivacyDisclosure,
    fees::FeeQuote,
    unlock::{next_unlock, utc},
};
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
    encryption::{Ciphertext, EncryptedNote, MlKem768EncapsulationKey, ViewingPublicKey},
    execution_state::TransactionEntry,
    native_token,
    program::{MessageBody, ProgramHeader, PROGRAM_LOADER_ACCOUNT_ID},
    AuthorizationSecretKey, Commitment, DummyInput, DummyOutput, EphemeralSecretKey, FeeTransfer,
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateAccountKind, PrivateWitness,
    RegularKey, RootCall, SharedSecretKey, WitnessKind, DUMMY_COMMITMENT_HASH,
};
use lez_admin_authority::{admin_op, AdminOp};
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use serde_json::json;

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

fn load_elf() -> Result<Option<(Vec<u8>, Program)>> {
    let Ok(path) = std::env::var("ESCAPEMENT_ELF") else {
        return Ok(None);
    };
    let elf = std::fs::read(&path).with_context(|| format!("read ESCAPEMENT_ELF {path}"))?;
    let program =
        Program::new(Cow::Owned(elf.clone())).map_err(|e| anyhow!("not a ProgramBinary: {e}"))?;
    Ok(Some((elf, program)))
}

fn catalog_for(program_id: AccountId) -> Result<Option<ProgramCatalog>> {
    let Some((elf, _)) = load_elf()? else {
        return Ok(None);
    };
    let ours = Program::new(Cow::Owned(elf)).map_err(|e| anyhow!("not a ProgramBinary: {e}"))?;
    Ok(Some(
        [
            (program_id, ours),
            (clock_core::clock_account_id(), programs::clock()),
        ]
        .into_iter()
        .collect(),
    ))
}

fn program_id() -> Result<AccountId> {
    std::env::var("ESCAPEMENT_PROGRAM")
        .context("ESCAPEMENT_PROGRAM (the deployed program's address) is required")?
        .parse::<AccountId>()
        .map_err(|e| anyhow!("ESCAPEMENT_PROGRAM: {e:?}"))
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
    let program = Program::new(Cow::Owned(elf)).map_err(|e| anyhow!("not a ProgramBinary: {e}"))?;
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
        std::fs::write(
            path,
            json!({"program": header.to_string(), "header_key": key_hex(&header_key)}).to_string(),
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
    let program = program_id()?;
    let d = Deployment {
        program,
        token_program: None,
    };
    let total = a.u128("total")?;
    let salt = match a.get("salt") {
        Some(h) => hex::decode(h)?
            .try_into()
            .map_err(|_| anyhow!("--salt: 32 bytes hex"))?,
        None => random_bytes(),
    };
    let mut req = ScheduleRequest::new(
        salt,
        Asset::Native,
        ctx.me,
        a.account("beneficiary")?,
        total,
        kind_from(a, total)?,
    );
    req.cancelable = !a.has("non-cancelable");
    req.transferable = a.has("transferable");
    req.refund_to = a.opt_account("refund-to")?;
    req.cancel_authority = a.opt_account("cancel-authority")?;
    req.milestone_authority = a.opt_account("milestone-authority")?;
    let params = req.params();
    let call = builders::create_schedule(&d, ctx.me, &params, a.has("fee"));
    let schedule = schedule_pda(program, &ctx.me, &salt);
    let escrow = single_escrow_pda(program, &schedule);
    if a.has("dry-run") {
        return Ok(
            json!({"dry_run": true, "schedule": schedule.to_string(), "call": print_call(&call)}),
        );
    }
    let catalog = catalog_for(program)?;
    let (included, cycles) = ctx
        .send_call(
            &call,
            &[],
            vec![],
            catalog.as_ref(),
            !a.has("no-precheck"),
            2_000_000,
        )
        .await?;
    Ok(
        json!({"tx": included.json(), "simulated_cycles": cycles, "schedule": schedule.to_string(),
              "escrow": escrow.to_string(), "escrow_balance": ctx.balance(escrow).await?.to_string()}),
    )
}

async fn show(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    let program = program_id()?;
    let id = a.account("schedule")?;
    let s = ctx.schedule(program, id).await?;
    let now = ctx.clock_ms().await?;
    let (next, reason) = next_unlock(&s, now);
    Ok(json!({
        "schedule": id.to_string(), "asset": format!("{:?}", s.asset),
        "beneficiary": s.beneficiary.to_string(), "creator": s.creator.to_string(),
        "total": s.total_amount.to_string(), "claimed": s.claimed_amount.to_string(),
        "locked": s.total_amount.saturating_sub(s.claimed_amount).to_string(),
        "claimable_now": claimable_at(&s, now).to_string(), "clock_ms": now,
        "next_unlock_ms": next, "next_unlock_utc": next.map(utc),
        "reason": if claimable_at(&s, now) > 0 { "tokens are claimable now".to_string() } else { reason.describe() },
        "cancelable": s.cancelable, "transferable": s.transferable,
        "cancelled": s.cancelled.map(|c| json!({"at_ms": c.cancelled_at_ms, "vested": c.vested_at_cancel.to_string(), "refunded": c.refunded_amount.to_string()})),
        "escrow": s.escrow_account.to_string(),
        "escrow_balance": ctx.balance(s.escrow_account).await?.to_string(),
    }))
}

async fn simple(ctx: &Ctx, a: &Args, call: Call, program: AccountId) -> Result<serde_json::Value> {
    if a.has("dry-run") {
        return Ok(json!({"dry_run": true, "call": print_call(&call)}));
    }
    let catalog = catalog_for(program)?;
    let (included, cycles) = ctx
        .send_call(
            &call,
            &[],
            vec![],
            catalog.as_ref(),
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

/// A regular private account's keys (LEZ's own derivations).
struct PrivateKeys {
    ask: AuthorizationSecretKey,
    vpk: ViewingPublicKey,
}

impl PrivateKeys {
    fn random() -> Self {
        Self {
            ask: AuthorizationSecretKey(random_bytes()),
            vpk: ViewingPublicKey::from_seed(&random_bytes(), &random_bytes()),
        }
    }
    fn nsk(&self) -> NullifierSecretKey {
        NullifierSecretKey::from(&self.ask)
    }
    fn npk(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&self.nsk())
    }
    fn id(&self) -> AccountId {
        AccountId::for_regular_private_account(&self.npk(), &self.vpk)
    }
}

async fn claim(ctx: &Ctx, a: &Args) -> Result<serde_json::Value> {
    let program = program_id()?;
    let d = Deployment {
        program,
        token_program: None,
    };
    let id = a.account("schedule")?;
    let s = ctx.schedule(program, id).await?;
    let now = ctx.clock_ms().await?;
    let requested = a.get("amount").map(str::parse::<u128>).transpose()?;
    let quote = ctx.quote().await?;
    let precheck = !a.has("no-precheck");
    if !a.has("private") {
        let to = a.account("to")?;
        let call = builders::claim_public(&d, id, &s, to, requested);
        if precheck {
            let ctx_claim = ClaimContext {
                schedule_account: id,
                schedule: &s,
                signer: ctx.me,
                asset_label: "LGO units".into(),
                now_ms: now,
                requested,
                quote,
                public_cycles: 110_000,
            };
            let prepared =
                prepare_public_claim(&ctx_claim, to, ctx.me, ctx.balance(ctx.me).await?, 1_000)
                    .map_err(|e| anyhow!("{e}"))?;
            eprintln!("{}", prepared.summary.render());
            if !prepared.summary.sufficient_gas {
                bail!("the fee payer cannot cover the fee reserve; fund it first");
            }
        }
        if a.has("dry-run") {
            return Ok(json!({"dry_run": true, "call": print_call(&call)}));
        }
        let before = ctx.balance(to).await?;
        let escrow_before = ctx.balance(s.escrow_account).await?;
        let catalog = catalog_for(program)?;
        let (included, cycles) = ctx
            .send_call(&call, &[], vec![], catalog.as_ref(), precheck, 1_000_000)
            .await?;
        let after = ctx.balance(to).await?;
        let escrow_after = ctx.balance(s.escrow_account).await?;
        // `destination_delta` nets out the fee when the destination also pays it.
        return Ok(json!({"tx": included.json(), "simulated_cycles": cycles,
                         "escrow_debited": escrow_before.saturating_sub(escrow_after).to_string(),
                         "destination_delta": (after as i128 - before as i128).to_string(),
                         "claimed_total": ctx.schedule(program, id).await?.claimed_amount.to_string()}));
    }

    // Private claim: a fresh private account receives the tokens under a one-time alias and pays
    // the in-proof fee out of the claimed credit (native asset).
    if s.asset != Asset::Native {
        bail!("this CLI's private path covers native schedules; token claims are in the SDK tests");
    }
    let (elf, _) =
        load_elf()?.context("a private claim proves the program locally: set ESCAPEMENT_ELF")?;
    let amount = match requested {
        Some(v) => v,
        None => claimable_at(&s, now),
    };
    if precheck && amount == 0 {
        let (next, reason) = next_unlock(&s, now);
        bail!(
            "Nothing is claimable yet: {}.{}",
            reason.describe(),
            next.map(|t| format!(" Next unlock at {}.", utc(t)))
                .unwrap_or_default()
        );
    }
    let keys = PrivateKeys::random();
    let factor = random_bytes();
    let alias = keys.id().blinded(&factor);
    let fee_opening = random_bytes();
    let payer_actor = Actor::native_balance(keys.id());
    let call = builders::claim_exact(&d, id, &s, alias, amount, now);
    let inbox = Actor::native_balance(system_accounts::fee_inbox_account_id());
    let mut public_actors = call.declared.clone();
    public_actors.push(inbox);
    let (_, _, commitment_root) = ctx.client.get_proofs_and_root(vec![], vec![]).await?;
    let witness = PrivateWitness {
        vpk: keys.vpk.clone(),
        random_seed: random_bytes(),
        kind: WitnessKind::Regular(RegularKey::Authorized(keys.ask)),
        nullifier: NullifierWitness::Init {
            commitment_root: DUMMY_COMMITMENT_HASH,
        },
        address_openings: BTreeSet::from([factor]),
    };
    let mut input = ProvingInput {
        root: TransactionEntry::Sync(RootCall {
            to: call.root,
            message: call.message.clone(),
        }),
        claims: Vec::new(),
        fee: None,
        public_context: PublicExecutionContext::new(public_actors.clone(), [ctx.me]),
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
                npk: keys.npk(),
                vpk: keys.vpk.clone(),
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
    let ours = Program::new(Cow::Owned(elf)).map_err(|e| anyhow!("{e}"))?;
    let programs: ProgramCatalog = [(program, ours)].into_iter().collect();
    let present = move |actor: Actor| {
        if actor == payer_actor {
            SenderPresentation::Blinded(fee_opening)
        } else {
            SenderPresentation::Blinded(random_bytes())
        }
    };
    let select = move |_, body: &MessageBody| body.to.account_id == alias;
    let cycles = lee::simulate_privacy_preserving_transaction(
        &input,
        &simulation,
        &programs,
        present,
        select,
    )
    .map_err(|e| anyhow!("simulation (nothing proven or sent): {e}"))?;
    // The fresh account holds nothing before the root: the claimed credit pays the fee at the head.
    let reserve =
        fee_core::assess::private_fee_required(cycles, quote.base_fee_exec, quote.base_fee_stor);
    if precheck && reserve >= amount {
        bail!(
            "the claim ({amount}) does not cover its own private fee ({reserve}); claim more, or claim publicly"
        );
    }
    // The disclosure names the exact reserve the proof will credit to the fee inbox.
    let disclosure = PrivacyDisclosure {
        schedule_account: id,
        beneficiary: s.beneficiary,
        amount,
        asset: "LGO units".into(),
        alias,
        fee_reserve: reserve,
    };
    eprintln!("{}", disclosure.render());
    if !a.has("accept-privacy-disclosure") {
        return Ok(
            json!({"needs_confirmation": true, "disclosure_token": disclosure.token().to_string(),
                         "fee_reserve": reserve.to_string(), "public_cycles_simulated": cycles,
                         "hint": "read the disclosure above; rerun with --accept-privacy-disclosure"}),
        );
    }
    if a.has("dry-run") {
        return Ok(
            json!({"dry_run": true, "fee_reserve": reserve.to_string(), "call": print_call(&call)}),
        );
    }
    input.fee = Some(FeeTransfer {
        payer: keys.id(),
        recipient: system_accounts::fee_inbox_account_id(),
        amount: reserve,
        refund_to: None,
    });
    let no_seal = |body: &MessageBody| -> Result<RecipientEncryption, LeeError> {
        Err(LeeError::InvalidInput(format!("no seal for {:?}", body.to)))
    };
    let started = Instant::now();
    let (output, proof) =
        lee::execute_and_prove(input, &simulation, &programs, present, select, no_seal)
            .map_err(|e| anyhow!("proving: {e}"))?;
    let prove_s = started.elapsed().as_secs_f64();
    let proof_bytes = proof.clone().into_inner().len();
    let nonce = ctx.nonce(ctx.me).await?;
    let message = PrivateMessage::from_circuit_output(BTreeMap::from([(ctx.me, nonce)]), output);
    let witness_set = PrivateWitnessSet::for_message(&message, proof, &[&ctx.key]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);
    let tx_bytes_all = borsh::to_vec(&tx)?;
    let leaks_owner = tx_bytes_all
        .windows(32)
        .any(|w| w == keys.id().value().as_slice());
    let escrow_before = ctx.balance(s.escrow_account).await?;
    let included = ctx
        .send_and_wait(LeeTransaction::PrivacyPreserving(tx))
        .await?;
    let escrow_after = ctx.balance(s.escrow_account).await?;
    let mut expected = lee::Account::funded(amount - reserve);
    expected.nonce = Nonce::default().private_account_nonce_increment(&keys.nsk());
    let (proofs, _, _) = ctx
        .client
        .get_proofs_and_root(vec![Commitment::new(&keys.id(), &expected)], vec![])
        .await?;
    let committed = proofs.first().is_some_and(Option::is_some);
    Ok(
        json!({"tx": included.json(), "amount": amount.to_string(), "alias": alias.to_string(),
              "fee_reserve": reserve.to_string(), "public_cycles_simulated": cycles,
              "prove_s": prove_s, "proof_bytes": proof_bytes,
              "escrow_debited": escrow_before.saturating_sub(escrow_after).to_string(),
              "private_commitment_found": committed, "private_account_id_in_tx_bytes": leaks_owner,
              "claimed_total": ctx.schedule(program, id).await?.claimed_amount.to_string(),
              "dev_mode": std::env::var("RISC0_DEV_MODE").is_ok_and(|v| v == "1" || v == "true")}),
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let raw: Vec<String> = std::env::args().collect();
    let command = raw.get(1).cloned().unwrap_or_default();
    let a = Args::parse(raw.get(2..).unwrap_or_default());
    if command == "keygen" {
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
        "probe" => probe(&ctx).await?,
        "fund" => fund(&ctx, &a).await?,
        "deploy" => deploy(&ctx, &a).await?,
        "configure" => configure(&ctx, &a).await?,
        "create" => create(&ctx, &a).await?,
        "show" | "claimable" => show(&ctx, &a).await?,
        "claim" => claim(&ctx, &a).await?,
        "cancel" | "make-non-cancelable" | "signal" | "transfer-beneficiary" => {
            let program = program_id()?;
            let d = Deployment {
                program,
                token_program: None,
            };
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
            let program = program_id()?;
            let d = Deployment {
                program,
                token_program: None,
            };
            let call = builders::withdraw_fees(
                &d,
                ctx.me,
                Asset::Native,
                a.account("to")?,
                a.u128("amount")?,
            );
            simple(&ctx, &a, call, program).await?
        }
        _ => {
            eprintln!(
                "{}",
                include_str!("main.rs")
                    .lines()
                    .skip(1)
                    .take(22)
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
