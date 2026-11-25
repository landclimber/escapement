//! The methods of `escapement_core_module`, as functions over JSON: one JSON request in, one JSON reply out, so they
//! run and are tested natively (`examples/call.rs`) and the module crate only forwards to them.
//!
//! - Reads: a beneficiary's schedules (locked, claimable now, next unlock in UTC) and a creator's, decoded with
//!   `escapement-core` and computed with `escapement-sdk` (the program's own math), from a LEZ v0.4.0-rc3 sequencer.
//! - Writes: a public claim, a schedule's creation (native asset) and its cancellation. Each is `prepare`d first:
//!   checked with the SDK (who may sign, what is claimable, the program's own parameter checks), built with the SDK's
//!   builders and summarised for the person; nothing is signed then. Only `approve` with that pending id signs it (with
//!   the key the module holds) and sends it; `reject` drops it. A pending transaction expires after five minutes.
//! - The key: imported from a key file the person names (64 hex digits, or `escapement keygen`'s JSON), or made by the
//!   module into its own data directory (mode 0600). It is never returned, logged or sent; only its account id is.
//!
//! - Who may call (review R1 H1, M3): every method goes through [`call`]. Only the mini-app's view
//!   (`module:escapement_ui`) and the host (`host`: logosctl, Logos Core's own anchors) are served; any other Logos
//!   module, and any caller Logos Core cannot name (`unknown`), may call `version` and nothing else. A prepared
//!   transaction can be approved only by the caller that prepared it, and only on the network it was prepared for.
//! - Units (review R1 M1): the native asset is shown with fixed units ([`NATIVE_DECIMALS`], [`NATIVE_LABEL`]) and
//!   every amount in a prompt also in base units; the prompt says which units it used.
//!
//! Every reply is `{"ok": true, ...}` or `{"ok": false, "error": "<what happened and what to do>"}`.

pub mod lez;
mod store;
#[cfg(test)]
mod testnet;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use escapement_core::{
    math::{claimable_at, vested_at, validate_schedule_params},
    schedule_pda, single_escrow_pda, Asset, Config, ScheduleAccount, ScheduleKind, VestingActorState,
};
use escapement_sdk::{
    builders::{self, Call, Deployment, ScheduleRequest},
    claim::{prepare_public_claim, ClaimContext},
    codes,
    unlock::{next_unlock, utc},
    FeeQuote, SdkError,
};
use lee_core::account::AccountId;
use serde_json::{json, Value};

use lez::{Actor, Fee, Id, Key, Message, Rpc};

pub const MODULE: &str = "escapement_core_module";
pub const VIEW: &str = "escapement_ui";
/// The view's caller name as Logos Core reports it (each Basecamp mini-app calls under its own plugin name).
pub const VIEW_CALLER: &str = "module:escapement_ui";
/// The host: logosctl and Logos Core's own anchors (anything that can reach the Logos Core daemon).
pub const HOST_CALLER: &str = "host";
/// The native asset's display units: 10^-9 of a LEZ per base unit, as the e2e suite and Ferrata's network count it.
/// Fixed in the module: a caller cannot rescale what a prompt shows (review R1 M1).
pub const NATIVE_DECIMALS: u32 = 9;
pub const NATIVE_LABEL: &str = "LEZ";
/// The program's measured cycles in the e2e suite (create 140,553; claim 79,500; cancel 77,506), with headroom:
/// without LEZ's executor in the module, a transaction's gas limit is fixed rather than simulated.
const CREATE_CYCLES: u64 = 400_000;
const CLAIM_CYCLES: u64 = 200_000;
const CANCEL_CYCLES: u64 = 200_000;
const PENDING_TTL: Duration = Duration::from_secs(300);
const WAIT_IN_CALL: Duration = Duration::from_secs(12);

// ------------------------------------------------------------------------------------------------ state

struct Pending {
    id: String,
    op: &'static str,
    prepared_by: String,
    /// The network shown in the prompt: approve refuses if the module's network changed since (review R1 L2).
    rpc_url: String,
    program: Id,
    message: Vec<u8>,
    hash: [u8; 32],
    signer: Id,
    nonce: u128,
    made: Instant,
    check: Check,
    summary: Value,
}

/// What the transaction should do, read back from the chain once it is in a block.
#[derive(Clone)]
enum Check {
    Claimed { schedule: Id, before: u128, amount: u128 },
    Created { schedule: Id },
    Cancelled { schedule: Id },
}

/// A signed transaction not yet seen in a block, kept in the module's state file (it survives a restart and a lost host
/// reply) with the network it was sent to: review R2 (Kimi M1). Settled once it is seen in a block, or dismissed.
fn unsettled_record(hash: &str, op: &str, check: &Check, summary: &Value, rpc_url: &str, program: &Id) -> Value {
    json!({ "tx_hash": hash, "op": op, "check": check.to_json(), "title": summary["title"].clone(), "summary": summary,
            "rpc_url": rpc_url, "program": lez::id_string(program), "sent_utc": utc(now_ms()) })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

impl Check {
    fn to_json(&self) -> Value {
        match self {
            Check::Claimed { schedule, before, amount } => json!({"kind": "claimed", "schedule": lez::id_string(schedule),
                "before": before.to_string(), "amount": amount.to_string()}),
            Check::Created { schedule } => json!({"kind": "created", "schedule": lez::id_string(schedule)}),
            Check::Cancelled { schedule } => json!({"kind": "cancelled", "schedule": lez::id_string(schedule)}),
        }
    }

    fn from_json(v: &Value) -> Option<Check> {
        let schedule = lez::id_from_string(v["schedule"].as_str()?).ok()?;
        Some(match v["kind"].as_str()? {
            "claimed" => Check::Claimed {
                schedule,
                before: v["before"].as_str()?.parse().ok()?,
                amount: v["amount"].as_str()?.parse().ok()?,
            },
            "created" => Check::Created { schedule },
            "cancelled" => Check::Cancelled { schedule },
            _ => return None,
        })
    }
}

#[derive(Default)]
struct State {
    key: Option<Key>,
    key_source: String,
    pending: Option<Pending>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with<T>(f: impl FnOnce(&mut State) -> Result<T, String>) -> Result<T, String> {
    let mut g = STATE.lock().map_err(|_| "the module's state is unusable after an earlier failure; restart it".to_string())?;
    f(g.get_or_insert_with(State::default))
}

// ------------------------------------------------------------------------------------------------ replies

fn reply(r: Result<Value, String>) -> String {
    match r {
        Ok(mut v) => {
            if let Some(o) = v.as_object_mut() {
                o.insert("ok".into(), json!(true));
            }
            v.to_string()
        }
        Err(e) => json!({ "ok": false, "error": e }).to_string(),
    }
}

fn parse(req: &str) -> Result<Value, String> {
    let t = req.trim();
    if t.is_empty() {
        return Ok(json!({}));
    }
    let v: Value = serde_json::from_str(t).map_err(|e| format!("the request is not JSON: {e}"))?;
    if !v.is_object() {
        return Err("the request must be a JSON object".into());
    }
    Ok(v)
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str).map(str::trim).filter(|x| !x.is_empty())
}

fn need<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    s(v, k).ok_or_else(|| format!("\"{k}\" is missing"))
}

/// An amount in base units: a decimal string (or a JSON integer) of digits only. Decimal points, signs and exponents
/// are refused: the view converts from display units with string arithmetic, so no amount ever passes a float.
pub fn base_units(v: &Value, what: &str) -> Result<u128, String> {
    let text = match v {
        Value::String(t) => t.trim().to_string(),
        Value::Number(n) if n.is_u64() => n.to_string(),
        Value::Null => return Err(format!("{what}: no amount given")),
        _ => return Err(format!("{what}: give the amount as a whole number of base units in a string")),
    };
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{what}: {text:?} is not a whole number of base units (digits only)"));
    }
    text.parse::<u128>().map_err(|_| format!("{what}: {text} is too large"))
}

/// A boolean field: absent -> `default`; anything but a JSON boolean is refused (review R1 Kimi L2).
fn flag(v: &Value, k: &str, default: bool) -> Result<bool, String> {
    match v.get(k) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(other) => Err(format!("\"{k}\" must be true or false, not {other}")),
    }
}

fn ms(v: &Value, k: &str) -> Result<u64, String> {
    match v.get(k) {
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| format!("\"{k}\": not a time in unix milliseconds")),
        Some(Value::String(t)) => t.trim().parse::<u64>().map_err(|_| format!("\"{k}\": not a time in unix milliseconds")),
        _ => Err(format!("\"{k}\" is missing (unix milliseconds)")),
    }
}

fn aid(id: &Id) -> AccountId {
    AccountId::new(*id)
}

fn hexs(b: &[u8]) -> String {
    hex::encode(b)
}

// ------------------------------------------------------------------------------------------------ chain reads

struct Net {
    rpc: Rpc,
    program: Id,
    read_only: bool,
}

fn net() -> Result<Net, String> {
    let c = store::config().ok_or("no network is set: call configure with the sequencer's address and the program id first")?;
    Ok(Net { rpc: Rpc::new(&c.rpc_url)?, program: lez::id_from_string(&c.program)?, read_only: c.read_only })
}

impl Net {
    fn deployment(&self) -> Deployment {
        Deployment { program: aid(&self.program), token_program: None }
    }

    fn clock_ms(&self) -> Result<u64, String> {
        let c = clock_core::clock_actor();
        let raw = self.rpc.state(c.account_id.value(), c.program_account_id.value())?;
        if raw.is_empty() {
            return Err("the sequencer has no clock account (not a LEZ v0.4 sequencer?)".into());
        }
        let d: clock_core::ClockAccountData =
            borsh::from_slice(&raw).map_err(|_| "the clock account does not decode as LEZ v0.4's clock".to_string())?;
        Ok(d.timestamp)
    }

    fn schedule(&self, id: &Id) -> Result<ScheduleAccount, String> {
        let raw = self.rpc.state(id, &self.program)?;
        match VestingActorState::decode(&raw) {
            Some(VestingActorState::Schedule(s)) => Ok(*s),
            Some(_) => Err(format!("{} is an Escapement account but not a schedule", lez::id_string(id))),
            None => Err(format!(
                "no Escapement schedule at {} under program {} (wrong id, wrong network, or not created yet)",
                lez::id_string(id),
                lez::id_string(&self.program)
            )),
        }
    }

    fn fee_bps(&self) -> Result<u16, String> {
        let cfg = escapement_core::config_pda(aid(&self.program));
        let raw = self.rpc.state(cfg.value(), &self.program)?;
        if raw.is_empty() {
            return Err("the program has no configuration yet (its admin has not initialised it)".into());
        }
        let c: Config = borsh::from_slice(&raw).map_err(|_| "the program's configuration does not decode".to_string())?;
        Ok(c.fee_bps)
    }

    fn quote(&self) -> Result<FeeQuote, String> {
        let (e, st) = self.rpc.base_fees()?;
        Ok(FeeQuote { base_fee_exec: u64::try_from(e).unwrap_or(u64::MAX), base_fee_stor: u64::try_from(st).unwrap_or(u64::MAX) })
    }

    fn amount(&self, base: u128) -> Value {
        json!({ "base_units": base.to_string(), "display": display(base, NATIVE_DECIMALS), "unit": NATIVE_LABEL })
    }
}

/// An amount as a prompt shows it: display units and the base units the transaction carries.
fn shown(base: u128) -> String {
    format!("{} {NATIVE_LABEL} ({base} base units)", display(base, NATIVE_DECIMALS))
}

/// An amount in running text (messages, notes): display units only.
fn words(base: u128) -> String {
    format!("{} {NATIVE_LABEL}", display(base, NATIVE_DECIMALS))
}

/// `base` as a decimal number of display units (exact: integer arithmetic only).
pub fn display(base: u128, decimals: u32) -> String {
    if decimals == 0 {
        return base.to_string();
    }
    let d = 10u128.pow(decimals.min(38));
    let (whole, frac) = (base / d, base % d);
    if frac == 0 {
        return whole.to_string();
    }
    let f = format!("{frac:0width$}", width = decimals as usize);
    format!("{whole}.{}", f.trim_end_matches('0'))
}

fn kind_json(k: &ScheduleKind) -> Value {
    match k {
        ScheduleKind::Linear { start_ts, end_ts } => json!({
            "type": "linear", "start_ms": start_ts, "end_ms": end_ts, "start_utc": utc(*start_ts), "end_utc": utc(*end_ts)
        }),
        ScheduleKind::CliffLinear { start_ts, cliff_ts, end_ts, cliff_amount } => json!({
            "type": "cliff_linear", "start_ms": start_ts, "cliff_ms": cliff_ts, "end_ms": end_ts,
            "start_utc": utc(*start_ts), "cliff_utc": utc(*cliff_ts), "end_utc": utc(*end_ts), "cliff_amount": cliff_amount.to_string()
        }),
        ScheduleKind::Milestone { tranches } => json!({
            "type": "milestone",
            "tranches": tranches.iter().map(|t| json!({"amount": t.amount.to_string(), "unlocked": t.unlocked})).collect::<Vec<_>>()
        }),
    }
}

/// An amount of a schedule's asset: native in LEZ (display and base units); a token only in its own base units, named
/// by its definition (the module has no token metadata: review R1 Kimi M1).
fn asset_amount(n: &Net, asset: &Asset, base: u128) -> Value {
    match asset {
        Asset::Native => n.amount(base),
        Asset::Token { definition } => {
            json!({ "base_units": base.to_string(), "display": base.to_string(), "unit": format!("base units of token {definition}") })
        }
    }
}

/// Only native schedules are claimed or cancelled from the module for now.
fn native_only(sch: &ScheduleAccount, what: &str) -> Result<(), String> {
    match sch.asset {
        Asset::Native => Ok(()),
        Asset::Token { definition } => Err(format!(
            "this schedule pays token {definition}, not native {NATIVE_LABEL}: {what} it with the escapement CLI (the module handles native schedules only for now)"
        )),
    }
}

fn row(n: &Net, id: &Id, s: &ScheduleAccount, now: u64) -> Value {
    let vested = vested_at(s, now);
    let claimable = claimable_at(s, now);
    let (next, reason) = next_unlock(s, now);
    let refunded = s.cancelled.map_or(0, |c| c.refunded_amount);
    let locked = s.total_amount.saturating_sub(vested).saturating_sub(refunded);
    let next_label = match (&s.kind, next) {
        (_, None) => match reason {
            escapement_sdk::NextUnlockReason::MilestonePending { .. } => "when the milestone authority signals the next tranche".to_string(),
            _ => "none".to_string(),
        },
        (ScheduleKind::Linear { start_ts, end_ts }, Some(t)) if now >= *start_ts && t < *end_ts => {
            format!("accruing continuously until {}", utc(*end_ts))
        }
        (ScheduleKind::CliffLinear { cliff_ts, end_ts, .. }, Some(t)) if now >= *cliff_ts && t < *end_ts => {
            format!("accruing continuously until {}", utc(*end_ts))
        }
        (_, Some(t)) => utc(t),
    };
    json!({
        "schedule": lez::id_string(id),
        "creator": s.creator.to_string(),
        "beneficiary": s.beneficiary.to_string(),
        "asset": match s.asset { Asset::Native => "native".to_string(), Asset::Token { definition } => format!("token {definition}") },
        "native": s.asset.is_native(),
        "total": asset_amount(n, &s.asset, s.total_amount),
        "vested": asset_amount(n, &s.asset, vested),
        "claimed": asset_amount(n, &s.asset, s.claimed_amount),
        "claimable_now": asset_amount(n, &s.asset, claimable),
        "locked": asset_amount(n, &s.asset, locked),
        "next_unlock_ms": next,
        "next_unlock_utc": next.map(utc),
        "next_unlock_label": next_label,
        "status": if claimable > 0 { "tokens are claimable now".to_string() } else { reason.describe() },
        "kind": kind_json(&s.kind),
        "cancelable": s.cancelable,
        "cancel_authority": s.effective_cancel_authority().to_string(),
        "cancelled": s.cancelled.map(|c| json!({"at_utc": utc(c.cancelled_at_ms), "vested": c.vested_at_cancel.to_string(), "refunded": c.refunded_amount.to_string()})),
    })
}

// ------------------------------------------------------------------------------------------------ methods

/// Whether the module serves this caller (review R1 H1, M3).
fn allowed(caller: &str) -> bool {
    caller == VIEW_CALLER || caller == HOST_CALLER
}

fn refuse_caller(caller: &str, method: &str) -> String {
    json!({ "ok": false, "error": format!(
        "refused: {caller} may not call {method} (escapement_core_module serves only its view, {VIEW_CALLER}, and the host)"
    ) })
    .to_string()
}

/// Every method, by name, for `caller` as Logos Core names it (`module:<name>`, `host` or `unknown`). Only `version`
/// is open to every caller; the rest serve the view and the host alone.
pub fn call(method: &str, request: &str, caller: &str) -> String {
    if method != "version" && !allowed(caller) {
        return refuse_caller(caller, method);
    }
    match method {
        "version" => version(),
        "configure" => configure(request),
        "status" => status(request),
        "key" => key(request),
        "schedules" => schedules(request),
        "track" => track(request),
        "prepare_claim" => prepare_claim(request, caller),
        "prepare_create" => prepare_create(request, caller),
        "prepare_cancel" => prepare_cancel(request, caller),
        "approve" => approve(request, caller),
        "reject" => reject(request, caller),
        "tx_status" => tx_status(request),
        m => json!({ "ok": false, "error": format!("unknown method {m:?}") }).to_string(),
    }
}

fn version() -> String {
    reply(Ok(json!({
        "module": MODULE,
        "version": env!("CARGO_PKG_VERSION"),
        "lez": "v0.4.0-rc3 (bafd07be)",
        "staged": store::staged(),
        "methods": ["version", "configure", "status", "key", "schedules", "track", "prepare_claim", "prepare_create",
                    "prepare_cancel", "approve", "reject", "tx_status"],
        "writes": "public claim, create (native asset), cancel; each signed only by approve(pending_id) after prepare, by the caller that prepared it",
        "callers": [VIEW_CALLER, HOST_CALLER],
        "units": { "decimals": NATIVE_DECIMALS, "unit": NATIVE_LABEL },
        "not_yet": ["private claim (the CLI does it; the module does not prove)", "token schedules from the view", "milestone signals"],
    })))
}

/// `{rpc_url, program, read_only?}`: the network the module reads and sends to. The answer says what the sequencer
/// reports (head block, clock) and whether the program is configured there. The native asset's units are fixed:
/// `decimals` or `asset_label` other than the module's are refused.
fn configure(req: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        if r.get("decimals").is_some_and(|d| d.as_u64() != Some(u64::from(NATIVE_DECIMALS)))
            || r.get("asset_label").is_some_and(|l| l.as_str() != Some(NATIVE_LABEL))
        {
            return Err(format!(
                "the native asset's units are fixed in the module ({NATIVE_DECIMALS} decimals, {NATIVE_LABEL}); they cannot be configured"
            ));
        }
        let rpc = Rpc::new(need(&r, "rpc_url")?)?;
        let program = lez::id_from_string(need(&r, "program")?)?;
        let head = rpc.head()?;
        let c = store::Config {
            rpc_url: rpc.url.clone(),
            program: lez::id_string(&program),
            read_only: flag(&r, "read_only", false)?,
        };
        store::set_config(&c)?;
        with(|st| {
            st.pending = None;
            Ok(())
        })?;
        let n = net()?;
        let clock = n.clock_ms()?;
        let fee = n.fee_bps();
        Ok(json!({
            "rpc_url": c.rpc_url, "program": c.program, "read_only": c.read_only, "head": head,
            "clock_utc": utc(clock), "program_configured": fee.is_ok(), "fee_bps": fee.as_ref().ok(),
            "note": fee.err(), "asset_label": NATIVE_LABEL, "decimals": NATIVE_DECIMALS,
        }))
    })())
}

/// The network, the key's account (never the key) and its balance, and whether a transaction waits for approval (its
/// kind and age; not its id, which only the caller that prepared it holds: review R1 H1).
fn status(_req: &str) -> String {
    reply((|| {
        let cfg = store::config();
        let (account, source, pending) = with(|st| {
            Ok((
                st.key.as_ref().map(|k| k.id),
                st.key_source.clone(),
                st.pending.as_ref().map(|p| json!({"op": p.op, "age_s": p.made.elapsed().as_secs()})),
            ))
        })?;
        let unsettled: Vec<Value> = store::unsettled()
            .iter()
            .map(|x| json!({"tx_hash": x["tx_hash"], "op": x["op"], "title": x["title"], "rpc_url": x["rpc_url"],
                            "program": x["program"], "sent_utc": x["sent_utc"]}))
            .collect();
        let mut out = json!({ "network": cfg.as_ref().map(|c| json!({"rpc_url": c.rpc_url, "program": c.program, "read_only": c.read_only, "asset_label": NATIVE_LABEL, "decimals": NATIVE_DECIMALS})),
                              "account": account.map(|a| lez::id_string(&a)), "key_source": source, "pending": pending,
                              "unsettled": unsettled });
        if let (Ok(n), Some(a)) = (net(), account) {
            match (n.rpc.head(), n.clock_ms(), n.rpc.balance(&a)) {
                (Ok(h), Ok(c), Ok(b)) => {
                    out["head"] = json!(h);
                    out["clock_utc"] = json!(utc(c));
                    out["balance"] = n.amount(b);
                }
                (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => out["network_error"] = json!(e),
            }
        }
        Ok(out)
    })())
}

/// `{"action": "import", "path"}` (a key file: 64 hex digits, or `escapement keygen`'s JSON), `{"action": "new"}`
/// (a fresh key written to the module's data directory, mode 0600), `{"action": "show"}`, `{"action": "forget"}`.
/// Only the account id and the public key are returned.
fn key(req: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        let action = s(&r, "action").unwrap_or("show");
        let (k, source) = match action {
            "import" => {
                let path = need(&r, "path")?;
                (Key::from_file(path)?, format!("file {path}"))
            }
            "new" => {
                let k = Key::fresh()?;
                let path = store::write_key(&lez::id_string(&k.id), &k.to_hex())?;
                (k, format!("new key, written to {path} (mode 0600)"))
            }
            "show" => {
                return with(|st| {
                    Ok(json!({ "account": st.key.as_ref().map(|k| lez::id_string(&k.id)),
                               "public_key": st.key.as_ref().map(|k| hexs(&k.pk)), "key_source": st.key_source }))
                })
            }
            "forget" => {
                return with(|st| {
                    st.key = None;
                    st.key_source.clear();
                    st.pending = None;
                    Ok(json!({ "account": null }))
                })
            }
            a => return Err(format!("action {a:?}: use import, new, show or forget")),
        };
        let out = json!({ "account": lez::id_string(&k.id), "public_key": hexs(&k.pk), "key_source": source });
        with(|st| {
            st.key = Some(k);
            st.key_source = source;
            st.pending = None;
            Ok(())
        })?;
        Ok(out)
    })())
}

fn my_account() -> Result<Id, String> {
    with(|st| st.key.as_ref().map(|k| k.id).ok_or_else(|| "no key: import a key file or make a new key first".to_string()))
}

/// `{beneficiary?, creator?, ids?}`: the schedules the module knows on this network (those it created or was told of
/// with `track`, and `ids`), read live: `positions` where `beneficiary` (default: the key's account) is the
/// beneficiary, `created` where `creator` (default: the key's account) created them. There is no indexer: a schedule
/// made elsewhere appears once its id is tracked.
fn schedules(req: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        let n = net()?;
        let me = my_account().ok();
        let beneficiary = match s(&r, "beneficiary") {
            Some(b) => Some(lez::id_from_string(b)?),
            None => me,
        };
        let creator = match s(&r, "creator") {
            Some(c) => Some(lez::id_from_string(c)?),
            None => me,
        };
        let mut ids: Vec<Id> = store::tracked(&n.rpc.url, &lez::id_string(&n.program))
            .iter()
            .filter_map(|t| lez::id_from_string(t).ok())
            .collect();
        if let Some(extra) = r.get("ids").and_then(Value::as_array) {
            for e in extra {
                let id = lez::id_from_string(e.as_str().ok_or("ids: account ids as strings")?)?;
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
        let now = n.clock_ms()?;
        let (mut positions, mut created, mut unreadable) = (Vec::new(), Vec::new(), Vec::new());
        for id in &ids {
            match n.schedule(id) {
                Ok(sch) => {
                    let row = row(&n, id, &sch, now);
                    if beneficiary.is_some_and(|b| sch.beneficiary.value() == &b) {
                        positions.push(row.clone());
                    }
                    if creator.is_some_and(|c| sch.creator.value() == &c) {
                        created.push(row);
                    }
                }
                Err(e) => unreadable.push(json!({"schedule": lez::id_string(id), "error": e})),
            }
        }
        Ok(json!({
            "clock_ms": now, "clock_utc": utc(now), "beneficiary": beneficiary.map(|b| lez::id_string(&b)),
            "creator": creator.map(|c| lez::id_string(&c)), "positions": positions, "created": created,
            "unreadable": unreadable, "known": ids.len(), "asset_label": NATIVE_LABEL, "decimals": NATIVE_DECIMALS,
        }))
    })())
}

/// `{schedule}`: remember a schedule id on this network (checked: it must be a schedule of the program).
fn track(req: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        let n = net()?;
        let id = lez::id_from_string(need(&r, "schedule")?)?;
        let sch = n.schedule(&id)?;
        store::track(&n.rpc.url, &lez::id_string(&n.program), &lez::id_string(&id))?;
        Ok(row(&n, &id, &sch, n.clock_ms()?))
    })())
}

// ------------------------------------------------------------------------------------------------ prepare

fn writable(n: &Net) -> Result<(), String> {
    if n.read_only {
        return Err("this network is set read-only in the module: nothing is signed or sent here".into());
    }
    Ok(())
}

/// The CLI's fee rule (`escapement-cli` `build_public`): price = max(base fees) x 8, at least 64; max_fee =
/// (gas_limit + 1,100,000) x price. The sequencer charges what is used, at most max_fee.
fn max_fee(q: &FeeQuote, gas_limit: u64) -> u128 {
    let price = u128::from(q.base_fee_exec.max(q.base_fee_stor).saturating_mul(8).max(64));
    (u128::from(gas_limit) + 1_100_000) * price
}

fn new_id() -> Result<String, String> {
    let mut raw = [0u8; 12];
    getrandom::getrandom(&mut raw).map_err(|e| format!("no randomness from the operating system: {e}"))?;
    Ok(hexs(&raw))
}

#[allow(clippy::too_many_arguments)]
fn stage(
    n: &Net,
    op: &'static str,
    caller: &str,
    call: &Call,
    gas_limit: u64,
    check: Check,
    title: String,
    rows: Vec<(String, String)>,
    effects: Vec<String>,
    extra_needed: u128,
) -> Result<Value, String> {
    if !allowed(caller) {
        return Err(format!("refused: {caller} may not prepare Escapement transactions"));
    }
    let me = my_account()?;
    if call.root.account_id.value() != &me {
        return Err(format!(
            "this transaction must be signed by {}; the module's key is {}",
            call.root.account_id,
            lez::id_string(&me)
        ));
    }
    let q = n.quote()?;
    let fee = max_fee(&q, gas_limit);
    let balance = n.rpc.balance(&me)?;
    let needed = fee.saturating_add(extra_needed);
    if balance < needed {
        return Err(format!(
            "your account {} holds {} but this needs up to {} (amount and the fee reserve): fund it first",
            lez::id_string(&me),
            words(balance),
            words(needed),
        ));
    }
    let nonce = n.rpc.nonce(&me)?;
    let actors: Vec<Actor> = call
        .declared
        .iter()
        .chain(std::iter::once(&call.root))
        .map(|a| Actor { account: *a.account_id.value(), program: *a.program_account_id.value() })
        .collect();
    let m = Message {
        actors,
        to: Actor { account: *call.root.account_id.value(), program: *call.root.program_account_id.value() },
        data: call.message.clone(),
        fee: Some(Fee { payer: me, gas_limit, tip: 0, max_fee: fee }),
        nonces: vec![(me, nonce)],
    };
    let bytes = lez::encode_message(&m);
    let hash = lez::message_hash(&bytes);
    let id = new_id()?;
    let mut all_rows: Vec<Value> = rows.into_iter().map(|(a, b)| json!([a, b])).collect();
    all_rows.push(json!(["Signed by (and pays the fee)", lez::id_string(&me)]));
    all_rows.push(json!(["Fee, at most", format!("{} (gas limit {gas_limit}; charged as used)", shown(fee))]));
    all_rows.push(json!(["Network", format!("{} (program {})", n.rpc.url, lez::id_string(&n.program))]));
    let summary = json!({
        "pending_id": id, "op": op, "title": title, "rows": all_rows, "effects": effects,
        "max_fee": n.amount(fee), "balance": n.amount(balance), "signer": lez::id_string(&me),
        "message_hash": hexs(&hash), "expires_in_s": PENDING_TTL.as_secs(), "signed": false,
        "decimals": NATIVE_DECIMALS, "unit": NATIVE_LABEL,
        "network": { "rpc_url": n.rpc.url, "program": lez::id_string(&n.program) },
    });
    with(|st| {
        st.pending = Some(Pending {
            id,
            op,
            prepared_by: caller.to_string(),
            rpc_url: n.rpc.url.clone(),
            program: n.program,
            message: bytes,
            hash,
            signer: me,
            nonce,
            made: Instant::now(),
            check,
            summary: summary.clone(),
        });
        Ok(())
    })?;
    Ok(summary)
}

/// The SDK's refusal in the person's units: its amounts are base units, the view's are display units.
fn sdk_message(e: SdkError) -> String {
    match e {
        SdkError::ExceedsClaimable { requested, claimable } => format!(
            "You asked to claim {} but only {} is claimable now; claim at most {}.",
            words(requested),
            words(claimable),
            words(claimable)
        ),
        other => other.to_string(),
    }
}

/// `{schedule, amount?, to?}`: a public claim by the key's account (it must be the beneficiary); `amount` in base units
/// (default: everything claimable now), `to` a public account (default: the beneficiary itself).
fn prepare_claim(req: &str, caller: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        let n = net()?;
        writable(&n)?;
        let me = my_account()?;
        let sid = lez::id_from_string(need(&r, "schedule")?)?;
        let sch = n.schedule(&sid)?;
        native_only(&sch, "claim")?;
        let to = match s(&r, "to") {
            Some(t) => lez::id_from_string(t)?,
            None => me,
        };
        let requested = match r.get("amount") {
            None | Some(Value::Null) => None,
            Some(Value::String(t)) if t.trim().is_empty() => None,
            Some(v) => Some(base_units(v, "amount")?),
        };
        let now = n.clock_ms()?;
        let q = n.quote()?;
        let balance = n.rpc.balance(&me)?;
        let ctx = ClaimContext {
            schedule_account: aid(&sid),
            schedule: &sch,
            signer: aid(&me),
            asset_label: NATIVE_LABEL.to_string(),
            now_ms: now,
            requested,
            quote: q,
            public_cycles: CLAIM_CYCLES,
        };
        let p = prepare_public_claim(&ctx, aid(&to), aid(&me), balance, 400).map_err(sdk_message)?;
        let call = builders::claim_public(&n.deployment(), aid(&sid), &sch, aid(&to), Some(p.amount));
        let rows = vec![
            ("Schedule".to_string(), lez::id_string(&sid)),
            ("Claim".to_string(), shown(p.amount)),
            ("Claimable now".to_string(), shown(claimable_at(&sch, now))),
            ("To (public account)".to_string(), lez::id_string(&to)),
        ];
        let effects = vec![
            format!("Moves {} from the schedule's escrow to {} (public).", shown(p.amount), lez::id_string(&to)),
            "Public on chain: the schedule, the amount, the time and the destination (a private claim is not in this view yet)."
                .to_string(),
        ];
        stage(
            &n,
            "claim",
            caller,
            &call,
            p.gas_limit,
            Check::Claimed { schedule: sid, before: sch.claimed_amount, amount: p.amount },
            format!("Claim {} (public)", shown(p.amount)),
            rows,
            effects,
            0,
        )
    })())
}

/// `{beneficiary, total, kind: "linear"|"cliff", start_ms, end_ms, cliff_ms?, cliff_amount?, cancelable?}`: a new
/// schedule of the native asset, funded by the key's account; amounts in base units.
fn prepare_create(req: &str, caller: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        let n = net()?;
        writable(&n)?;
        let me = my_account()?;
        let beneficiary = lez::id_from_string(need(&r, "beneficiary")?)?;
        let total = base_units(r.get("total").unwrap_or(&Value::Null), "total")?;
        let start = ms(&r, "start_ms")?;
        let end = ms(&r, "end_ms")?;
        let kind = match s(&r, "kind").unwrap_or("linear") {
            "linear" => ScheduleKind::Linear { start_ts: start, end_ts: end },
            "cliff" | "cliff_linear" => ScheduleKind::CliffLinear {
                start_ts: start,
                cliff_ts: ms(&r, "cliff_ms")?,
                end_ts: end,
                cliff_amount: base_units(r.get("cliff_amount").unwrap_or(&Value::Null), "cliff_amount")?,
            },
            k => return Err(format!("kind {k:?}: the view creates \"linear\" or \"cliff\" schedules (milestones: the CLI)")),
        };
        let fee_bps = n.fee_bps()?;
        validate_schedule_params(total, &kind, fee_bps, 0).map_err(|e| {
            let code = e.code();
            codes::refusal(u32::from(code)).map_or_else(|| e.message(), |x| x.message.to_string())
        })?;
        let mut salt = [0u8; 32];
        getrandom::getrandom(&mut salt).map_err(|e| format!("no randomness from the operating system: {e}"))?;
        let mut sr = ScheduleRequest::new(salt, Asset::Native, aid(&me), aid(&beneficiary), total, kind.clone());
        sr.cancelable = flag(&r, "cancelable", true)?;
        let params = sr.params();
        let call = builders::create_schedule(&n.deployment(), aid(&me), &params, fee_bps > 0);
        let sid = *schedule_pda(aid(&n.program), &aid(&me), &salt).value();
        let escrow = single_escrow_pda(aid(&n.program), &aid(&sid));
        let k = kind_json(&kind);
        let mut rows = vec![
            ("Beneficiary".to_string(), lez::id_string(&beneficiary)),
            ("Total".to_string(), format!("{} (native)", shown(total))),
            ("Vesting".to_string(), match &kind {
                ScheduleKind::Linear { .. } => format!("linear from {} to {}", k["start_utc"].as_str().unwrap_or(""), k["end_utc"].as_str().unwrap_or("")),
                _ => format!(
                    "cliff at {} ({}), then linear to {}",
                    k["cliff_utc"].as_str().unwrap_or(""),
                    shown(base_units(&k["cliff_amount"], "cliff").unwrap_or(0)),
                    k["end_utc"].as_str().unwrap_or("")
                ),
            }),
            ("Cancelable".to_string(), if sr.cancelable { "yes, by you (the unvested part comes back)".into() } else { "no".into() }),
            ("New schedule id".to_string(), lez::id_string(&sid)),
        ];
        if fee_bps > 0 {
            rows.push(("Protocol fee".to_string(), format!("{fee_bps} bps of the total")));
        }
        let effects = vec![
            format!("Moves {} from your account into the schedule's escrow {escrow}.", shown(total)),
            "Public on chain: the schedule's terms, the beneficiary and the amount.".to_string(),
        ];
        stage(
            &n,
            "create",
            caller,
            &call,
            CREATE_CYCLES,
            Check::Created { schedule: sid },
            format!("Create a schedule of {} for {}", shown(total), lez::id_string(&beneficiary)),
            rows,
            effects,
            total,
        )
    })())
}

/// `{schedule}`: cancel a schedule as its cancel authority (the key's account).
fn prepare_cancel(req: &str, caller: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        let n = net()?;
        writable(&n)?;
        let me = my_account()?;
        let sid = lez::id_from_string(need(&r, "schedule")?)?;
        let sch = n.schedule(&sid)?;
        native_only(&sch, "cancel")?;
        if sch.cancelled.is_some() {
            return Err("this schedule is already cancelled".into());
        }
        if !sch.cancelable {
            return Err("this schedule was made non-cancelable; it cannot be cancelled".into());
        }
        if sch.effective_cancel_authority().value() != &me {
            return Err(format!(
                "only the cancel authority {} can cancel this schedule; the module's key is {}",
                sch.effective_cancel_authority(),
                lez::id_string(&me)
            ));
        }
        let now = n.clock_ms()?;
        let vested = vested_at(&sch, now);
        let refund = sch.total_amount.saturating_sub(vested);
        let call = builders::cancel(&n.deployment(), aid(&sid), &sch);
        let rows = vec![
            ("Schedule".to_string(), lez::id_string(&sid)),
            ("Beneficiary".to_string(), sch.beneficiary.to_string()),
            ("Vested so far".to_string(), format!("{} (stays claimable by the beneficiary)", shown(vested))),
            ("Unvested, refunded".to_string(), format!("about {} to {}", shown(refund), sch.refund_holding)),
        ];
        let effects = vec![
            "Stops vesting now; the amounts are fixed at the block's time, so they may differ slightly from these.".to_string(),
            "Public on chain: the cancellation, the vested and refunded amounts.".to_string(),
        ];
        stage(
            &n,
            "cancel",
            caller,
            &call,
            CANCEL_CYCLES,
            Check::Cancelled { schedule: sid },
            format!("Cancel schedule {}", lez::id_string(&sid)),
            rows,
            effects,
            0,
        )
    })())
}

// ------------------------------------------------------------------------------------------------ approve

/// Who may approve: the view or the host, and only what that same caller prepared (review R1 H1: `unknown`, or any
/// other name, is refused; there is no exception).
fn may_approve(caller: &str, prepared_by: &str) -> Result<(), String> {
    if !allowed(caller) {
        return Err(format!("refused: {caller} may not approve Escapement transactions (only the {VIEW} view or the host)"));
    }
    if caller != prepared_by {
        return Err(format!("refused: prepared by {prepared_by}, approved by {caller}: approve from where it was prepared"));
    }
    Ok(())
}

fn outcome(n: &Net, check: &Check) -> Result<Value, String> {
    Ok(match check {
        Check::Claimed { schedule, before, amount } => {
            let sch = n.schedule(schedule)?;
            let applied = sch.claimed_amount >= before.saturating_add(*amount);
            json!({"applied": applied, "claimed_total": n.amount(sch.claimed_amount),
                   "detail": if applied { "the claim is recorded on the schedule" } else { "the schedule shows no new claim: the program refused it (reverted); nothing moved" }})
        }
        // Only an answer that shows no schedule at the new id is a revert; a read that fails is an unread outcome (the
        // caller reports applied: null): review R2 (Kimi).
        Check::Created { schedule } => {
            let raw = n.rpc.state(schedule, &n.program)?;
            if raw.is_empty() {
                json!({"applied": false, "schedule": lez::id_string(schedule),
                       "detail": "no schedule at the new id: the program refused it (reverted); nothing moved but the fee"})
            } else {
                match VestingActorState::decode(&raw) {
                    Some(VestingActorState::Schedule(sch)) => json!({"applied": true, "schedule": lez::id_string(schedule),
                        "total": n.amount(sch.total_amount), "detail": "the schedule exists and its escrow is funded"}),
                    _ => return Err("the account at the new id holds something that does not read as a schedule".into()),
                }
            }
        }
        Check::Cancelled { schedule } => {
            let sch = n.schedule(schedule)?;
            match sch.cancelled {
                Some(c) => json!({"applied": true, "vested": n.amount(c.vested_at_cancel), "refunded": n.amount(c.refunded_amount),
                                  "detail": "the schedule is cancelled"}),
                None => json!({"applied": false, "detail": "the schedule is not cancelled: the program refused it (reverted)"}),
            }
        }
    })
}

/// `{pending_id}`: sign the prepared transaction exactly as prepared (once), send it, and wait up to 12 s for its block;
/// then read the schedule back to say whether the program applied it. Later: `tx_status`.
fn approve(req: &str, caller: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        let id = need(&r, "pending_id")?.to_string();
        let n = net()?;
        writable(&n)?;
        // The transaction is taken out (it can be approved once) only when this caller may approve it.
        let p = with(|st| {
            match &st.pending {
                Some(p) if p.id == id => may_approve(caller, &p.prepared_by)?,
                _ => return Err("no transaction waits for approval under this id (sent, rejected, replaced or expired): prepare it again".into()),
            }
            let p = st.pending.take().expect("checked above");
            if p.made.elapsed() >= PENDING_TTL {
                return Err("the approval came after five minutes (fees and nonces move): prepare it again".into());
            }
            Ok(p)
        })?;
        // Review R1 L2: only to the network the prompt showed.
        if n.rpc.url != p.rpc_url || n.program != p.program {
            return Err(format!(
                "the module's network changed since this was prepared (prompt: {} program {}; now: {} program {}): nothing was signed; prepare it again",
                p.rpc_url,
                lez::id_string(&p.program),
                n.rpc.url,
                lez::id_string(&n.program)
            ));
        }
        // The nonce before the signature: nothing is signed that cannot be sent.
        if n.rpc.nonce(&p.signer)? != p.nonce {
            return Err("your account sent another transaction since this was prepared: prepare it again (nothing was signed or sent)".into());
        }
        let tx = with(|st| {
            let k = st.key.as_ref().filter(|k| k.id == p.signer).ok_or("the key changed since this was prepared: prepare it again")?;
            let sig = k.sign(&p.hash)?;
            Ok(lez::encode_transaction(&p.message, &[(sig, k.pk)]))
        })?;
        let (wire, hash) = lez::wire(&tx);
        // From here on the transaction exists: it is recorded before the send, and every later failure says so with its
        // hash instead of looking like a refusal (review R1 Kimi M6).
        store::add_unsettled(unsettled_record(&hash, p.op, &p.check, &p.summary, &p.rpc_url, &p.program))?;
        let mut out = json!({"op": p.op, "tx_hash": hash, "summary": p.summary, "signed_by": lez::id_string(&p.signer),
                             "approved_by": caller});
        let unknown = |mut out: Value, why: String| {
            out["state"] = json!("unknown");
            out["warning"] = json!(format!(
                "signed and sent, but {why}: it may or may not be in a block. Check it (tx_status {hash}, or Refresh) before trying again."
            ));
            Ok(out)
        };
        match n.rpc.send(&wire) {
            Err(lez::RpcError::Transport(e)) => return unknown(out, format!("the sequencer's answer did not arrive ({e})")),
            // Review R2 L1: the sequencer answered with a refusal: not a lost answer.
            Err(lez::RpcError::Refused(e)) => {
                out["state"] = json!("refused_by_sequencer");
                out["warning"] = json!(format!(
                    "the sequencer refused it ({e}); it should not be in a block. Check it (tx_status {hash}, or Refresh) before trying again."
                ));
                return Ok(out);
            }
            Ok(answered) => {
                if let Some(a) = answered.as_str() {
                    if !a.trim_start_matches("0x").eq_ignore_ascii_case(&hash) {
                        return unknown(out, format!("the sequencer named it {a}, not {hash}"));
                    }
                }
            }
        }
        if let Check::Created { schedule } = &p.check {
            if let Err(e) = store::track(&n.rpc.url, &lez::id_string(&n.program), &lez::id_string(schedule)) {
                out["note"] = json!(format!("the new schedule's id could not be remembered ({e}): add it by its id"));
            }
        }
        let t0 = Instant::now();
        let (mut block, mut poll_error) = (None, None);
        while t0.elapsed() < WAIT_IN_CALL {
            match n.rpc.block_of(&hash) {
                Ok(Some(b)) => {
                    block = Some(b);
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(700)),
                Err(e) => {
                    poll_error = Some(e);
                    break;
                }
            }
        }
        match block {
            Some(b) => {
                let _ = store::settle(&hash);
                out["block"] = json!(b);
                out["state"] = json!("in_block");
                out["outcome"] = outcome(&n, &p.check).unwrap_or_else(|e| {
                    json!({"applied": null, "detail": format!("in block {b}, but the schedule could not be read back ({e}): check before trying again")})
                });
            }
            None => {
                out["state"] = json!("sent");
                out["note"] = json!(match poll_error {
                    Some(e) => format!("sent; whether it is in a block could not be read ({e}): ask tx_status with this tx_hash"),
                    None => "sent; not in a block yet: ask tx_status with this tx_hash".to_string(),
                });
            }
        }
        Ok(out)
    })())
}

/// `{pending_id?}`: drop the pending transaction (nothing was signed).
fn reject(req: &str, caller: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        let id = s(&r, "pending_id").map(str::to_string);
        with(|st| {
            if let Some(p) = &st.pending {
                if p.prepared_by != caller {
                    return Err(format!("refused: prepared by {}, rejected by {caller}: reject from where it was prepared", p.prepared_by));
                }
            }
            let dropped = match (&st.pending, &id) {
                (Some(p), Some(i)) if &p.id == i => st.pending.take().map(|p| p.id),
                (Some(_), None) => st.pending.take().map(|p| p.id),
                _ => None,
            };
            Ok(json!({"rejected": dropped, "signed": false}))
        })
    })())
}

/// `{tx_hash, dismiss?}`: whether a transaction sent by `approve` is in a block, and its outcome read back from the
/// schedule, on the network it was sent to (its record); once in a block it is settled. `dismiss: true` drops the
/// record (the person has seen it and takes it from here).
fn tx_status(req: &str) -> String {
    reply((|| {
        let r = parse(req)?;
        let hash = need(&r, "tx_hash")?.trim_start_matches("0x").to_lowercase();
        let record = store::unsettled().into_iter().find(|x| x["tx_hash"].as_str() == Some(hash.as_str()));
        if flag(&r, "dismiss", false)? {
            store::settle(&hash)?;
            return Ok(json!({"tx_hash": hash, "dismissed": record.is_some()}));
        }
        // The network the transaction went to, not the one configured now (review R2, Kimi M1).
        let n = match &record {
            Some(x) => Net {
                rpc: Rpc::new(x["rpc_url"].as_str().unwrap_or(""))?,
                program: lez::id_from_string(x["program"].as_str().unwrap_or(""))?,
                read_only: true,
            },
            None => net()?,
        };
        let block = n.rpc.block_of(&hash)?;
        let mut out = json!({"tx_hash": hash, "block": block, "state": if block.is_some() { "in_block" } else { "not_in_a_block_yet" },
                             "network": {"rpc_url": n.rpc.url, "program": lez::id_string(&n.program)}});
        if let (Some(b), Some(x)) = (block, &record) {
            out["op"] = x["op"].clone();
            out["summary"] = x["summary"].clone();
            // Review R2 L3: an unreadable read-back is an unread outcome, as in approve, not a failed call.
            out["outcome"] = match Check::from_json(&x["check"]) {
                Some(check) => outcome(&n, &check).unwrap_or_else(|e| {
                    json!({"applied": null, "detail": format!("in block {b}, but the schedule could not be read back ({e}): check before trying again")})
                }),
                None => json!({"applied": null, "detail": "in block; the record of what it should do is unreadable"}),
            };
            store::settle(&hash)?;
        }
        Ok(out)
    })())
}

/// The program's refusal code as a plain message (for the view's errors).
pub fn refusal_message(code: u32) -> Option<&'static str> {
    codes::refusal(code).map(|r| r.message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_exact() {
        assert_eq!(display(1, 9), "0.000000001");
        assert_eq!(display(1_500_000_000, 9), "1.5");
        assert_eq!(display(u128::MAX, 9), "340282366920938463463374607431.768211455");
        assert_eq!(display(42, 0), "42");
        assert_eq!(base_units(&json!("1000"), "x").unwrap(), 1000);
        assert!(base_units(&json!("1.5"), "x").is_err());
        assert!(base_units(&json!("-1"), "x").is_err());
        assert!(base_units(&json!("1e9"), "x").is_err());
        assert!(base_units(&json!(1.5), "x").is_err());
        assert!(base_units(&json!("340282366920938463463374607431768211456"), "x").is_err());
    }

    #[test]
    fn approvals_come_from_the_view_or_the_host() {
        assert!(may_approve("module:escapement_ui", "module:escapement_ui").is_ok());
        assert!(may_approve("host", "host").is_ok());
        assert!(may_approve("module:other", "module:other").is_err());
        assert!(may_approve("host", "module:escapement_ui").is_err());
        // Review R1 H1: `unknown` is refused, whoever prepared.
        assert!(may_approve("unknown", "unknown").is_err());
        assert!(may_approve("unknown", "module:escapement_ui").is_err());
        assert!(may_approve("module:escapement_ui", "unknown").is_err());
        assert!(may_approve("unknown", "host").is_err());
    }

    #[test]
    fn nothing_is_sent_without_a_network_or_key() {
        let _g = store::test_home();
        let v: Value = serde_json::from_str(&call("approve", r#"{"pending_id":"x"}"#, "host")).unwrap();
        assert_eq!(v["ok"], json!(false));
        let v: Value = serde_json::from_str(&call("prepare_claim", r#"{"schedule":"x"}"#, "host")).unwrap();
        assert_eq!(v["ok"], json!(false));
        let v: Value = serde_json::from_str(&call("configure", r#"{"rpc_url":"http://example.com","program":"x"}"#, "host")).unwrap();
        assert!(v["error"].as_str().unwrap().contains("only to this machine"));
    }
}

#[cfg(test)]
mod review_r1;
#[cfg(test)]
mod review_r1_more;
#[cfg(test)]
mod review_r1_kimi;
#[cfg(test)]
mod review_r2;
