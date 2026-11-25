//! The first review's findings (spike review of 5744dbf, R1), each as a test through [`call`], the way Logos Core
//! calls the module: against a stand-in sequencer ([`crate::testnet`]) that records what is sent to it.

use std::sync::MutexGuard;

use escapement_core::{config_pda, Asset, Config, ScheduleAccount, ScheduleKind, VestingActorState, NATIVE_PROGRAM_ID};
use lee_core::account::AccountId;
use serde_json::{json, Value};

use super::*;
use crate::testnet::Testnet;

const VIEW_C: &str = "module:escapement_ui";

fn j(s: String) -> Value {
    serde_json::from_str(&s).expect("a JSON reply")
}

fn ok(v: &Value) -> bool {
    v["ok"] == json!(true)
}

pub(crate) struct Fixture {
    pub net: Testnet,
    pub schedule: String,
    pub me: String,
    _g: MutexGuard<'static, ()>,
}

/// A configured module (as the host) on a stand-in sequencer, its key imported, and one linear schedule of 90 LEZ
/// whose creator and beneficiary are the key's account (so it can be claimed and cancelled with the same key).
pub(crate) fn fixture() -> Fixture {
    let g = store::test_home();
    with(|st| {
        *st = State::default();
        Ok(())
    })
    .unwrap();
    let net = Testnet::start();
    let program = [7u8; 32];
    let home = std::path::PathBuf::from(std::env::var("ESCAPEMENT_MODULE_HOME").unwrap());
    std::fs::create_dir_all(&home).unwrap();
    let key_path = home.join("test.key");
    std::fs::write(&key_path, "01".repeat(32)).unwrap();
    let me = lez::Key::from_text(&"01".repeat(32)).unwrap().id;
    let now: u64 = 1_795_600_000_000;
    let sid = [5u8; 32];
    let sch = ScheduleAccount {
        version: 1,
        asset_program_id: NATIVE_PROGRAM_ID,
        creator: AccountId::new(me),
        beneficiary: AccountId::new(me),
        asset: Asset::Native,
        escrow_seed: [0u8; 32],
        escrow_account: AccountId::new([9u8; 32]),
        refund_holding: AccountId::new(me),
        total_amount: 90_000_000_000,
        claimed_amount: 0,
        vested_high_water: 0,
        kind: ScheduleKind::Linear { start_ts: now - 600_000, end_ts: now + 600_000 },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        cancelled: None,
    };
    {
        let mut ch = net.chain.lock().unwrap();
        let b = lez::id_string;
        let clock = clock_core::clock_actor();
        ch.states.insert(
            (b(clock.account_id.value()), b(clock.program_account_id.value())),
            borsh::to_vec(&clock_core::ClockAccountData { block_id: 7, timestamp: now }).unwrap(),
        );
        ch.states.insert((b(config_pda(AccountId::new(program)).value()), b(&program)), borsh::to_vec(&Config::default()).unwrap());
        ch.states.insert((b(&sid), b(&program)), VestingActorState::Schedule(Box::new(sch)).encode());
        ch.balances.insert(b(&me), 100_000_000_000);
    }
    let c = j(call("configure", &json!({"rpc_url": net.url, "program": lez::id_string(&program)}).to_string(), "host"));
    assert!(ok(&c), "configure: {c}");
    let k = j(call("key", &json!({"action": "import", "path": key_path.display().to_string()}).to_string(), "host"));
    assert!(ok(&k), "key: {k}");
    Fixture { net, schedule: lez::id_string(&sid), me: lez::id_string(&me), _g: g }
}

pub(crate) fn claim_req(f: &Fixture) -> String {
    json!({ "schedule": f.schedule, "amount": "250000000" }).to_string()
}

// H1: `approve` let an `unknown` caller through; any caller could prepare. Only the view and the host prepare, and only
// the caller that prepared approves.
#[test]
fn h1_only_the_preparer_among_the_view_and_the_host_approves() {
    let f = fixture();
    for c in ["unknown", "module:other", "module:escapement_ui_x", ""] {
        let r = j(call("prepare_claim", &claim_req(&f), c));
        assert!(!ok(&r) && r["error"].as_str().unwrap().contains("may not"), "prepare as {c:?}: {r}");
    }
    let p = j(call("prepare_claim", &claim_req(&f), VIEW_C));
    assert!(ok(&p), "prepare as the view: {p}");
    let id = p["pending_id"].as_str().unwrap().to_string();
    for c in ["unknown", "module:other", "host"] {
        let r = j(call("approve", &json!({ "pending_id": id }).to_string(), c));
        assert!(!ok(&r), "approve as {c:?} must be refused: {r}");
    }
    assert_eq!(f.net.sent(), 0, "nothing may be sent before the view approves");
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), VIEW_C));
    assert!(ok(&a), "approve as the view: {a}");
    assert_eq!(a["approved_by"], json!(VIEW_C));
    assert_eq!(f.net.sent(), 1);
}

// H1: `status` handed the pending id to every caller.
#[test]
fn h1_status_does_not_reveal_the_pending_id() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), VIEW_C));
    let id = p["pending_id"].as_str().unwrap().to_string();
    let st = call("status", "{}", "host");
    assert!(!st.contains(&id), "status must not carry the pending id: {st}");
    assert_eq!(j(st)["pending"]["op"], json!("claim"));
}

// M1: any caller could set decimals and the label, so a prompt could misstate amounts by powers of ten.
#[test]
fn m1_units_are_fixed_and_prompts_show_base_units() {
    let f = fixture();
    for bad in [json!({"decimals": 12}), json!({"decimals": 6}), json!({"asset_label": "LEZ<font color=\"white\">"})] {
        let mut req = json!({ "rpc_url": f.net.url, "program": lez::id_string(&[7u8; 32]) });
        for (k, v) in bad.as_object().unwrap() {
            req[k] = v.clone();
        }
        let r = j(call("configure", &req.to_string(), "host"));
        assert!(!ok(&r) && r["error"].as_str().unwrap().contains("fixed"), "configure {bad}: {r}");
    }
    let p = j(call("prepare_claim", &claim_req(&f), "host"));
    assert!(ok(&p), "{p}");
    assert_eq!(p["decimals"], json!(9));
    assert_eq!(p["unit"], json!("LEZ"));
    assert!(p["title"].as_str().unwrap().contains("0.25 LEZ (250000000 base units)"), "{}", p["title"]);
    let claim_row = p["rows"].as_array().unwrap().iter().find(|r| r[0] == json!("Claim")).unwrap();
    assert!(claim_row[1].as_str().unwrap().contains("(250000000 base units)"), "{claim_row}");
}

// M3: every method but approve was open to every caller (configure, key import of any path, reject, read_only off).
#[test]
fn m3_other_callers_reach_only_version() {
    let f = fixture();
    let methods = [
        "configure", "status", "key", "schedules", "track", "prepare_claim", "prepare_create", "prepare_cancel",
        "approve", "reject", "tx_status",
    ];
    for caller in ["module:other", "unknown"] {
        for m in methods {
            let r = j(call(m, &json!({ "action": "import", "path": "/etc/hostname", "rpc_url": f.net.url, "program": f.schedule }).to_string(), caller));
            assert!(!ok(&r) && r["error"].as_str().unwrap().contains("may not call"), "{m} as {caller}: {r}");
        }
        assert!(ok(&j(call("version", "", caller))), "version stays open");
    }
    assert_eq!(f.net.sent(), 0);
}

// L2: a prepared transaction was not tied to the network its prompt showed: another process sharing the module's home
// could switch the program between the prompt and the signature.
#[test]
fn l2_a_prepared_transaction_stays_on_its_network() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), "host"));
    let id = p["pending_id"].as_str().unwrap().to_string();
    let path = std::path::PathBuf::from(std::env::var("ESCAPEMENT_MODULE_HOME").unwrap()).join("state.json");
    let mut state: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    state["config"]["program"] = json!(lez::id_string(&[8u8; 32]));
    std::fs::write(&path, state.to_string()).unwrap();
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), "host"));
    assert!(!ok(&a), "approve after the network changed must be refused: {a}");
    assert_eq!(f.net.sent(), 0);
}
