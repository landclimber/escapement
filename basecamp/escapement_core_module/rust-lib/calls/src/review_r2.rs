//! Review round 2 (of 04b45c8): a sequencer's refusal of the transaction is not a lost answer (L1), and `tx_status`
//! reports an unreadable read-back as an unread outcome (L3). Through [`call`], against the stand-in sequencer.

use serde_json::{json, Value};

use super::*;
use crate::review_r1::{claim_req, fixture};

fn j(s: String) -> Value {
    serde_json::from_str(&s).expect("a JSON reply")
}

// R2 L1: a JSON-RPC error on sendTransaction was reported as "the answer did not arrive".
#[test]
fn r2_l1_a_refusal_by_the_sequencer_is_not_a_lost_answer() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), "host"));
    let id = p["pending_id"].as_str().unwrap().to_string();
    f.net.chain.lock().unwrap().refuse_send = Some("nonce too low".into());
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), "host"));
    assert_eq!(a["ok"], json!(true), "{a}");
    assert_eq!(a["state"], json!("refused_by_sequencer"), "{a}");
    let w = a["warning"].as_str().unwrap();
    assert!(w.contains("nonce too low") && w.contains("refused") && !w.contains("did not arrive"), "{w}");
    assert!(a["tx_hash"].as_str().is_some_and(|h| h.len() == 64), "{a}");
    assert_eq!(f.net.sent(), 0);
}

// R2 L3: tx_status turned an unreadable read-back into a failed call.
#[test]
fn r2_l3_tx_status_reports_an_unread_outcome() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), "host"));
    let id = p["pending_id"].as_str().unwrap().to_string();
    f.net.chain.lock().unwrap().lose_send_answer = true;
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), "host"));
    let hash = a["tx_hash"].as_str().unwrap().to_string();
    // The schedule is gone when tx_status reads it back.
    f.net.chain.lock().unwrap().states.remove(&(f.schedule.clone(), lez::id_string(&[7u8; 32])));
    let t = j(call("tx_status", &json!({ "tx_hash": hash }).to_string(), "host"));
    assert_eq!(t["ok"], json!(true), "{t}");
    assert_eq!(t["state"], json!("in_block"), "{t}");
    assert_eq!(t["outcome"]["applied"], Value::Null, "{t}");
}

// R2 (Kimi): after a create, a read-back that failed (transport) was reported as the program refusing it.
#[test]
fn r2_kimi_a_failed_create_read_back_is_not_a_revert() {
    let f = fixture();
    let p = j(call("prepare_create", &json!({ "beneficiary": f.me, "total": "1000", "kind": "linear",
                                              "start_ms": 1_795_600_000_000u64, "end_ms": 1_795_700_000_000u64 }).to_string(), "host"));
    assert_eq!(p["ok"], json!(true), "{p}");
    let id = p["pending_id"].as_str().unwrap().to_string();
    f.net.chain.lock().unwrap().fail_reads_after_send = true;
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), "host"));
    assert_eq!(a["ok"], json!(true), "{a}");
    assert_eq!(a["state"], json!("in_block"), "{a}");
    assert_eq!(a["outcome"]["applied"], Value::Null, "a failed read is not a revert: {a}");
    assert!(!a["outcome"]["detail"].as_str().unwrap_or("").contains("refused it"), "{a}");
}

fn unsettled_hashes() -> Vec<String> {
    let st = j(call("status", "{}", "host"));
    st["unsettled"].as_array().unwrap().iter().map(|x| x["tx_hash"].as_str().unwrap().to_string()).collect()
}

// R2 (Kimi M1): a signed transaction whose answer was lost is kept in the module's state file, so a restart or a lost
// host reply does not lose it; status lists it (hash, network; never the approval id); tx_status settles it.
#[test]
fn r2_kimi_an_unsettled_transaction_survives_a_restart_and_is_settled_by_tx_status() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), "host"));
    let id = p["pending_id"].as_str().unwrap().to_string();
    f.net.chain.lock().unwrap().lose_send_answer = true;
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), "host"));
    let hash = a["tx_hash"].as_str().unwrap().to_string();
    // The module restarts: its memory is gone, its state file is not.
    with(|st| {
        *st = State::default();
        Ok(())
    })
    .unwrap();
    assert_eq!(unsettled_hashes(), vec![hash.clone()], "status lists the unsettled transaction after a restart");
    assert!(!call("status", "{}", "host").contains(&id), "never the approval id");
    let t = j(call("tx_status", &json!({ "tx_hash": hash }).to_string(), "host"));
    assert_eq!(t["state"], json!("in_block"), "{t}");
    assert!(unsettled_hashes().is_empty(), "settled once seen in a block");
}

// R2 (Kimi M1): tx_status checks a transaction on the network it was sent to, not the one configured since.
#[test]
fn r2_kimi_tx_status_uses_the_network_the_transaction_went_to() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), "host"));
    let id = p["pending_id"].as_str().unwrap().to_string();
    f.net.chain.lock().unwrap().lose_send_answer = true;
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), "host"));
    let hash = a["tx_hash"].as_str().unwrap().to_string();
    let path = std::path::PathBuf::from(std::env::var("ESCAPEMENT_MODULE_HOME").unwrap()).join("state.json");
    let mut state: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    state["config"]["program"] = json!(lez::id_string(&[8u8; 32]));
    std::fs::write(&path, state.to_string()).unwrap();
    let t = j(call("tx_status", &json!({ "tx_hash": hash }).to_string(), "host"));
    assert_eq!(t["network"]["program"], json!(lez::id_string(&[7u8; 32])), "{t}");
    assert_eq!(t["outcome"]["applied"], json!(false), "read on the recorded program (the stand-in did not apply it): {t}");
}

// R2 (Kimi M1): the person can dismiss an unsettled transaction; it is then no longer listed.
#[test]
fn r2_kimi_an_unsettled_transaction_can_be_dismissed() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), "host"));
    let id = p["pending_id"].as_str().unwrap().to_string();
    f.net.chain.lock().unwrap().refuse_send = Some("fee too low".into());
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), "host"));
    let hash = a["tx_hash"].as_str().unwrap().to_string();
    assert_eq!(unsettled_hashes(), vec![hash.clone()]);
    let d = j(call("tx_status", &json!({ "tx_hash": hash, "dismiss": true }).to_string(), "host"));
    assert_eq!(d["dismissed"], json!(true), "{d}");
    assert!(unsettled_hashes().is_empty());
}
