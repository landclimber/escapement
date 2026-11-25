//! The second review's findings (Kimi on 5744dbf, R1) not already in [`crate::review_r1`], through [`call`] against the
//! stand-in sequencer.

use escapement_core::{Asset, ScheduleAccount, ScheduleKind, VestingActorState};
use lee_core::account::AccountId;
use serde_json::{json, Value};

use super::*;
use crate::review_r1::{claim_req, fixture};

const VIEW_C: &str = "module:escapement_ui";

fn j(s: String) -> Value {
    serde_json::from_str(&s).expect("a JSON reply")
}

// Kimi M1: a tracked token schedule was claimed and cancelled as if its base units were LEZ.
#[test]
fn kimi_m1_token_schedules_are_not_claimed_or_cancelled_as_lez() {
    let f = fixture();
    let me = AccountId::new(lez::id_from_string(&f.me).unwrap());
    let token = [6u8; 32];
    let sch = ScheduleAccount {
        version: 1,
        asset_program_id: AccountId::new([3u8; 32]),
        creator: me,
        beneficiary: me,
        asset: Asset::Token { definition: AccountId::new([4u8; 32]) },
        escrow_seed: [0u8; 32],
        escrow_account: AccountId::new([9u8; 32]),
        refund_holding: me,
        total_amount: 1_000,
        claimed_amount: 0,
        kind: ScheduleKind::Linear { start_ts: 1_795_599_000_000, end_ts: 1_795_601_000_000 },
        cancelable: true,
        transferable: false,
        cancel_authority: None,
        milestone_authority: None,
        cancelled: None,
    };
    f.net.chain.lock().unwrap().states.insert(
        (lez::id_string(&token), lez::id_string(&[7u8; 32])),
        VestingActorState::Schedule(Box::new(sch)).encode(),
    );
    let t = lez::id_string(&token);
    let rows = j(call("schedules", &json!({ "ids": [t] }).to_string(), "host"));
    let row = rows["positions"].as_array().unwrap().iter().find(|r| r["schedule"] == json!(t)).expect("the token row");
    assert_eq!(row["native"], json!(false));
    assert!(row["claimable_now"]["unit"].as_str().unwrap().contains("token"), "{row}");
    assert_ne!(row["total"]["display"], json!("0.000001"), "token base units are not LEZ");
    for m in ["prepare_claim", "prepare_cancel"] {
        let r = j(call(m, &json!({ "schedule": t }).to_string(), "host"));
        assert!(r["ok"] == json!(false) && r["error"].as_str().unwrap().contains("token"), "{m}: {r}");
    }
    assert_eq!(f.net.sent(), 0);
}

// Kimi H1/M3: reject, like approve, belongs to the caller that prepared.
#[test]
fn kimi_reject_only_by_the_preparer() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), VIEW_C));
    let id = p["pending_id"].as_str().unwrap().to_string();
    let r = j(call("reject", &json!({ "pending_id": id }).to_string(), "host"));
    assert_eq!(r["ok"], json!(false), "another caller's reject must be refused: {r}");
    let r = j(call("reject", &json!({}).to_string(), "host"));
    assert_eq!(r["ok"], json!(false), "and without an id too: {r}");
    let r = j(call("reject", &json!({ "pending_id": id }).to_string(), VIEW_C));
    assert_eq!(r["rejected"], json!(id), "{r}");
}

// Kimi M6: an answer lost after the send looked like a refusal and lost the transaction's hash.
#[test]
fn kimi_m6_a_lost_answer_after_the_send_is_unknown_not_refused() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), "host"));
    let id = p["pending_id"].as_str().unwrap().to_string();
    f.net.chain.lock().unwrap().lose_send_answer = true;
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), "host"));
    assert_eq!(a["ok"], json!(true), "{a}");
    assert_eq!(a["state"], json!("unknown"), "{a}");
    let hash = a["tx_hash"].as_str().unwrap().to_string();
    assert_eq!(f.net.chain.lock().unwrap().sent, vec![hash.clone()], "the hash given is the one the sequencer took");
    let t = j(call("tx_status", &json!({ "tx_hash": hash }).to_string(), "host"));
    assert_eq!(t["state"], json!("in_block"), "tx_status finds it: {t}");
}

// Kimi M6: a schedule that cannot be read back after the block is an unread outcome, not a refusal.
#[test]
fn kimi_m6_an_unreadable_outcome_is_not_a_refusal() {
    let f = fixture();
    let p = j(call("prepare_claim", &claim_req(&f), "host"));
    let id = p["pending_id"].as_str().unwrap().to_string();
    f.net.chain.lock().unwrap().drop_on_send = vec![(f.schedule.clone(), lez::id_string(&[7u8; 32]))];
    let a = j(call("approve", &json!({ "pending_id": id }).to_string(), "host"));
    assert_eq!(a["ok"], json!(true), "{a}");
    assert_eq!(a["state"], json!("in_block"), "{a}");
    assert_eq!(a["outcome"]["applied"], Value::Null, "{a}");
    assert!(a["tx_hash"].as_str().is_some());
}

// Kimi L2: a flag of the wrong type was read as its default (read_only false, cancelable true).
#[test]
fn kimi_l2_flags_must_be_booleans() {
    let f = fixture();
    let c = j(call("configure", &json!({ "rpc_url": f.net.url, "program": lez::id_string(&[7u8; 32]), "read_only": "yes" }).to_string(), "host"));
    assert_eq!(c["ok"], json!(false), "{c}");
    let p = j(call("prepare_create", &json!({ "beneficiary": f.me, "total": "1000", "kind": "linear", "start_ms": 1_795_600_000_000u64,
                                              "end_ms": 1_795_700_000_000u64, "cancelable": "no" }).to_string(), "host"));
    assert_eq!(p["ok"], json!(false), "{p}");
    assert!(p["error"].as_str().unwrap().contains("cancelable"), "{p}");
}
