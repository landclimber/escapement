//! Review R1's nit, tested beside its findings: `approve` checked the nonce only after signing.

use serde_json::{json, Value};

use super::*;
use crate::review_r1::{claim_req, fixture};

#[test]
fn nit_the_nonce_is_checked_before_anything_is_signed() {
    let f = fixture();
    let p: Value = serde_json::from_str(&call("prepare_claim", &claim_req(&f), "host")).unwrap();
    let id = p["pending_id"].as_str().unwrap().to_string();
    f.net.chain.lock().unwrap().nonces.insert(f.me.clone(), 1);
    let before = lez::SIGNATURES.load(std::sync::atomic::Ordering::SeqCst);
    let a: Value = serde_json::from_str(&call("approve", &json!({ "pending_id": id }).to_string(), "host")).unwrap();
    assert_eq!(a["ok"], json!(false), "{a}");
    assert!(a["error"].as_str().unwrap().contains("nothing was signed"), "{a}");
    assert_eq!(lez::SIGNATURES.load(std::sync::atomic::Ordering::SeqCst), before, "no signature may be made");
    assert_eq!(f.net.sent(), 0);
}
