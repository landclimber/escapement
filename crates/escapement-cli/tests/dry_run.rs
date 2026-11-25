//! The CLI's dry runs need no sequencer (nothing listens at `LEZ_RPC` here): they build the call, print it and send
//! nothing. The printed message is decoded with the program's own types, so these tests check what would be signed.

use std::process::Command;

use escapement_core::{Message, ScheduleKind};

const PROGRAM: &str = "Be6eH1Ps2cr7zSmuV2XfwZDkF14naGcEG6h71ViszSXW";
const A: &str = "9LX1fRDTUMsSx6PFJFgrnNRXoNtBw5oV6HukWvjDLs1o";
const B: &str = "FehjGQw4YYhkBPVCA8WY6Xd9YEsSXaKbvekUZqrzcgBN";
const BATCH_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// (exit success, the printed result, stderr).
fn run(args: &[&str]) -> (bool, serde_json::Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_escapement"))
        .args(args)
        .env("LEZ_RPC", "http://127.0.0.1:1")
        .env("ESCAPEMENT_PROGRAM", PROGRAM)
        .env_remove("ESCAPEMENT_TOKEN_PROGRAM")
        .env_remove("ESCAPEMENT_KEY")
        .output()
        .expect("run escapement");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = stdout
        .lines()
        .last()
        .and_then(|l| serde_json::from_str(l).ok())
        .unwrap_or(serde_json::Value::Null);
    (
        out.status.success(),
        v["result"].clone(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn message(result: &serde_json::Value) -> Message {
    let bytes = hex::decode(result["call"]["message_hex"].as_str().expect("message_hex")).unwrap();
    borsh::from_slice(&bytes).expect("an Escapement message")
}

#[test]
fn a_cliff_batch_signs_each_recipients_own_total_and_cliff() {
    let r = [A, ":60000000:20000000,", B, ":40000000:10000000"].concat();
    let (ok, out, err) = run(&[
        "batch",
        "--recipients",
        &r,
        "--cliff",
        "1000,2000,9000",
        "--batch-id",
        BATCH_ID,
        "--dry-run",
    ]);
    assert!(ok, "{err}");
    let Message::BatchCreate(p) = message(&out) else {
        panic!("not a BatchCreate")
    };
    let got: Vec<(String, u128, ScheduleKind)> = p
        .items
        .iter()
        .map(|i| (i.beneficiary.to_string(), i.total_amount, i.kind.clone()))
        .collect();
    let cliff = |c| ScheduleKind::CliffLinear {
        start_ts: 1000,
        cliff_ts: 2000,
        end_ts: 9000,
        cliff_amount: c,
    };
    assert_eq!(
        got,
        vec![
            (A.into(), 60_000_000, cliff(20_000_000)),
            (B.into(), 40_000_000, cliff(10_000_000))
        ]
    );
    assert_eq!(out["items"][1]["cliff_amount"], "10000000");
    // The same batch id gives the same schedule accounts.
    let (_, again, _) = run(&[
        "batch",
        "--recipients",
        &r,
        "--cliff",
        "1000,2000,9000",
        "--batch-id",
        BATCH_ID,
        "--dry-run",
    ]);
    assert_eq!(out["schedules"], again["schedules"]);
    assert_eq!(out["schedules"].as_array().unwrap().len(), 2);
}

#[test]
fn a_linear_batch_signs_linear_terms() {
    let r = [A, ":5,", B, ":7"].concat();
    let (ok, out, err) = run(&[
        "batch",
        "--recipients",
        &r,
        "--linear",
        "1000,9000",
        "--dry-run",
    ]);
    assert!(ok, "{err}");
    let Message::BatchCreate(p) = message(&out) else {
        panic!("not a BatchCreate")
    };
    assert!(p.items.iter().all(|i| i.kind
        == ScheduleKind::Linear {
            start_ts: 1000,
            end_ts: 9000
        }));
    assert_eq!(
        p.items.iter().map(|i| i.total_amount).collect::<Vec<_>>(),
        vec![5, 7]
    );
}

#[test]
fn ambiguous_or_malformed_batches_are_refused_before_anything_is_built() {
    let two = [A, ":5:1,", B, ":7:1"].concat();
    for (args, why) in [
        (
            vec!["--recipients", &two, "--linear", "1,9", "--cliff", "1,2,9"],
            "exactly one of",
        ),
        (
            vec!["--recipients", &two, "--cliff", "1,2,9,1"],
            "each recipient's cliff amount",
        ),
        (
            vec![
                "--recipients",
                &[A, ":5,", A, ":7"].concat(),
                "--linear",
                "1,9",
            ],
            "named twice",
        ),
        (
            vec!["--recipients", &[A, ":5,"].concat(), "--linear", "1,9"],
            "stray comma",
        ),
        (
            vec!["--recipients", &[A, ":0"].concat(), "--linear", "1,9"],
            "zero total",
        ),
    ] {
        let mut full = vec!["batch"];
        full.extend(args);
        full.push("--dry-run");
        let (ok, _, err) = run(&full);
        assert!(!ok && err.contains(why), "{full:?}: {err}");
    }
    let dup = [A, ":5,", A, ":7"].concat();
    assert!(
        run(&[
            "batch",
            "--recipients",
            &dup,
            "--linear",
            "1,9",
            "--allow-duplicates",
            "--dry-run"
        ])
        .0
    );
}

#[test]
fn create_takes_exactly_one_shape_and_a_u128_cliff_amount() {
    let (ok, _, err) = run(&[
        "create",
        "--beneficiary",
        A,
        "--total",
        "100",
        "--linear",
        "1,9",
        "--cliff",
        "1,2,9,50",
        "--dry-run",
    ]);
    assert!(!ok && err.contains("exactly one of"), "{err}");
    let big = "36893488147419103232"; // 2^65, above u64::MAX
    let total = "73786976294838206464"; // 2^66
    let (ok, out, err) = run(&[
        "create",
        "--beneficiary",
        A,
        "--total",
        total,
        "--cliff",
        &format!("1,2,9,{big}"),
        "--dry-run",
    ]);
    assert!(ok, "{err}");
    let Message::CreateSchedule(p) = message(&out) else {
        panic!("not a CreateSchedule")
    };
    assert_eq!(
        p.kind,
        ScheduleKind::CliffLinear {
            start_ts: 1,
            cliff_ts: 2,
            end_ts: 9,
            cliff_amount: 1u128 << 65
        }
    );
}
