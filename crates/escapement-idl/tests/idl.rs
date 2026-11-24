//! U6: the committed SPEL IDL v2 (`idl/escapement.idl.json`) is exactly what SPEL generates from
//! `crates/escapement-core`, names every message and event, carries the program's event selectors,
//! and SPEL's IDL-driven decoder reads every message the program accepts.

use escapement_core::{
    event::{
        BeneficiaryTransferred, Cancelled, Claimed, FeeConfigUpdated, FeeWithdrawn,
        MadeNonCancelable, MilestoneSignaled, ScheduleCreated, VestingEvent,
    },
    Asset, BatchCreateParams, BatchRecipient, BrokerFee, CreateScheduleParams, Message,
    MilestoneTranche, PdaCall, ScheduleKind,
};
use lee_core::account::AccountId;
use spel_framework_core::{
    decode::decode_named,
    idl::{IdlEnumVariant, IdlTypeDef, SpelIdl},
};

const A: AccountId = AccountId::new([1; 32]);
const B: AccountId = AccountId::new([2; 32]);

fn committed() -> SpelIdl {
    let json = std::fs::read_to_string(escapement_idl::idl_path())
        .expect("idl/escapement.idl.json exists");
    SpelIdl::from_json(&json).expect("SPEL parses the committed IDL")
}

#[test]
fn u6_generated_idl_matches_committed() {
    let (_, json) = escapement_idl::generate();
    let committed = std::fs::read_to_string(escapement_idl::idl_path()).unwrap_or_default();
    assert_eq!(
        committed, json,
        "regenerate with `cargo run -p escapement-idl --bin idl -- --write`"
    );
}

fn kinds() -> Vec<ScheduleKind> {
    vec![
        ScheduleKind::CliffLinear {
            start_ts: 1,
            cliff_ts: 2,
            end_ts: u64::MAX,
            cliff_amount: 7,
        },
        ScheduleKind::Linear {
            start_ts: 0,
            end_ts: 9,
        },
        ScheduleKind::Milestone {
            tranches: vec![
                MilestoneTranche {
                    amount: 1,
                    unlocked: true,
                    unlocked_at_ms: Some(3),
                },
                MilestoneTranche {
                    amount: u128::MAX - 1,
                    unlocked: false,
                    unlocked_at_ms: None,
                },
            ],
        },
    ]
}

fn messages() -> Vec<Message> {
    let mut out = vec![Message::Configure {
        token_program_id: Some(A),
        fee_bps: 100,
        fee_treasury: Some(B),
    }];
    for asset in [Asset::Native, Asset::Token { definition: B }] {
        out.push(Message::WithdrawFees {
            asset,
            destination: A,
            amount: 5,
        });
        for kind in kinds() {
            let params = CreateScheduleParams {
                salt: [7; 32],
                asset,
                creator_holding: A,
                refund_holding: B,
                beneficiary: A,
                total_amount: u128::MAX,
                kind: kind.clone(),
                cancelable: true,
                transferable: false,
                cancel_authority: Some(B),
                milestone_authority: None,
                broker: Some(BrokerFee {
                    holding: B,
                    bps: 500,
                }),
            };
            out.push(Message::CreateSchedule(Box::new(params.clone())));
            out.push(Message::AsPda {
                seed: [9; 32],
                call: Box::new(PdaCall::CreateSchedule(Box::new(params))),
            });
        }
        out.push(Message::BatchCreate(Box::new(BatchCreateParams {
            batch_id: [8; 32],
            asset,
            creator_holding: A,
            refund_holding: A,
            broker: None,
            items: kinds()
                .into_iter()
                .map(|kind| BatchRecipient {
                    beneficiary: B,
                    total_amount: 5,
                    kind,
                    cancelable: false,
                    transferable: true,
                    cancel_authority: None,
                    milestone_authority: Some(A),
                })
                .collect(),
        })));
    }
    out.extend([
        Message::ClaimPublic {
            schedule_id: A,
            destination: B,
            amount: Some(1),
        },
        Message::ClaimPublic {
            schedule_id: A,
            destination: B,
            amount: None,
        },
        Message::ClaimExact {
            schedule_id: A,
            destination: B,
            amount: 3,
            effective_ts: 4,
        },
        Message::Cancel { schedule_id: A },
        Message::MakeNonCancelable { schedule_id: A },
        Message::SignalMilestone {
            schedule_id: A,
            milestone_index: 63,
        },
        Message::TransferBeneficiary {
            schedule_id: A,
            new_beneficiary: B,
        },
        Message::ReadState,
        Message::AsPda {
            seed: [9; 32],
            call: Box::new(PdaCall::Cancel { schedule_id: A }),
        },
    ]);
    out
}

/// The variant name from `Debug`: up to the first space, brace or parenthesis.
fn variant_name<T: std::fmt::Debug>(value: &T) -> String {
    let debug = format!("{value:?}");
    debug.split([' ', '{', '(']).next().unwrap().to_owned()
}

#[test]
fn u6_idl_covers_all_messages_states_events_and_round_trips() {
    let idl = committed();
    assert_eq!(idl.version, "2");
    assert_eq!(idl.name, "escapement");
    let names: Vec<&str> = idl.messages.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "Configure",
            "WithdrawFees",
            "CreateSchedule",
            "BatchCreate",
            "ClaimPublic",
            "ClaimExact",
            "Cancel",
            "MakeNonCancelable",
            "SignalMilestone",
            "TransferBeneficiary",
            "ReadState",
            "AsPda",
        ]
    );
    for (index, message) in idl.messages.iter().enumerate() {
        assert_eq!(
            usize::from(message.tag),
            index,
            "tags are the variant order"
        );
    }

    // Events: all eight, each with the program's own 8-byte selector.
    let expected: [(&str, [u8; 8]); 8] = [
        (ScheduleCreated::NAME, ScheduleCreated::SELECTOR),
        (Claimed::NAME, Claimed::SELECTOR),
        (Cancelled::NAME, Cancelled::SELECTOR),
        (MilestoneSignaled::NAME, MilestoneSignaled::SELECTOR),
        (
            BeneficiaryTransferred::NAME,
            BeneficiaryTransferred::SELECTOR,
        ),
        (MadeNonCancelable::NAME, MadeNonCancelable::SELECTOR),
        (FeeConfigUpdated::NAME, FeeConfigUpdated::SELECTOR),
        (FeeWithdrawn::NAME, FeeWithdrawn::SELECTOR),
    ];
    let idl_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(escapement_idl::idl_path()).unwrap())
            .unwrap();
    let events = idl_json["events"].as_array().expect("the IDL lists events");
    for (name, selector) in expected {
        let event = events
            .iter()
            .find(|e| e["name"] == name)
            .unwrap_or_else(|| panic!("event {name} missing from the IDL"));
        let text = event.to_string();
        let hex: String = selector.iter().map(|b| format!("{b:02x}")).collect();
        let list = format!("{:?}", selector.to_vec()).replace(' ', "");
        assert!(
            text.contains(&hex) || text.replace(' ', "").contains(&list),
            "event {name}: selector {hex} not in the IDL entry {text}"
        );
    }
    for state in ["VestingActorState", "ScheduleAccount", "PendingOp"] {
        assert!(
            idl.types.iter().any(|t| t.name == state),
            "type {state} missing from the IDL"
        );
    }

    // Every message decodes through SPEL's IDL-driven decoder to the same variant.
    let mut with_messages = idl.clone();
    with_messages.types.push(IdlTypeDef {
        name: "MessageEnvelope".to_owned(),
        kind: "enum".to_owned(),
        fields: vec![],
        variants: idl
            .messages
            .iter()
            .map(|m| IdlEnumVariant {
                name: m.name.clone(),
                fields: m.fields.clone(),
            })
            .collect(),
    });
    for message in messages() {
        let bytes = borsh::to_vec(&message).unwrap();
        let value = decode_named(&bytes, "MessageEnvelope", &with_messages)
            .unwrap_or_else(|e| panic!("{message:?} does not decode through the IDL: {e}"));
        let name = variant_name(&message);
        let decoded = value
            .as_str()
            .map(str::to_owned)
            .or_else(|| value.as_object().and_then(|o| o.keys().next().cloned()));
        assert_eq!(decoded.as_deref(), Some(name.as_str()), "{value}");
    }
}
