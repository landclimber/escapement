//! Every Escapement operation as a [`Call`]: the root actor the signer addresses, every actor the
//! transaction must declare on LEZ v0.4 (undeclared actors are refused), and the message bytes
//! (`lez_authority::Wire::Program(Message)`). Both assets, and `AsPda` for programs acting as their
//! own PDAs (multisigs, DAOs, launchpads).

use clock_core::clock_actor;
use escapement_core::{
    batch_coord_pda, batch_escrow_pda, batch_schedule_pda, config_pda, fee_vault_pda, schedule_pda,
    single_escrow_pda, Asset, BatchCreateParams, BatchRecipient, CreateScheduleParams, Message,
    PdaCall, ScheduleAccount, ScheduleKind, NATIVE_PROGRAM_ID,
};
use lee_core::{
    account::{AccountId, Actor},
    program::PdaSeed,
};
use lez_authority::Wire;

use crate::SdkError;

/// One transaction's content, before signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub root: Actor,
    pub declared: Vec<Actor>,
    pub message: Vec<u8>,
}

/// The deployed program and how assets resolve on this chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deployment {
    /// The Escapement program's id.
    pub program: AccountId,
    /// The token program pinned in the config (`None` on a native-only deployment).
    pub token_program: Option<AccountId>,
}

impl Deployment {
    /// The program that holds balances of `asset`.
    #[must_use]
    pub fn asset_program(&self, asset: Asset) -> AccountId {
        match asset {
            Asset::Native => NATIVE_PROGRAM_ID,
            Asset::Token { .. } => self.token_program.unwrap_or(NATIVE_PROGRAM_ID),
        }
    }

    fn seat(&self, account: AccountId) -> Actor {
        Actor::new(account, self.program)
    }
}

/// Encodes a program message as it travels (`Wire::Program`).
#[must_use]
pub fn encode(message: Message) -> Vec<u8> {
    borsh::to_vec(&Wire::Program(message)).expect("message encodes")
}

/// A schedule request with the RFP's defaults (F3: cancelable unless asked otherwise; refunds go
/// back to the funding account).
#[derive(Debug, Clone)]
pub struct ScheduleRequest {
    pub salt: [u8; 32],
    pub asset: Asset,
    pub creator: AccountId,
    /// Token holding that funds the schedule (`None`: the creator itself, required for native).
    pub funding_holding: Option<AccountId>,
    pub beneficiary: AccountId,
    pub total_amount: u128,
    pub kind: ScheduleKind,
    pub cancelable: bool,
    pub transferable: bool,
    pub refund_to: Option<AccountId>,
    pub cancel_authority: Option<AccountId>,
    pub milestone_authority: Option<AccountId>,
}

impl ScheduleRequest {
    /// Defaults: cancelable, non-transferable, refunds to the funding account, no delegations.
    #[must_use]
    pub fn new(
        salt: [u8; 32],
        asset: Asset,
        creator: AccountId,
        beneficiary: AccountId,
        total_amount: u128,
        kind: ScheduleKind,
    ) -> Self {
        Self {
            salt,
            asset,
            creator,
            funding_holding: None,
            beneficiary,
            total_amount,
            kind,
            cancelable: true,
            transferable: false,
            refund_to: None,
            cancel_authority: None,
            milestone_authority: None,
        }
    }

    #[must_use]
    pub fn params(&self) -> CreateScheduleParams {
        let funding = self.funding_holding.unwrap_or(self.creator);
        CreateScheduleParams {
            salt: self.salt,
            asset: self.asset,
            creator_holding: funding,
            refund_holding: self.refund_to.unwrap_or(funding),
            beneficiary: self.beneficiary,
            total_amount: self.total_amount,
            kind: self.kind.clone(),
            cancelable: self.cancelable,
            transferable: self.transferable,
            cancel_authority: self.cancel_authority,
            milestone_authority: self.milestone_authority,
            broker: None,
        }
    }
}

fn fee_vault_actors(d: &Deployment, asset: Asset, out: &mut Vec<Actor>) {
    let fv = fee_vault_pda(d.program, &asset.key());
    if asset == Asset::Native {
        out.push(d.seat(fv));
    }
    out.push(Actor::new(fv, d.asset_program(asset)));
}

/// `CreateSchedule`, signed by `params`' creator (`with_fee`: a protocol fee is configured).
#[must_use]
pub fn create_schedule(
    d: &Deployment,
    creator: AccountId,
    params: &CreateScheduleParams,
    with_fee: bool,
) -> Call {
    let sched = schedule_pda(d.program, &creator, &params.salt);
    let escrow = single_escrow_pda(d.program, &sched);
    let ap = d.asset_program(params.asset);
    let mut declared = vec![
        d.seat(creator),
        d.seat(sched),
        d.seat(config_pda(d.program)),
        Actor::new(params.creator_holding, ap),
        Actor::new(escrow, ap),
    ];
    if let Asset::Token { definition } = params.asset {
        declared.push(Actor::new(definition, ap));
        declared.push(Actor::new(params.refund_holding, ap));
    }
    if let Some(b) = &params.broker {
        declared.push(Actor::new(b.holding, ap));
    }
    if with_fee {
        fee_vault_actors(d, params.asset, &mut declared);
    }
    declared.dedup();
    Call {
        root: d.seat(creator),
        declared,
        message: encode(Message::CreateSchedule(Box::new(params.clone()))),
    }
}

/// `BatchCreate`, signed by the creator.
#[must_use]
pub fn batch_create(
    d: &Deployment,
    creator: AccountId,
    params: &BatchCreateParams,
    with_fee: bool,
) -> Call {
    let ap = d.asset_program(params.asset);
    let mut declared = vec![
        d.seat(creator),
        d.seat(batch_coord_pda(d.program, &creator, &params.batch_id)),
        d.seat(config_pda(d.program)),
        Actor::new(params.creator_holding, ap),
        Actor::new(batch_escrow_pda(d.program, &creator, &params.batch_id), ap),
    ];
    if let Asset::Token { definition } = params.asset {
        declared.push(Actor::new(definition, ap));
        declared.push(Actor::new(params.refund_holding, ap));
    }
    for i in 0..params.items.len() {
        let index = u32::try_from(i).expect("batch index fits u32");
        declared.push(d.seat(batch_schedule_pda(
            d.program,
            &creator,
            &params.batch_id,
            index,
        )));
    }
    if let Some(b) = &params.broker {
        declared.push(Actor::new(b.holding, ap));
    }
    if with_fee {
        fee_vault_actors(d, params.asset, &mut declared);
    }
    Call {
        root: d.seat(creator),
        declared,
        message: encode(Message::BatchCreate(Box::new(params.clone()))),
    }
}

/// Measured single-transaction ceilings on LEZ v0.4.0-rc3 (simulated at the 10M-cycle cap), with a
/// margin: the batch shapes in `docs/gas-and-batch.md`. A launch larger than this is split.
pub const SAFE_BATCH_CEILING: usize = 128;

/// Splits a batch into transactions of at most `ceiling` recipients; chunk `i` gets the given
/// batch id with its last two bytes replaced by `i` (so each chunk is a new batch).
///
/// # Errors
/// [`SdkError::BatchTooLarge`] if more than 65,536 chunks would be needed.
pub fn batch_create_chunked(
    params: &BatchCreateParams,
    ceiling: usize,
) -> Result<Vec<BatchCreateParams>, SdkError> {
    let ceiling = ceiling.max(1);
    let chunks: Vec<&[BatchRecipient]> = params.items.chunks(ceiling).collect();
    if chunks.len() > usize::from(u16::MAX) + 1 {
        return Err(SdkError::BatchTooLarge {
            requested: params.items.len(),
            ceiling,
        });
    }
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(i, items)| {
            let mut batch_id = params.batch_id;
            let tag = u16::try_from(i).expect("checked above").to_le_bytes();
            batch_id[30] = tag[0];
            batch_id[31] = tag[1];
            BatchCreateParams {
                batch_id,
                items: items.to_vec(),
                ..params.clone()
            }
        })
        .collect())
}

/// `ClaimPublic` by the beneficiary into a public `destination`.
#[must_use]
pub fn claim_public(
    d: &Deployment,
    schedule_id: AccountId,
    schedule: &ScheduleAccount,
    destination: AccountId,
    amount: Option<u128>,
) -> Call {
    let ap = schedule.asset_program_id;
    Call {
        root: d.seat(schedule.beneficiary),
        declared: vec![
            d.seat(schedule.beneficiary),
            d.seat(schedule_id),
            clock_actor(),
            Actor::new(schedule.escrow_account, ap),
            Actor::new(destination, ap),
        ],
        message: encode(Message::ClaimPublic {
            schedule_id,
            destination,
            amount,
        }),
    }
}

/// The public part of a one-transaction private claim (`ClaimExact`): root, public actors, and the
/// message naming the one-time alias. The private witness and the alias opening come from the
/// wallet (`PrivateDestination::opening`).
#[must_use]
pub fn claim_exact(
    d: &Deployment,
    schedule_id: AccountId,
    schedule: &ScheduleAccount,
    alias: AccountId,
    amount: u128,
    effective_ts: u64,
) -> Call {
    Call {
        root: d.seat(schedule.beneficiary),
        declared: vec![
            d.seat(schedule.beneficiary),
            d.seat(schedule_id),
            Actor::new(schedule.escrow_account, schedule.asset_program_id),
        ],
        message: encode(Message::ClaimExact {
            schedule_id,
            destination: alias,
            amount,
            effective_ts,
        }),
    }
}

/// `Cancel` by the cancel authority (the creator unless delegated).
#[must_use]
pub fn cancel(d: &Deployment, schedule_id: AccountId, schedule: &ScheduleAccount) -> Call {
    let ap = schedule.asset_program_id;
    let by = schedule.effective_cancel_authority();
    Call {
        root: d.seat(by),
        declared: vec![
            d.seat(by),
            d.seat(schedule_id),
            clock_actor(),
            Actor::new(schedule.escrow_account, ap),
            Actor::new(schedule.refund_holding, ap),
        ],
        message: encode(Message::Cancel { schedule_id }),
    }
}

/// `MakeNonCancelable` by the cancel authority.
#[must_use]
pub fn make_non_cancelable(
    d: &Deployment,
    schedule_id: AccountId,
    schedule: &ScheduleAccount,
) -> Call {
    let by = schedule.effective_cancel_authority();
    Call {
        root: d.seat(by),
        declared: vec![d.seat(by), d.seat(schedule_id)],
        message: encode(Message::MakeNonCancelable { schedule_id }),
    }
}

/// `SignalMilestone` by the milestone authority.
#[must_use]
pub fn signal_milestone(
    d: &Deployment,
    schedule_id: AccountId,
    schedule: &ScheduleAccount,
    milestone_index: u8,
) -> Call {
    let by = schedule.effective_milestone_authority();
    Call {
        root: d.seat(by),
        declared: vec![d.seat(by), d.seat(schedule_id), clock_actor()],
        message: encode(Message::SignalMilestone {
            schedule_id,
            milestone_index,
        }),
    }
}

/// `TransferBeneficiary` by the current beneficiary.
#[must_use]
pub fn transfer_beneficiary(
    d: &Deployment,
    schedule_id: AccountId,
    schedule: &ScheduleAccount,
    new_beneficiary: AccountId,
) -> Call {
    Call {
        root: d.seat(schedule.beneficiary),
        declared: vec![d.seat(schedule.beneficiary), d.seat(schedule_id)],
        message: encode(Message::TransferBeneficiary {
            schedule_id,
            new_beneficiary,
        }),
    }
}

/// `WithdrawFees` by the fee treasury.
#[must_use]
pub fn withdraw_fees(
    d: &Deployment,
    treasury: AccountId,
    asset: Asset,
    destination: AccountId,
    amount: u128,
) -> Call {
    let ap = d.asset_program(asset);
    Call {
        root: d.seat(treasury),
        declared: vec![
            d.seat(treasury),
            d.seat(config_pda(d.program)),
            Actor::new(fee_vault_pda(d.program, &asset.key()), ap),
            Actor::new(destination, ap),
        ],
        message: encode(Message::WithdrawFees {
            asset,
            destination,
            amount,
        }),
    }
}

/// The message a multisig/DAO/launchpad program sends to `(pda, program)` to act as its PDA
/// (`pda = for_public_pda(that program, seed)`); it must also grant `seed` on that delivery.
#[must_use]
pub fn as_pda(seed: PdaSeed, call: PdaCall) -> Vec<u8> {
    encode(Message::AsPda {
        seed: *seed.as_bytes(),
        call: Box::new(call),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROGRAM: AccountId = AccountId::new([0x50; 32]);
    const TOKEN: AccountId = AccountId::new([0x70; 32]);

    fn d() -> Deployment {
        Deployment {
            program: PROGRAM,
            token_program: Some(TOKEN),
        }
    }

    #[test]
    fn f3a_requests_default_to_cancelable_with_refunds_to_the_funder() {
        let r = ScheduleRequest::new(
            [1; 32],
            Asset::Native,
            AccountId::new([2; 32]),
            AccountId::new([3; 32]),
            10,
            ScheduleKind::Linear {
                start_ts: 0,
                end_ts: 10,
            },
        );
        let p = r.params();
        assert!(p.cancelable);
        assert!(!p.transferable);
        assert_eq!(p.creator_holding, AccountId::new([2; 32]));
        assert_eq!(p.refund_holding, AccountId::new([2; 32]));
    }

    #[test]
    fn create_declares_asset_specific_actors_and_encodes_the_wire() {
        let creator = AccountId::new([2; 32]);
        let mut r = ScheduleRequest::new(
            [1; 32],
            Asset::Token {
                definition: AccountId::new([9; 32]),
            },
            creator,
            AccountId::new([3; 32]),
            10,
            ScheduleKind::Linear {
                start_ts: 0,
                end_ts: 10,
            },
        );
        r.funding_holding = Some(AccountId::new([4; 32]));
        let call = create_schedule(&d(), creator, &r.params(), true);
        assert_eq!(call.root, Actor::new(creator, PROGRAM));
        assert!(call
            .declared
            .contains(&Actor::new(AccountId::new([9; 32]), TOKEN)));
        let fv = fee_vault_pda(PROGRAM, &AccountId::new([9; 32]));
        assert!(call.declared.contains(&Actor::new(fv, TOKEN)));
        let decoded: Wire<Message> = borsh::from_slice(&call.message).unwrap();
        assert!(matches!(decoded, Wire::Program(Message::CreateSchedule(_))));

        let native = create_schedule(
            &d(),
            creator,
            &ScheduleRequest {
                asset: Asset::Native,
                funding_holding: None,
                ..r
            }
            .params(),
            true,
        );
        let fv_native = fee_vault_pda(PROGRAM, &Asset::Native.key());
        assert!(native.declared.contains(&Actor::new(fv_native, PROGRAM)));
        assert!(native
            .declared
            .contains(&Actor::new(fv_native, NATIVE_PROGRAM_ID)));
    }

    #[test]
    fn chunked_batches_keep_every_recipient_once_under_new_ids() {
        let item = BatchRecipient {
            beneficiary: AccountId::new([5; 32]),
            total_amount: 1,
            kind: ScheduleKind::Linear {
                start_ts: 0,
                end_ts: 1,
            },
            cancelable: true,
            transferable: false,
            cancel_authority: None,
            milestone_authority: None,
        };
        let p = BatchCreateParams {
            batch_id: [7; 32],
            asset: Asset::Native,
            creator_holding: AccountId::new([2; 32]),
            refund_holding: AccountId::new([2; 32]),
            broker: None,
            items: vec![item; 300],
        };
        let chunks = batch_create_chunked(&p, SAFE_BATCH_CEILING).unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks.iter().map(|c| c.items.len()).sum::<usize>(), 300);
        assert!(chunks.iter().all(|c| c.items.len() <= SAFE_BATCH_CEILING));
        let ids: std::collections::BTreeSet<_> = chunks.iter().map(|c| c.batch_id).collect();
        assert_eq!(ids.len(), 3);
    }
}
