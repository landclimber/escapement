//! Escapement — Privacy-Preserving Token Vesting Program for LEZ v0.4.
//!
//! Uses LEZ v0.4's actor-message execution model (`actor_entrypoint!(raw handle_message)`),
//! `lez-admin-authority` v0.2.0 for bounded creation-fee governance, `clock_core` for live
//! public time (`ClaimPublic`, `Cancel`, `SignalMilestone`), and `Response::timestamp_window`
//! for expiry-free private claims (`ClaimExact`).

use clock_core::{clock_actor, Message as ClockMessage, Reply as ClockReply};
use escapement_core::{
    batch_coord_pda, batch_escrow_pda, batch_escrow_seed, batch_schedule_pda, config_pda,
    event::{
        BeneficiaryTransferred, Cancelled, Claimed, FeeConfigUpdated, MadeNonCancelable,
        MilestoneSignaled, ScheduleCreated, VestingEvent as _,
    },
    math::{
        claimable_at, compute_fee_ceil, next_unlock_after, split_on_cancel,
        validate_schedule_params,
    },
    schedule_pda, single_escrow_pda, single_escrow_seed, BatchCreateParams, CancellationRecord,
    Config, CreateScheduleParams, Internal, Message, PendingOp, ScheduleAccount, ScheduleKind,
    VestingActorState, VestingError, CONFIG_SEED, MAX_BROKER_FEE_BPS, MAX_PROTOCOL_FEE_BPS,
    ZERO_ACCOUNT_ID,
};
use lee_core::{
    account::{AccountId, Actor},
    program::{PdaSeed, ReceiveInput, Response, StateReply, SyncMessage},
};
use lez_admin_authority::{Admin, InitGate};
use lez_authority::{Wire, LIBRARY_TAG};
use token_core::{Message as TokenMessage, TokenState};

/// Raw guest entrypoint: dispatches clock replies, pending `StateReply` continuations,
/// authenticated `Internal` actor hops, and `lez-admin-authority`-guarded public `Message`s.
pub fn handle_message(input: &ReceiveInput) -> Response {
    let own_program = input.receiver.program_account_id;
    let cfg_id = config_pda(own_program);

    // 1. Synchronous reply from LEZ's system clock actor.
    if input.from == Some(clock_actor()) {
        assert_ne!(
            input.receiver.account_id, cfg_id,
            "clock reply cannot target config account"
        );
        let Some(VestingActorState::Pending(pending)) = VestingActorState::decode(&input.pre_state)
        else {
            panic!("unexpected clock reply with no pending operation");
        };
        let reply = ClockReply::from_message(&input.message);
        return handle_clock_reply(input, *pending, reply);
    }

    // 2. Pending `StateReply` continuation on a non-config actor (reentrancy-locked).
    if input.receiver.account_id != cfg_id {
        if let Some(VestingActorState::Pending(pending)) =
            VestingActorState::decode(&input.pre_state)
        {
            return handle_state_reply(input, *pending);
        }
    }

    // 3. Authenticated internal message from another actor of this same program
    //    (excluding lez-authority's reserved LIBRARY_TAG=255 wire messages).
    let is_library_wire = input.message.first().copied() == Some(LIBRARY_TAG);
    if input.from_own_program() && !is_library_wire {
        let from = input.from.expect("internal message always has a sender");
        let internal: Internal =
            borsh::from_slice(&input.message).expect("internal vesting message must decode");
        return handle_internal(input, from, internal);
    }

    // 4. Public / library message guarded by `lez-admin-authority` v0.2.0.
    let wire: Wire<Message> =
        borsh::from_slice(&input.message).expect("vesting wire message must decode");
    lez_admin_authority::guard::<(Admin,), Config, Message>(
        input,
        &CONFIG_SEED,
        InitGate::Deployer,
        wire,
        handle_public_message,
    )
}

fn own_actor(input: &ReceiveInput, account_id: AccountId) -> Actor {
    Actor::new(account_id, input.receiver.program_account_id)
}

fn token_actor(token_program_id: AccountId, account_id: AccountId) -> Actor {
    Actor::new(account_id, token_program_id)
}

fn token_call(
    token_program_id: AccountId,
    account_id: AccountId,
    message: &TokenMessage,
    seed: Option<PdaSeed>,
) -> SyncMessage {
    SyncMessage::new(token_actor(token_program_id, account_id), message).with_pda_seeds(seed)
}

fn require_schedule(input: &ReceiveInput) -> ScheduleAccount {
    match VestingActorState::decode(&input.pre_state) {
        Some(VestingActorState::Schedule(s)) => *s,
        _ => VestingError::NotASchedule.panic_with(),
    }
}

fn require_non_zero(id: AccountId) {
    if id == ZERO_ACCOUNT_ID {
        VestingError::ZeroAddress.panic_with();
    }
}

// ============================================================================
// Public message handlers (post `lez-admin-authority::guard`)
// ============================================================================

fn handle_public_message(input: &ReceiveInput, message: Message) -> Response {
    let own_program = input.receiver.program_account_id;
    match message {
        Message::Configure {
            token_program_id,
            fee_bps,
            fee_treasury,
        } => {
            if fee_bps > MAX_PROTOCOL_FEE_BPS {
                VestingError::FeeRateExceedsCap {
                    bps: fee_bps,
                    max_bps: MAX_PROTOCOL_FEE_BPS,
                }
                .panic_with();
            }
            if fee_bps > 0 && fee_treasury.is_none() {
                VestingError::FeeTreasuryRequired.panic_with();
            }
            if let Some(treasury) = fee_treasury {
                require_non_zero(treasury);
            }
            let mut config: Config =
                borsh::from_slice(&input.pre_state).expect("config must decode");
            match (config.token_program_id, token_program_id) {
                (None, Some(id)) => {
                    require_non_zero(id);
                    config.token_program_id = Some(id);
                }
                (Some(existing), Some(supplied)) if existing != supplied => {
                    VestingError::TokenProgramImmutable.panic_with();
                }
                (None, None) => VestingError::TokenProgramNotConfigured.panic_with(),
                _ => {}
            }
            config.fee_bps = fee_bps;
            config.fee_treasury = fee_treasury;
            let resolved_token_program = config
                .token_program_id
                .expect("token_program_id set above");
            Response::set_state(borsh::to_vec(&config).expect("config encodes")).event(
                FeeConfigUpdated {
                    token_program_id: resolved_token_program,
                    fee_bps,
                    fee_treasury,
                }
                .to_program_event(),
            )
        }
        Message::CreateSchedule(params) => {
            if !input.is_authorized {
                VestingError::Unauthorized.panic_with();
            }
            let creator = input.receiver.account_id;
            let sched_id = schedule_pda(own_program, &creator, &params.salt);
            Response::keep_state().send_sync(
                own_actor(input, sched_id),
                &Internal::CreateSingle { creator, params },
            )
        }
        Message::BatchCreate(params) => {
            if !input.is_authorized {
                VestingError::Unauthorized.panic_with();
            }
            let creator = input.receiver.account_id;
            let coord_id = batch_coord_pda(own_program, &creator, &params.batch_id);
            Response::keep_state().send_sync(
                own_actor(input, coord_id),
                &Internal::CreateBatchCoord { creator, params },
            )
        }
        Message::ClaimPublic {
            schedule_id,
            destination,
            amount,
        } => {
            if !input.is_authorized {
                VestingError::Unauthorized.panic_with();
            }
            require_non_zero(destination);
            Response::keep_state().send_sync(
                own_actor(input, schedule_id),
                &Internal::ClaimPublic {
                    destination,
                    amount,
                },
            )
        }
        Message::ClaimExact {
            schedule_id,
            destination,
            amount,
            effective_ts,
        } => {
            if !input.is_authorized {
                VestingError::Unauthorized.panic_with();
            }
            require_non_zero(destination);
            Response::keep_state().send_sync(
                own_actor(input, schedule_id),
                &Internal::ClaimExact {
                    destination,
                    amount,
                    effective_ts,
                },
            )
        }
        Message::Cancel { schedule_id } => {
            if !input.is_authorized {
                VestingError::Unauthorized.panic_with();
            }
            Response::keep_state().send_sync(own_actor(input, schedule_id), &Internal::Cancel)
        }
        Message::MakeNonCancelable { schedule_id } => {
            if !input.is_authorized {
                VestingError::Unauthorized.panic_with();
            }
            Response::keep_state()
                .send_sync(own_actor(input, schedule_id), &Internal::MakeNonCancelable)
        }
        Message::SignalMilestone {
            schedule_id,
            milestone_index,
        } => {
            if !input.is_authorized {
                VestingError::Unauthorized.panic_with();
            }
            Response::keep_state().send_sync(
                own_actor(input, schedule_id),
                &Internal::SignalMilestone { milestone_index },
            )
        }
        Message::TransferBeneficiary {
            schedule_id,
            new_beneficiary,
        } => {
            if !input.is_authorized {
                VestingError::Unauthorized.panic_with();
            }
            require_non_zero(new_beneficiary);
            Response::keep_state().send_sync(
                own_actor(input, schedule_id),
                &Internal::TransferBeneficiary { new_beneficiary },
            )
        }
        Message::ReadState => {
            let reader = input.from.expect("ReadState needs a sender");
            Response::keep_state().send_sync(reader, &StateReply::from(input))
        }
    }
}

// ============================================================================
// Authenticated internal actor transitions
// ============================================================================

fn handle_internal(input: &ReceiveInput, from: Actor, internal: Internal) -> Response {
    let own_program = input.receiver.program_account_id;
    let cfg_id = config_pda(own_program);

    match internal {
        Internal::ReadConfig => {
            assert_eq!(
                input.receiver.account_id, cfg_id,
                "ReadConfig must target config account"
            );
            Response::keep_state().send_sync(from, &StateReply::from(input))
        }
        Internal::CreateSingle { creator, params } => {
            assert_eq!(
                from.account_id, creator,
                "CreateSingle must originate from creator actor"
            );
            assert_eq!(
                input.receiver.account_id,
                schedule_pda(own_program, &creator, &params.salt),
                "schedule PDA mismatch"
            );
            if !input.pre_state.is_empty() {
                VestingError::ScheduleAlreadyExists.panic_with();
            }
            validate_single_create(&params);
            let pending = PendingOp::CreateReadConfig { creator, params };
            Response::set_state(VestingActorState::Pending(Box::new(pending)).encode())
                .send_sync(own_actor(input, cfg_id), &Internal::ReadConfig)
        }
        Internal::CreateBatchCoord { creator, params } => {
            assert_eq!(
                from.account_id, creator,
                "CreateBatchCoord must originate from creator actor"
            );
            assert_eq!(
                input.receiver.account_id,
                batch_coord_pda(own_program, &creator, &params.batch_id),
                "batch coordinator PDA mismatch"
            );
            if !input.pre_state.is_empty() {
                VestingError::BatchAlreadyExists.panic_with();
            }
            let total_batch_amount = validate_batch_create(&params);
            let pending = PendingOp::BatchReadConfig {
                creator,
                total_batch_amount,
                params,
            };
            Response::set_state(VestingActorState::Pending(Box::new(pending)).encode())
                .send_sync(own_actor(input, cfg_id), &Internal::ReadConfig)
        }
        Internal::InitBatchSchedule { batch_id, schedule } => {
            let expected_coord = batch_coord_pda(own_program, &schedule.creator, &batch_id);
            assert_eq!(
                from.account_id, expected_coord,
                "InitBatchSchedule must originate from batch coordinator PDA"
            );
            if !input.pre_state.is_empty() {
                VestingError::ScheduleAlreadyExists.panic_with();
            }
            let ev = schedule_created_event(input.receiver.account_id, Some(batch_id), &schedule);
            Response::set_state(VestingActorState::Schedule(schedule).encode()).event(ev)
        }
        Internal::ClaimPublic {
            destination,
            amount,
        } => {
            let schedule = require_schedule(input);
            if from.account_id != schedule.beneficiary {
                VestingError::Unauthorized.panic_with();
            }
            if let Some(req) = amount {
                if req == 0 {
                    VestingError::ZeroAmount.panic_with();
                }
            }
            let pending = PendingOp::ClaimPublicReadClock {
                schedule: Box::new(schedule),
                destination,
                requested_amount: amount,
            };
            Response::set_state(VestingActorState::Pending(Box::new(pending)).encode())
                .send_sync(clock_actor(), &ClockMessage::ReadTimestamp { granularity: 1 })
        }
        Internal::ClaimExact {
            destination,
            amount,
            effective_ts,
        } => {
            let mut schedule = require_schedule(input);
            if from.account_id != schedule.beneficiary {
                VestingError::Unauthorized.panic_with();
            }
            if amount == 0 {
                VestingError::ZeroAmount.panic_with();
            }
            let claimable = claimable_at(&schedule, effective_ts);
            if claimable == 0 {
                VestingError::NothingClaimable {
                    next_unlock_ts: next_unlock_after(&schedule, effective_ts),
                }
                .panic_with();
            }
            if amount > claimable {
                VestingError::ExceedsClaimable {
                    requested: amount,
                    claimable,
                }
                .panic_with();
            }
            let needs_time_window = schedule.cancelled.is_none()
                && !matches!(schedule.kind, ScheduleKind::Milestone { .. });

            schedule.claimed_amount = schedule
                .claimed_amount
                .checked_add(amount)
                .unwrap_or_else(|| VestingError::ArithmeticOverflow.panic_with());

            let token_program_id = schedule.token_program_id;
            let escrow_account = schedule.escrow_account;
            let escrow_seed = schedule.escrow_seed;
            let ev = Claimed {
                schedule_id: input.receiver.account_id,
                beneficiary: schedule.beneficiary,
                amount,
                total_claimed: schedule.claimed_amount,
                timestamp_ms: effective_ts,
            }
            .to_program_event();

            let mut resp = Response::set_state(
                VestingActorState::Schedule(Box::new(schedule)).encode(),
            )
            .event(ev)
            .send(token_call(
                token_program_id,
                escrow_account,
                &TokenMessage::Transfer {
                    to: destination,
                    amount,
                },
                Some(escrow_seed),
            ));
            if needs_time_window {
                resp = resp.timestamp_window(effective_ts..);
            }
            resp
        }
        Internal::Cancel => {
            let schedule = require_schedule(input);
            if from.account_id != schedule.effective_cancel_authority() {
                VestingError::Unauthorized.panic_with();
            }
            if !schedule.cancelable {
                VestingError::NotCancelable.panic_with();
            }
            if schedule.cancelled.is_some() {
                VestingError::AlreadyCancelled.panic_with();
            }
            let pending = PendingOp::CancelReadClock {
                schedule: Box::new(schedule),
                cancelled_by: from.account_id,
            };
            Response::set_state(VestingActorState::Pending(Box::new(pending)).encode())
                .send_sync(clock_actor(), &ClockMessage::ReadTimestamp { granularity: 1 })
        }
        Internal::MakeNonCancelable => {
            let mut schedule = require_schedule(input);
            if from.account_id != schedule.effective_cancel_authority() {
                VestingError::Unauthorized.panic_with();
            }
            if schedule.cancelled.is_some() {
                VestingError::AlreadyCancelled.panic_with();
            }
            if !schedule.cancelable {
                VestingError::AlreadyNonCancelable.panic_with();
            }
            schedule.cancelable = false;
            let ev = MadeNonCancelable {
                schedule_id: input.receiver.account_id,
                by: from.account_id,
            }
            .to_program_event();
            Response::set_state(VestingActorState::Schedule(Box::new(schedule)).encode()).event(ev)
        }
        Internal::SignalMilestone { milestone_index } => {
            let schedule = require_schedule(input);
            if from.account_id != schedule.effective_milestone_authority() {
                VestingError::Unauthorized.panic_with();
            }
            if schedule.cancelled.is_some() {
                VestingError::AlreadyCancelled.panic_with();
            }
            let ScheduleKind::Milestone { ref tranches } = schedule.kind else {
                VestingError::NotMilestoneSchedule.panic_with();
            };
            let idx = usize::from(milestone_index);
            let Some(tranche) = tranches.get(idx) else {
                VestingError::MilestoneIndexOutOfBounds.panic_with();
            };
            if tranche.unlocked {
                VestingError::MilestoneAlreadyUnlocked(milestone_index).panic_with();
            }
            let pending = PendingOp::SignalMilestoneReadClock {
                schedule: Box::new(schedule),
                milestone_index,
                signaled_by: from.account_id,
            };
            Response::set_state(VestingActorState::Pending(Box::new(pending)).encode())
                .send_sync(clock_actor(), &ClockMessage::ReadTimestamp { granularity: 1 })
        }
        Internal::TransferBeneficiary { new_beneficiary } => {
            let mut schedule = require_schedule(input);
            if from.account_id != schedule.beneficiary {
                VestingError::Unauthorized.panic_with();
            }
            if !schedule.transferable {
                VestingError::NotTransferable.panic_with();
            }
            require_non_zero(new_beneficiary);
            if new_beneficiary == schedule.beneficiary {
                VestingError::SameBeneficiary.panic_with();
            }
            let old_beneficiary = schedule.beneficiary;
            schedule.beneficiary = new_beneficiary;
            let ev = BeneficiaryTransferred {
                schedule_id: input.receiver.account_id,
                old_beneficiary,
                new_beneficiary,
            }
            .to_program_event();
            Response::set_state(VestingActorState::Schedule(Box::new(schedule)).encode()).event(ev)
        }
    }
}

// ============================================================================
// Synchronous StateReply continuations (reentrancy-locked via PendingOp)
// ============================================================================

fn handle_state_reply(input: &ReceiveInput, pending: PendingOp) -> Response {
    let own_program = input.receiver.program_account_id;
    let cfg_actor = own_actor(input, config_pda(own_program));

    match pending {
        PendingOp::CreateReadConfig { creator, params } => {
            assert_eq!(input.from, Some(cfg_actor), "expected config StateReply");
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("config StateReply decodes");
            let config: Config = borsh::from_slice(&reply.state)
                .unwrap_or_else(|_| VestingError::TokenProgramNotConfigured.panic_with());
            let token_program_id = config
                .token_program_id
                .unwrap_or_else(|| VestingError::TokenProgramNotConfigured.panic_with());
            let protocol_fee = compute_fee_ceil(
                params.total_amount,
                config.fee_bps,
                MAX_PROTOCOL_FEE_BPS,
            )
            .unwrap_or_else(|e| e.panic_with());
            if protocol_fee > 0 && config.fee_treasury.is_none() {
                VestingError::FeeTreasuryRequired.panic_with();
            }
            let broker_fee = match &params.broker {
                Some(b) => compute_fee_ceil(params.total_amount, b.bps, MAX_BROKER_FEE_BPS)
                    .unwrap_or_else(|e| e.panic_with()),
                None => 0,
            };
            let refund_holding = params.refund_holding;
            let next = PendingOp::CreateVerifyRefund {
                creator,
                token_program_id,
                protocol_fee,
                fee_treasury: config.fee_treasury,
                broker_fee,
                params,
            };
            Response::set_state(VestingActorState::Pending(Box::new(next)).encode()).send(
                token_call(
                    token_program_id,
                    refund_holding,
                    &TokenMessage::ReadState,
                    None,
                ),
            )
        }
        PendingOp::CreateVerifyRefund {
            creator,
            token_program_id,
            protocol_fee,
            fee_treasury,
            broker_fee,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(token_program_id, params.refund_holding)),
                "expected refund_holding StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("refund StateReply decodes");
            match TokenState::decode(&reply.state) {
                Some(TokenState::Holding(h)) if h.definition_id == params.token_definition => {}
                _ => VestingError::InvalidRefundHolding.panic_with(),
            }
            let escrow_seed = single_escrow_seed(&input.receiver.account_id);
            let escrow_account = single_escrow_pda(own_program, &input.receiver.account_id);
            let token_def = params.token_definition;
            let next = PendingOp::CreateVerifyEscrowPre {
                creator,
                token_program_id,
                escrow_seed,
                escrow_account,
                protocol_fee,
                fee_treasury,
                broker_fee,
                params,
            };
            Response::set_state(VestingActorState::Pending(Box::new(next)).encode())
                .send(token_call(
                    token_program_id,
                    escrow_account,
                    &TokenMessage::InitializeHolding {
                        definition: token_def,
                    },
                    Some(escrow_seed),
                ))
                .send(token_call(
                    token_program_id,
                    escrow_account,
                    &TokenMessage::ReadState,
                    None,
                ))
        }
        PendingOp::CreateVerifyEscrowPre {
            creator,
            token_program_id,
            escrow_seed,
            escrow_account,
            protocol_fee,
            fee_treasury,
            broker_fee,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(token_program_id, escrow_account)),
                "expected escrow pre-balance StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("escrow pre StateReply decodes");
            let pre_balance = match TokenState::decode(&reply.state) {
                Some(TokenState::Holding(h)) if h.definition_id == params.token_definition => {
                    h.balance
                }
                _ => panic!("escrow holding failed to initialize for token_definition"),
            };
            let creator_holding = params.creator_holding;
            let total_amount = params.total_amount;
            let broker_target = params.broker.as_ref().map(|b| b.holding);
            let next = PendingOp::CreateVerifyEscrowPost {
                creator,
                token_program_id,
                escrow_seed,
                escrow_account,
                pre_balance,
                params,
            };
            let mut resp = Response::set_state(VestingActorState::Pending(Box::new(next)).encode())
                .send(token_call(
                    token_program_id,
                    creator_holding,
                    &TokenMessage::Transfer {
                        to: escrow_account,
                        amount: total_amount,
                    },
                    None,
                ));
            if protocol_fee > 0 {
                let treasury = fee_treasury.expect("treasury validated above");
                resp = resp.send(token_call(
                    token_program_id,
                    creator_holding,
                    &TokenMessage::Transfer {
                        to: treasury,
                        amount: protocol_fee,
                    },
                    None,
                ));
            }
            if broker_fee > 0 {
                let broker_h = broker_target.expect("broker present when broker_fee > 0");
                resp = resp.send(token_call(
                    token_program_id,
                    creator_holding,
                    &TokenMessage::Transfer {
                        to: broker_h,
                        amount: broker_fee,
                    },
                    None,
                ));
            }
            resp.send(token_call(
                token_program_id,
                escrow_account,
                &TokenMessage::ReadState,
                None,
            ))
        }
        PendingOp::CreateVerifyEscrowPost {
            creator,
            token_program_id,
            escrow_seed,
            escrow_account,
            pre_balance,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(token_program_id, escrow_account)),
                "expected escrow post-balance StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("escrow post StateReply decodes");
            let post_balance = match TokenState::decode(&reply.state) {
                Some(TokenState::Holding(h)) if h.definition_id == params.token_definition => {
                    h.balance
                }
                _ => panic!("escrow holding invalid post-transfer"),
            };
            let actual = post_balance.saturating_sub(pre_balance);
            if actual != params.total_amount {
                VestingError::EscrowFundingMismatch {
                    expected: params.total_amount,
                    actual,
                }
                .panic_with();
            }
            let schedule = ScheduleAccount {
                version: 1,
                token_program_id,
                creator,
                beneficiary: params.beneficiary,
                token_definition: params.token_definition,
                escrow_seed,
                escrow_account,
                refund_holding: params.refund_holding,
                total_amount: params.total_amount,
                claimed_amount: 0,
                kind: params.kind,
                cancelable: params.cancelable,
                transferable: params.transferable,
                cancel_authority: params.cancel_authority,
                milestone_authority: params.milestone_authority,
                cancelled: None,
            };
            let ev = schedule_created_event(input.receiver.account_id, None, &schedule);
            Response::set_state(VestingActorState::Schedule(Box::new(schedule)).encode()).event(ev)
        }
        PendingOp::BatchReadConfig {
            creator,
            total_batch_amount,
            params,
        } => {
            assert_eq!(input.from, Some(cfg_actor), "expected config StateReply");
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("config StateReply decodes");
            let config: Config = borsh::from_slice(&reply.state)
                .unwrap_or_else(|_| VestingError::TokenProgramNotConfigured.panic_with());
            let token_program_id = config
                .token_program_id
                .unwrap_or_else(|| VestingError::TokenProgramNotConfigured.panic_with());
            let protocol_fee = compute_fee_ceil(
                total_batch_amount,
                config.fee_bps,
                MAX_PROTOCOL_FEE_BPS,
            )
            .unwrap_or_else(|e| e.panic_with());
            if protocol_fee > 0 && config.fee_treasury.is_none() {
                VestingError::FeeTreasuryRequired.panic_with();
            }
            let broker_fee = match &params.broker {
                Some(b) => compute_fee_ceil(total_batch_amount, b.bps, MAX_BROKER_FEE_BPS)
                    .unwrap_or_else(|e| e.panic_with()),
                None => 0,
            };
            let refund_holding = params.refund_holding;
            let next = PendingOp::BatchVerifyRefund {
                creator,
                token_program_id,
                total_batch_amount,
                protocol_fee,
                fee_treasury: config.fee_treasury,
                broker_fee,
                params,
            };
            Response::set_state(VestingActorState::Pending(Box::new(next)).encode()).send(
                token_call(
                    token_program_id,
                    refund_holding,
                    &TokenMessage::ReadState,
                    None,
                ),
            )
        }
        PendingOp::BatchVerifyRefund {
            creator,
            token_program_id,
            total_batch_amount,
            protocol_fee,
            fee_treasury,
            broker_fee,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(token_program_id, params.refund_holding)),
                "expected refund_holding StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("refund StateReply decodes");
            match TokenState::decode(&reply.state) {
                Some(TokenState::Holding(h)) if h.definition_id == params.token_definition => {}
                _ => VestingError::InvalidRefundHolding.panic_with(),
            }
            let escrow_seed = batch_escrow_seed(&creator, &params.batch_id);
            let escrow_account = batch_escrow_pda(own_program, &creator, &params.batch_id);
            let token_def = params.token_definition;
            let next = PendingOp::BatchVerifyEscrowPre {
                creator,
                token_program_id,
                escrow_seed,
                escrow_account,
                total_batch_amount,
                protocol_fee,
                fee_treasury,
                broker_fee,
                params,
            };
            Response::set_state(VestingActorState::Pending(Box::new(next)).encode())
                .send(token_call(
                    token_program_id,
                    escrow_account,
                    &TokenMessage::InitializeHolding {
                        definition: token_def,
                    },
                    Some(escrow_seed),
                ))
                .send(token_call(
                    token_program_id,
                    escrow_account,
                    &TokenMessage::ReadState,
                    None,
                ))
        }
        PendingOp::BatchVerifyEscrowPre {
            creator,
            token_program_id,
            escrow_seed,
            escrow_account,
            total_batch_amount,
            protocol_fee,
            fee_treasury,
            broker_fee,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(token_program_id, escrow_account)),
                "expected batch escrow pre StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("batch pre StateReply decodes");
            let pre_balance = match TokenState::decode(&reply.state) {
                Some(TokenState::Holding(h)) if h.definition_id == params.token_definition => {
                    h.balance
                }
                _ => panic!("batch escrow holding failed to initialize"),
            };
            let creator_holding = params.creator_holding;
            let broker_target = params.broker.as_ref().map(|b| b.holding);
            let next = PendingOp::BatchVerifyEscrowPost {
                creator,
                token_program_id,
                escrow_seed,
                escrow_account,
                total_batch_amount,
                pre_balance,
                params,
            };
            let mut resp = Response::set_state(VestingActorState::Pending(Box::new(next)).encode())
                .send(token_call(
                    token_program_id,
                    creator_holding,
                    &TokenMessage::Transfer {
                        to: escrow_account,
                        amount: total_batch_amount,
                    },
                    None,
                ));
            if protocol_fee > 0 {
                let treasury = fee_treasury.expect("treasury validated above");
                resp = resp.send(token_call(
                    token_program_id,
                    creator_holding,
                    &TokenMessage::Transfer {
                        to: treasury,
                        amount: protocol_fee,
                    },
                    None,
                ));
            }
            if broker_fee > 0 {
                let broker_h = broker_target.expect("broker present when broker_fee > 0");
                resp = resp.send(token_call(
                    token_program_id,
                    creator_holding,
                    &TokenMessage::Transfer {
                        to: broker_h,
                        amount: broker_fee,
                    },
                    None,
                ));
            }
            resp.send(token_call(
                token_program_id,
                escrow_account,
                &TokenMessage::ReadState,
                None,
            ))
        }
        PendingOp::BatchVerifyEscrowPost {
            creator,
            token_program_id,
            escrow_seed,
            escrow_account,
            total_batch_amount,
            pre_balance,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(token_program_id, escrow_account)),
                "expected batch escrow post StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("batch post StateReply decodes");
            let post_balance = match TokenState::decode(&reply.state) {
                Some(TokenState::Holding(h)) if h.definition_id == params.token_definition => {
                    h.balance
                }
                _ => panic!("batch escrow invalid post-transfer"),
            };
            let actual = post_balance.saturating_sub(pre_balance);
            if actual != total_batch_amount {
                VestingError::EscrowFundingMismatch {
                    expected: total_batch_amount,
                    actual,
                }
                .panic_with();
            }
            let count = u32::try_from(params.items.len())
                .unwrap_or_else(|_| VestingError::ArithmeticOverflow.panic_with());
            let committed = VestingActorState::BatchCommitted {
                creator,
                batch_id: params.batch_id,
                count,
                total_amount: total_batch_amount,
            };
            let mut resp = Response::set_state(committed.encode());
            for (idx, item) in params.items.into_iter().enumerate() {
                let index_u32 = u32::try_from(idx).expect("checked count fits u32");
                let sched_id = batch_schedule_pda(own_program, &creator, &params.batch_id, index_u32);
                let schedule = ScheduleAccount {
                    version: 1,
                    token_program_id,
                    creator,
                    beneficiary: item.beneficiary,
                    token_definition: params.token_definition,
                    escrow_seed,
                    escrow_account,
                    refund_holding: params.refund_holding,
                    total_amount: item.total_amount,
                    claimed_amount: 0,
                    kind: item.kind,
                    cancelable: item.cancelable,
                    transferable: item.transferable,
                    cancel_authority: item.cancel_authority,
                    milestone_authority: item.milestone_authority,
                    cancelled: None,
                };
                resp = resp.send_sync(
                    own_actor(input, sched_id),
                    &Internal::InitBatchSchedule {
                        batch_id: params.batch_id,
                        schedule: Box::new(schedule),
                    },
                );
            }
            resp
        }
        PendingOp::ClaimPublicReadClock { .. }
        | PendingOp::CancelReadClock { .. }
        | PendingOp::SignalMilestoneReadClock { .. } => {
            panic!("actor is awaiting clock reply, rejecting reentrant call");
        }
    }
}

// ============================================================================
// Synchronous Clock Reply continuations
// ============================================================================

fn handle_clock_reply(input: &ReceiveInput, pending: PendingOp, reply: ClockReply) -> Response {
    let ClockReply::Timestamp(now_ms) = reply else {
        panic!("expected ClockReply::Timestamp");
    };
    match pending {
        PendingOp::ClaimPublicReadClock {
            mut schedule,
            destination,
            requested_amount,
        } => {
            let claimable = claimable_at(&schedule, now_ms);
            if claimable == 0 {
                VestingError::NothingClaimable {
                    next_unlock_ts: next_unlock_after(&schedule, now_ms),
                }
                .panic_with();
            }
            let amount = match requested_amount {
                Some(req) => {
                    if req > claimable {
                        VestingError::ExceedsClaimable {
                            requested: req,
                            claimable,
                        }
                        .panic_with();
                    }
                    req
                }
                None => claimable,
            };
            schedule.claimed_amount = schedule
                .claimed_amount
                .checked_add(amount)
                .unwrap_or_else(|| VestingError::ArithmeticOverflow.panic_with());

            let token_program_id = schedule.token_program_id;
            let escrow_account = schedule.escrow_account;
            let escrow_seed = schedule.escrow_seed;
            let ev = Claimed {
                schedule_id: input.receiver.account_id,
                beneficiary: schedule.beneficiary,
                amount,
                total_claimed: schedule.claimed_amount,
                timestamp_ms: now_ms,
            }
            .to_program_event();

            Response::set_state(VestingActorState::Schedule(schedule).encode())
                .event(ev)
                .send(token_call(
                    token_program_id,
                    escrow_account,
                    &TokenMessage::Transfer {
                        to: destination,
                        amount,
                    },
                    Some(escrow_seed),
                ))
        }
        PendingOp::CancelReadClock {
            mut schedule,
            cancelled_by,
        } => {
            let (vested_at_cancel, unvested_refund) =
                split_on_cancel(&schedule, now_ms).unwrap_or_else(|e| e.panic_with());
            schedule.cancelled = Some(CancellationRecord {
                cancelled_at_ms: now_ms,
                vested_at_cancel,
                refunded_amount: unvested_refund,
            });
            let token_program_id = schedule.token_program_id;
            let escrow_account = schedule.escrow_account;
            let escrow_seed = schedule.escrow_seed;
            let refund_holding = schedule.refund_holding;
            let ev = Cancelled {
                schedule_id: input.receiver.account_id,
                cancelled_by,
                cancelled_at_ms: now_ms,
                vested_at_cancel,
                refunded_amount: unvested_refund,
                refund_holding,
            }
            .to_program_event();

            Response::set_state(VestingActorState::Schedule(schedule).encode())
                .event(ev)
                .send(token_call(
                    token_program_id,
                    escrow_account,
                    &TokenMessage::Transfer {
                        to: refund_holding,
                        amount: unvested_refund,
                    },
                    Some(escrow_seed),
                ))
        }
        PendingOp::SignalMilestoneReadClock {
            mut schedule,
            milestone_index,
            signaled_by,
        } => {
            let ScheduleKind::Milestone { ref mut tranches } = schedule.kind else {
                VestingError::NotMilestoneSchedule.panic_with();
            };
            let tranche = &mut tranches[usize::from(milestone_index)];
            tranche.unlocked = true;
            tranche.unlocked_at_ms = Some(now_ms);
            let amount_unlocked = tranche.amount;
            let ev = MilestoneSignaled {
                schedule_id: input.receiver.account_id,
                milestone_index,
                amount_unlocked,
                signaled_by,
                unlocked_at_ms: now_ms,
            }
            .to_program_event();
            Response::set_state(VestingActorState::Schedule(schedule).encode()).event(ev)
        }
        _ => panic!("unexpected clock reply for non-clock pending op"),
    }
}

// ============================================================================
// Validation & event helpers
// ============================================================================

fn validate_single_create(params: &CreateScheduleParams) {
    require_non_zero(params.beneficiary);
    require_non_zero(params.token_definition);
    require_non_zero(params.refund_holding);
    if let Some(a) = params.cancel_authority {
        require_non_zero(a);
    }
    if let Some(a) = params.milestone_authority {
        require_non_zero(a);
    }
    let broker_bps = match &params.broker {
        Some(b) => {
            require_non_zero(b.holding);
            b.bps
        }
        None => 0,
    };
    validate_schedule_params(params.total_amount, &params.kind, 0, broker_bps)
        .unwrap_or_else(|e| e.panic_with());
}

fn validate_batch_create(params: &BatchCreateParams) -> u128 {
    require_non_zero(params.token_definition);
    require_non_zero(params.refund_holding);
    if params.items.is_empty() {
        VestingError::EmptyBatch.panic_with();
    }
    let broker_bps = match &params.broker {
        Some(b) => {
            require_non_zero(b.holding);
            if b.bps > MAX_BROKER_FEE_BPS {
                VestingError::FeeRateExceedsCap {
                    bps: b.bps,
                    max_bps: MAX_BROKER_FEE_BPS,
                }
                .panic_with();
            }
            b.bps
        }
        None => 0,
    };
    let mut sum = 0u128;
    for item in &params.items {
        require_non_zero(item.beneficiary);
        if let Some(a) = item.cancel_authority {
            require_non_zero(a);
        }
        if let Some(a) = item.milestone_authority {
            require_non_zero(a);
        }
        validate_schedule_params(item.total_amount, &item.kind, 0, broker_bps)
            .unwrap_or_else(|e| e.panic_with());
        sum = sum
            .checked_add(item.total_amount)
            .unwrap_or_else(|| VestingError::ArithmeticOverflow.panic_with());
    }
    sum
}

fn schedule_created_event(
    schedule_id: AccountId,
    batch_id: Option<[u8; 32]>,
    schedule: &ScheduleAccount,
) -> lee_core::program::ProgramEvent {
    ScheduleCreated {
        schedule_id,
        batch_id,
        creator: schedule.creator,
        beneficiary: schedule.beneficiary,
        token_definition: schedule.token_definition,
        escrow_account: schedule.escrow_account,
        refund_holding: schedule.refund_holding,
        total_amount: schedule.total_amount,
        kind_tag: schedule.kind.tag(),
        cancelable: schedule.cancelable,
        transferable: schedule.transferable,
        cancel_authority: schedule.cancel_authority,
        milestone_authority: schedule.milestone_authority,
    }
    .to_program_event()
}
