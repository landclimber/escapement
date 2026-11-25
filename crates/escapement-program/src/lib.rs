//! Escapement — Privacy-Preserving Token Vesting Program for LEZ v0.4.
//!
//! Uses LEZ v0.4's actor-message execution model (`actor_entrypoint!(raw handle_message)`),
//! `lez-admin-authority` v0.2.0 for bounded creation-fee governance, per-token fee vault PDAs,
//! `clock_core` for live public time (`ClaimPublic`, `Cancel`, `SignalMilestone`), and
//! `Response::timestamp_window` for expiry-free private claims (`ClaimExact`).

use clock_core::{clock_account_id, clock_actor, Message as ClockMessage, Reply as ClockReply};
use escapement_core::{
    batch_coord_pda, batch_coord_seed, batch_escrow_pda, batch_escrow_seed, batch_schedule_pda,
    batch_schedule_seed, config_pda,
    event::{
        BeneficiaryTransferred, Cancelled, Claimed, FeeConfigUpdated, FeeWithdrawn,
        MadeNonCancelable, MilestoneSignaled, ScheduleCreated, VestingEvent as _,
    },
    fee_vault_pda, fee_vault_seed,
    math::{claimable_at, compute_fee_ceil, split_on_cancel, validate_schedule_params},
    schedule_pda, schedule_seed, single_escrow_pda, single_escrow_seed, Asset, BatchCreateParams,
    BrokerFee, CancellationRecord, Config, CreateScheduleParams, Internal, Message, PendingOp,
    ScheduleAccount, ScheduleKind, VestingActorState, VestingError, CONFIG_SEED,
    MAX_BROKER_FEE_BPS, MAX_PROTOCOL_FEE_BPS, NATIVE_PROGRAM_ID, ZERO_ACCOUNT_ID,
};
use lee_core::native_token::Message as NativeMessage;
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
    let wire: Wire<Message> = borsh::from_slice(&input.message)
        .unwrap_or_else(|_| VestingError::MalformedMessage.abort());
    let mut resp = lez_admin_authority::guard::<(Admin,), Config, Message>(
        input,
        &CONFIG_SEED,
        InitGate::Deployer,
        wire,
        handle_public_message,
    );
    // Admit `config_pda` on first delivery (e.g., `AdminOp::Init`) under LEZ v0.4's
    // `UnadmittedPublicActor` rule by attaching `CONFIG_SEED` strictly to `lez-authority`
    // library seat->config forwards.
    for msg in &mut resp.sync_messages {
        if msg.to == Actor::new(cfg_id, own_program)
            && msg.message.first().copied() == Some(LIBRARY_TAG)
        {
            msg.pda_seeds.insert(CONFIG_SEED);
        }
    }
    resp
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

/// Transfer `amount` of `asset` out of `from` (debited with `seed` when `from` is one of our PDAs).
fn asset_transfer(
    asset_program_id: AccountId,
    asset: Asset,
    from: AccountId,
    to: AccountId,
    amount: u128,
    seed: Option<PdaSeed>,
) -> SyncMessage {
    match asset {
        Asset::Native => SyncMessage::new(
            Actor::native_balance(from),
            &NativeMessage::Transfer { to, amount },
        )
        .with_pda_seeds(seed),
        Asset::Token { .. } => token_call(
            asset_program_id,
            from,
            &TokenMessage::Transfer { to, amount },
            seed,
        ),
    }
}

/// Ask `account`'s balance actor for its state (a `StateReply` comes back to the sender). A seed
/// admits a not-yet-existing PDA account under LEZ v0.4's admission rule.
fn asset_read(
    asset_program_id: AccountId,
    asset: Asset,
    account: AccountId,
    seed: Option<PdaSeed>,
) -> SyncMessage {
    match asset {
        Asset::Native => {
            SyncMessage::new(Actor::native_balance(account), &NativeMessage::ReadState)
                .with_pda_seeds(seed)
        }
        Asset::Token { .. } => {
            token_call(asset_program_id, account, &TokenMessage::ReadState, seed)
        }
    }
}

/// Balance of `asset` encoded in a balance actor's state (`None` if it is not a valid balance of
/// this asset, e.g. a token holding of another definition).
fn asset_balance(asset: Asset, state: &[u8]) -> Option<u128> {
    match asset {
        Asset::Native => lee_core::native_token::decode_balance(state).ok(),
        Asset::Token { definition } => match TokenState::decode(state) {
            Some(TokenState::Holding(h)) if h.definition_id == definition => Some(h.balance),
            _ => None,
        },
    }
}

/// Program holding `asset` balances: the native program, or the configured token program.
fn asset_program_for(asset: Asset, config: &Config) -> AccountId {
    match asset {
        Asset::Native => NATIVE_PROGRAM_ID,
        Asset::Token { .. } => config
            .token_program_id
            .unwrap_or_else(|| VestingError::TokenProgramNotConfigured.abort()),
    }
}

fn require_asset(asset: Asset) {
    if let Asset::Token { definition } = asset {
        require_non_zero(definition);
    }
}

/// Native refunds are plain native credits: refuse refund targets that are this schedule's own
/// program accounts, where refunded tokens would be stranded.
fn require_native_refund_target(
    own_program: AccountId,
    refund: AccountId,
    own_accounts: &[AccountId],
) {
    if refund == config_pda(own_program)
        || refund == fee_vault_pda(own_program, &Asset::Native.key())
        || own_accounts.contains(&refund)
    {
        VestingError::InvalidRefundHolding.abort();
    }
}

/// Native-asset creations debit the creator's own native balance.
fn require_native_funding(creator: AccountId, creator_holding: AccountId) {
    if creator_holding != creator {
        VestingError::Unauthorized.abort();
    }
}

fn admit_fee_vault(input: &ReceiveInput, asset: Asset) -> SyncMessage {
    let own_program = input.receiver.program_account_id;
    let key = asset.key();
    SyncMessage::new(
        own_actor(input, fee_vault_pda(own_program, &key)),
        &Internal::AdmitFeeVault { asset_key: key },
    )
    .with_pda_seeds(Some(fee_vault_seed(&key)))
}

fn require_schedule(input: &ReceiveInput) -> ScheduleAccount {
    if input.receiver.account_id == config_pda(input.receiver.program_account_id) {
        VestingError::NotASchedule.abort();
    }
    match VestingActorState::decode(&input.pre_state) {
        Some(VestingActorState::Schedule(s)) => *s,
        _ => VestingError::NotASchedule.abort(),
    }
}

fn require_non_zero(id: AccountId) {
    if id == ZERO_ACCOUNT_ID {
        VestingError::ZeroAddress.abort();
    }
}

fn abort_nothing_claimable(schedule: &ScheduleAccount, timestamp_ms: u64) -> ! {
    #[cfg(target_os = "zkvm")]
    {
        let _ = (schedule, timestamp_ms);
        VestingError::NothingClaimable {
            next_unlock_ts: None,
        }
        .abort()
    }
    #[cfg(not(target_os = "zkvm"))]
    {
        VestingError::NothingClaimable {
            next_unlock_ts: escapement_core::math::next_unlock_after(schedule, timestamp_ms),
        }
        .abort()
    }
}

// ============================================================================
// Public message handlers (post `lez-admin-authority::guard`)
// ============================================================================

fn handle_public_message(input: &ReceiveInput, message: Message) -> Response {
    let own_program = input.receiver.program_account_id;
    let cfg_id = config_pda(own_program);
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
                .abort();
            }
            if fee_bps > 0 && fee_treasury.is_none() {
                VestingError::FeeTreasuryRequired.abort();
            }
            if let Some(treasury) = fee_treasury {
                require_non_zero(treasury);
            }
            let mut config: Config =
                borsh::from_slice(&input.pre_state).expect("config must decode");
            match (config.token_program_id, token_program_id) {
                (None, Some(id)) => {
                    require_non_zero(id);
                    if id == own_program || id == cfg_id || id == clock_account_id() {
                        VestingError::InvalidTokenProgram.abort();
                    }
                    config.token_program_id = Some(id);
                }
                (Some(existing), Some(supplied)) if existing != supplied => {
                    VestingError::TokenProgramImmutable.abort();
                }
                (None, None) => VestingError::TokenProgramNotConfigured.abort(),
                _ => {}
            }
            config.fee_bps = fee_bps;
            config.fee_treasury = fee_treasury;
            let resolved_token_program =
                config.token_program_id.expect("token_program_id set above");
            Response::set_state(borsh::to_vec(&config).expect("config encodes")).event(
                FeeConfigUpdated {
                    token_program_id: resolved_token_program,
                    fee_bps,
                    fee_treasury,
                }
                .to_program_event(),
            )
        }
        Message::ReadState => {
            let Some(reader) = input.from else {
                VestingError::MalformedMessage.abort();
            };
            Response::keep_state().send_sync(reader, &StateReply::from(input))
        }
        Message::AsPda { seed, call } => {
            // Only the program that owns this PDA, calling it directly with the PDA's seed,
            // may act for it. An inherited grant or a signer's propagated authority is not enough.
            let direct = input.from.is_some_and(|from| {
                from.program_account_id != own_program
                    && AccountId::for_public_pda(&from.program_account_id, &PdaSeed::new(seed))
                        == input.receiver.account_id
            });
            if !direct || !input.is_authorized {
                VestingError::NotRootOrDirectPda.abort();
            }
            handle_user_call(input, Message::from(*call))
        }
        user => {
            // LEZ v0.4 authorizes a signer's account on every message of the call tree, so a
            // program the user signs for could otherwise act here in the user's name.
            if input.from.is_some() {
                VestingError::NotRootOrDirectPda.abort();
            }
            if !input.is_authorized {
                VestingError::Unauthorized.abort();
            }
            handle_user_call(input, user)
        }
    }
}

/// User transitions, after `handle_public_message` established that the receiving account itself
/// authorized this call (as the transaction's signer at the root, or as a directly-called PDA).
fn handle_user_call(input: &ReceiveInput, message: Message) -> Response {
    let own_program = input.receiver.program_account_id;
    let cfg_id = config_pda(own_program);
    match message {
        Message::WithdrawFees {
            asset,
            destination,
            amount,
        } => {
            require_asset(asset);
            require_non_zero(destination);
            if amount == 0 {
                VestingError::ZeroAmount.abort();
            }
            Response::keep_state().send_sync(
                own_actor(input, cfg_id),
                &Internal::WithdrawFees {
                    asset,
                    destination,
                    amount,
                },
            )
        }
        Message::CreateSchedule(params) => {
            let creator = input.receiver.account_id;
            let seed = schedule_seed(&creator, &params.salt);
            let sched_id = schedule_pda(own_program, &creator, &params.salt);
            Response::keep_state().send(
                SyncMessage::new(
                    own_actor(input, sched_id),
                    &Internal::CreateSingle { creator, params },
                )
                .with_pda_seeds(Some(seed)),
            )
        }
        Message::BatchCreate(params) => {
            let creator = input.receiver.account_id;
            let seed = batch_coord_seed(&creator, &params.batch_id);
            let coord_id = batch_coord_pda(own_program, &creator, &params.batch_id);
            Response::keep_state().send(
                SyncMessage::new(
                    own_actor(input, coord_id),
                    &Internal::CreateBatchCoord { creator, params },
                )
                .with_pda_seeds(Some(seed)),
            )
        }
        Message::ClaimPublic {
            schedule_id,
            destination,
            amount,
        } => {
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
            Response::keep_state().send_sync(own_actor(input, schedule_id), &Internal::Cancel)
        }
        Message::MakeNonCancelable { schedule_id } => Response::keep_state()
            .send_sync(own_actor(input, schedule_id), &Internal::MakeNonCancelable),
        Message::SignalMilestone {
            schedule_id,
            milestone_index,
        } => Response::keep_state().send_sync(
            own_actor(input, schedule_id),
            &Internal::SignalMilestone { milestone_index },
        ),
        Message::TransferBeneficiary {
            schedule_id,
            new_beneficiary,
        } => {
            require_non_zero(new_beneficiary);
            Response::keep_state().send_sync(
                own_actor(input, schedule_id),
                &Internal::TransferBeneficiary { new_beneficiary },
            )
        }
        Message::Configure { .. } | Message::ReadState | Message::AsPda { .. } => {
            VestingError::MalformedMessage.abort()
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
        Internal::AdmitFeeVault { asset_key } => {
            assert_eq!(
                input.receiver.account_id,
                fee_vault_pda(own_program, &asset_key),
                "AdmitFeeVault must target the asset's fee vault"
            );
            Response::keep_state()
        }
        Internal::WithdrawFees {
            asset,
            destination,
            amount,
        } => {
            assert_eq!(
                input.receiver.account_id, cfg_id,
                "WithdrawFees must target config account"
            );
            let config: Config = borsh::from_slice(&input.pre_state)
                .unwrap_or_else(|_| VestingError::TokenProgramNotConfigured.abort());
            let asset_program_id = asset_program_for(asset, &config);
            if config.fee_treasury != Some(from.account_id) {
                VestingError::Unauthorized.abort();
            }
            let fv_seed = fee_vault_seed(&asset.key());
            let fv_pda = fee_vault_pda(own_program, &asset.key());
            if destination == fv_pda {
                VestingError::InvalidDestination.abort();
            }
            let ev = FeeWithdrawn {
                asset,
                amount,
                withdrawn_by: from.account_id,
            }
            .to_program_event();
            Response::keep_state().event(ev).send(asset_transfer(
                asset_program_id,
                asset,
                fv_pda,
                destination,
                amount,
                Some(fv_seed),
            ))
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
                VestingError::ScheduleAlreadyExists.abort();
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
                VestingError::BatchAlreadyExists.abort();
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
                VestingError::ScheduleAlreadyExists.abort();
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
                VestingError::Unauthorized.abort();
            }
            if destination == schedule.escrow_account {
                VestingError::InvalidDestination.abort();
            }
            if amount == Some(0) {
                VestingError::ZeroAmount.abort();
            }
            let pending = PendingOp::ClaimPublicReadClock {
                schedule: Box::new(schedule),
                destination,
                requested_amount: amount,
            };
            Response::set_state(VestingActorState::Pending(Box::new(pending)).encode()).send_sync(
                clock_actor(),
                &ClockMessage::ReadTimestamp { granularity: 1 },
            )
        }
        Internal::ClaimExact {
            destination,
            amount,
            effective_ts,
        } => {
            let mut schedule = require_schedule(input);
            if from.account_id != schedule.beneficiary {
                VestingError::Unauthorized.abort();
            }
            if destination == schedule.escrow_account {
                VestingError::InvalidDestination.abort();
            }
            if amount == 0 {
                VestingError::ZeroAmount.abort();
            }
            let vested = escapement_core::math::vested_at(&schedule, effective_ts);
            schedule.vested_high_water = schedule.vested_high_water.max(vested);
            let claimable = claimable_at(&schedule, effective_ts);
            if claimable == 0 {
                abort_nothing_claimable(&schedule, effective_ts);
            }
            if amount > claimable {
                VestingError::ExceedsClaimable {
                    requested: amount,
                    claimable,
                }
                .abort();
            }

            schedule.claimed_amount = schedule
                .claimed_amount
                .checked_add(amount)
                .unwrap_or_else(|| VestingError::ArithmeticOverflow.abort());

            let asset_program_id = schedule.asset_program_id;
            let asset = schedule.asset;
            let escrow_account = schedule.escrow_account;
            let escrow_seed = PdaSeed::new(schedule.escrow_seed);
            let ev = Claimed {
                schedule_id: input.receiver.account_id,
                beneficiary: schedule.beneficiary,
                amount,
                total_claimed: schedule.claimed_amount,
                timestamp_ms: effective_ts,
            }
            .to_program_event();

            // Always enforce `block_ts >= effective_ts` so `Claimed.timestamp_ms` can never be
            // spoofed into the future even on cancelled or milestone schedules (`effective_ts = 0`
            // remains valid whenever time does not gate vesting).
            Response::set_state(VestingActorState::Schedule(Box::new(schedule)).encode())
                .event(ev)
                .timestamp_window(effective_ts..)
                .send(asset_transfer(
                    asset_program_id,
                    asset,
                    escrow_account,
                    destination,
                    amount,
                    Some(escrow_seed),
                ))
        }
        Internal::Cancel => {
            let schedule = require_schedule(input);
            if from.account_id != schedule.effective_cancel_authority() {
                VestingError::Unauthorized.abort();
            }
            if !schedule.cancelable {
                VestingError::NotCancelable.abort();
            }
            if schedule.cancelled.is_some() {
                VestingError::AlreadyCancelled.abort();
            }
            let pending = PendingOp::CancelReadClock {
                schedule: Box::new(schedule),
                cancelled_by: from.account_id,
            };
            Response::set_state(VestingActorState::Pending(Box::new(pending)).encode()).send_sync(
                clock_actor(),
                &ClockMessage::ReadTimestamp { granularity: 1 },
            )
        }
        Internal::MakeNonCancelable => {
            let mut schedule = require_schedule(input);
            if from.account_id != schedule.effective_cancel_authority() {
                VestingError::Unauthorized.abort();
            }
            if schedule.cancelled.is_some() {
                VestingError::AlreadyCancelled.abort();
            }
            if !schedule.cancelable {
                VestingError::AlreadyNonCancelable.abort();
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
                VestingError::Unauthorized.abort();
            }
            if schedule.cancelled.is_some() {
                VestingError::AlreadyCancelled.abort();
            }
            let ScheduleKind::Milestone { ref tranches } = schedule.kind else {
                VestingError::NotMilestoneSchedule.abort();
            };
            let idx = usize::from(milestone_index);
            let Some(tranche) = tranches.get(idx) else {
                VestingError::MilestoneIndexOutOfBounds.abort();
            };
            if tranche.unlocked {
                VestingError::MilestoneAlreadyUnlocked(milestone_index).abort();
            }
            let pending = PendingOp::SignalMilestoneReadClock {
                schedule: Box::new(schedule),
                milestone_index,
                signaled_by: from.account_id,
            };
            Response::set_state(VestingActorState::Pending(Box::new(pending)).encode()).send_sync(
                clock_actor(),
                &ClockMessage::ReadTimestamp { granularity: 1 },
            )
        }
        Internal::TransferBeneficiary { new_beneficiary } => {
            let mut schedule = require_schedule(input);
            if from.account_id != schedule.beneficiary {
                VestingError::Unauthorized.abort();
            }
            if !schedule.transferable {
                VestingError::NotTransferable.abort();
            }
            require_non_zero(new_beneficiary);
            if new_beneficiary == schedule.beneficiary {
                VestingError::SameBeneficiary.abort();
            }
            if new_beneficiary == input.receiver.account_id
                || new_beneficiary == schedule.escrow_account
            {
                VestingError::InvalidDestination.abort();
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
                .unwrap_or_else(|_| VestingError::TokenProgramNotConfigured.abort());
            let asset = params.asset;
            let asset_program_id = asset_program_for(asset, &config);
            let (protocol_fee, broker_fee) =
                creation_fees(params.total_amount, &config, params.broker.as_ref());
            let sched_id = input.receiver.account_id;
            let escrow_seed = *single_escrow_seed(&sched_id).as_bytes();
            let escrow_account = single_escrow_pda(own_program, &sched_id);
            match asset {
                Asset::Token { .. } => {
                    let refund_holding = params.refund_holding;
                    let next = PendingOp::CreateVerifyRefund {
                        creator,
                        asset_program_id,
                        protocol_fee,
                        broker_fee,
                        params,
                    };
                    Response::set_state(VestingActorState::Pending(Box::new(next)).encode())
                        .send(asset_read(asset_program_id, asset, refund_holding, None))
                }
                Asset::Native => {
                    require_native_funding(creator, params.creator_holding);
                    require_native_refund_target(
                        own_program,
                        params.refund_holding,
                        &[sched_id, escrow_account],
                    );
                    let next = PendingOp::CreateVerifyEscrowPre {
                        creator,
                        asset_program_id,
                        escrow_seed,
                        escrow_account,
                        protocol_fee,
                        broker_fee,
                        params,
                    };
                    let mut resp =
                        Response::set_state(VestingActorState::Pending(Box::new(next)).encode());
                    if protocol_fee > 0 {
                        resp = resp.send(admit_fee_vault(input, asset));
                    }
                    // The seed admits the escrow PDA account before its first native credit.
                    resp.send(asset_read(
                        asset_program_id,
                        asset,
                        escrow_account,
                        Some(PdaSeed::new(escrow_seed)),
                    ))
                }
            }
        }
        PendingOp::CreateVerifyRefund {
            creator,
            asset_program_id,
            protocol_fee,
            broker_fee,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(asset_program_id, params.refund_holding)),
                "expected refund_holding StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("refund StateReply decodes");
            if asset_balance(params.asset, &reply.state).is_none() {
                VestingError::InvalidRefundHolding.abort();
            }
            let asset = params.asset;
            let Asset::Token { definition } = asset else {
                VestingError::MalformedMessage.abort();
            };
            let escrow_seed = *single_escrow_seed(&input.receiver.account_id).as_bytes();
            let escrow_account = single_escrow_pda(own_program, &input.receiver.account_id);
            let next = PendingOp::CreateVerifyEscrowPre {
                creator,
                asset_program_id,
                escrow_seed,
                escrow_account,
                protocol_fee,
                broker_fee,
                params,
            };
            init_token_escrow_and_read(
                input,
                VestingActorState::Pending(Box::new(next)),
                asset_program_id,
                definition,
                escrow_account,
                escrow_seed,
                protocol_fee,
            )
        }
        PendingOp::CreateVerifyEscrowPre {
            creator,
            asset_program_id,
            escrow_seed,
            escrow_account,
            protocol_fee,
            broker_fee,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(asset_program_id, escrow_account)),
                "expected escrow pre-balance StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("escrow pre StateReply decodes");
            let pre_balance = asset_balance(params.asset, &reply.state)
                .unwrap_or_else(|| panic!("escrow balance actor is invalid for the asset"));
            let asset = params.asset;
            let creator_holding = params.creator_holding;
            let total_amount = params.total_amount;
            let broker_target = params.broker.as_ref().map(|b| b.holding);
            let next = PendingOp::CreateVerifyEscrowPost {
                creator,
                asset_program_id,
                escrow_seed,
                escrow_account,
                pre_balance,
                params,
            };
            fund_escrow_and_read(
                input,
                VestingActorState::Pending(Box::new(next)),
                asset_program_id,
                asset,
                creator_holding,
                escrow_account,
                total_amount,
                protocol_fee,
                broker_fee,
                broker_target,
            )
        }
        PendingOp::CreateVerifyEscrowPost {
            creator,
            asset_program_id,
            escrow_seed,
            escrow_account,
            pre_balance,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(asset_program_id, escrow_account)),
                "expected escrow post-balance StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("escrow post StateReply decodes");
            let post_balance = asset_balance(params.asset, &reply.state)
                .unwrap_or_else(|| panic!("escrow balance actor invalid post-transfer"));
            let actual = post_balance.saturating_sub(pre_balance);
            if actual != params.total_amount {
                VestingError::EscrowFundingMismatch {
                    expected: params.total_amount,
                    actual,
                }
                .abort();
            }
            let schedule = ScheduleAccount {
                version: 1,
                asset_program_id,
                creator,
                beneficiary: params.beneficiary,
                asset: params.asset,
                escrow_seed,
                escrow_account,
                refund_holding: params.refund_holding,
                total_amount: params.total_amount,
                claimed_amount: 0,
                vested_high_water: 0,
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
                .unwrap_or_else(|_| VestingError::TokenProgramNotConfigured.abort());
            let asset = params.asset;
            let asset_program_id = asset_program_for(asset, &config);
            let (protocol_fee, broker_fee) =
                creation_fees(total_batch_amount, &config, params.broker.as_ref());
            let escrow_seed = *batch_escrow_seed(&creator, &params.batch_id).as_bytes();
            let escrow_account = batch_escrow_pda(own_program, &creator, &params.batch_id);
            match asset {
                Asset::Token { .. } => {
                    let refund_holding = params.refund_holding;
                    let next = PendingOp::BatchVerifyRefund {
                        creator,
                        asset_program_id,
                        total_batch_amount,
                        protocol_fee,
                        broker_fee,
                        params,
                    };
                    Response::set_state(VestingActorState::Pending(Box::new(next)).encode())
                        .send(asset_read(asset_program_id, asset, refund_holding, None))
                }
                Asset::Native => {
                    require_native_funding(creator, params.creator_holding);
                    require_native_refund_target(
                        own_program,
                        params.refund_holding,
                        &[input.receiver.account_id, escrow_account],
                    );
                    let next = PendingOp::BatchVerifyEscrowPre {
                        creator,
                        asset_program_id,
                        escrow_seed,
                        escrow_account,
                        total_batch_amount,
                        protocol_fee,
                        broker_fee,
                        params,
                    };
                    let mut resp =
                        Response::set_state(VestingActorState::Pending(Box::new(next)).encode());
                    if protocol_fee > 0 {
                        resp = resp.send(admit_fee_vault(input, asset));
                    }
                    resp.send(asset_read(
                        asset_program_id,
                        asset,
                        escrow_account,
                        Some(PdaSeed::new(escrow_seed)),
                    ))
                }
            }
        }
        PendingOp::BatchVerifyRefund {
            creator,
            asset_program_id,
            total_batch_amount,
            protocol_fee,
            broker_fee,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(asset_program_id, params.refund_holding)),
                "expected refund_holding StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("refund StateReply decodes");
            if asset_balance(params.asset, &reply.state).is_none() {
                VestingError::InvalidRefundHolding.abort();
            }
            let Asset::Token { definition } = params.asset else {
                VestingError::MalformedMessage.abort();
            };
            let escrow_seed = *batch_escrow_seed(&creator, &params.batch_id).as_bytes();
            let escrow_account = batch_escrow_pda(own_program, &creator, &params.batch_id);
            let next = PendingOp::BatchVerifyEscrowPre {
                creator,
                asset_program_id,
                escrow_seed,
                escrow_account,
                total_batch_amount,
                protocol_fee,
                broker_fee,
                params,
            };
            init_token_escrow_and_read(
                input,
                VestingActorState::Pending(Box::new(next)),
                asset_program_id,
                definition,
                escrow_account,
                escrow_seed,
                protocol_fee,
            )
        }
        PendingOp::BatchVerifyEscrowPre {
            creator,
            asset_program_id,
            escrow_seed,
            escrow_account,
            total_batch_amount,
            protocol_fee,
            broker_fee,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(asset_program_id, escrow_account)),
                "expected batch escrow pre StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("batch pre StateReply decodes");
            let pre_balance = asset_balance(params.asset, &reply.state)
                .unwrap_or_else(|| panic!("batch escrow balance actor is invalid for the asset"));
            let asset = params.asset;
            let creator_holding = params.creator_holding;
            let broker_target = params.broker.as_ref().map(|b| b.holding);
            let next = PendingOp::BatchVerifyEscrowPost {
                creator,
                asset_program_id,
                escrow_seed,
                escrow_account,
                total_batch_amount,
                pre_balance,
                params,
            };
            fund_escrow_and_read(
                input,
                VestingActorState::Pending(Box::new(next)),
                asset_program_id,
                asset,
                creator_holding,
                escrow_account,
                total_batch_amount,
                protocol_fee,
                broker_fee,
                broker_target,
            )
        }
        PendingOp::BatchVerifyEscrowPost {
            creator,
            asset_program_id,
            escrow_seed,
            escrow_account,
            total_batch_amount,
            pre_balance,
            params,
        } => {
            assert_eq!(
                input.from,
                Some(token_actor(asset_program_id, escrow_account)),
                "expected batch escrow post StateReply"
            );
            let reply: StateReply =
                borsh::from_slice(&input.message).expect("batch post StateReply decodes");
            let post_balance = asset_balance(params.asset, &reply.state)
                .unwrap_or_else(|| panic!("batch escrow invalid post-transfer"));
            let actual = post_balance.saturating_sub(pre_balance);
            if actual != total_batch_amount {
                VestingError::EscrowFundingMismatch {
                    expected: total_batch_amount,
                    actual,
                }
                .abort();
            }
            let count = u32::try_from(params.items.len())
                .unwrap_or_else(|_| VestingError::ArithmeticOverflow.abort());
            let committed = VestingActorState::BatchCommitted {
                creator,
                batch_id: params.batch_id,
                count,
                total_amount: total_batch_amount,
            };
            let mut resp = Response::set_state(committed.encode());
            for (idx, item) in params.items.into_iter().enumerate() {
                let index_u32 = u32::try_from(idx).expect("checked count fits u32");
                let seed = batch_schedule_seed(&creator, &params.batch_id, index_u32);
                let sched_id =
                    batch_schedule_pda(own_program, &creator, &params.batch_id, index_u32);
                let schedule = ScheduleAccount {
                    version: 1,
                    asset_program_id,
                    creator,
                    beneficiary: item.beneficiary,
                    asset: params.asset,
                    escrow_seed,
                    escrow_account,
                    refund_holding: params.refund_holding,
                    total_amount: item.total_amount,
                    claimed_amount: 0,
                    vested_high_water: 0,
                    kind: item.kind,
                    cancelable: item.cancelable,
                    transferable: item.transferable,
                    cancel_authority: item.cancel_authority,
                    milestone_authority: item.milestone_authority,
                    cancelled: None,
                };
                resp = resp.send(
                    SyncMessage::new(
                        own_actor(input, sched_id),
                        &Internal::InitBatchSchedule {
                            batch_id: params.batch_id,
                            schedule: Box::new(schedule),
                        },
                    )
                    .with_pda_seeds(Some(seed)),
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

/// Protocol and broker creation fees (both rounded up), checking the total still fits `u128`.
fn creation_fees(total: u128, config: &Config, broker: Option<&BrokerFee>) -> (u128, u128) {
    let protocol_fee =
        compute_fee_ceil(total, config.fee_bps, MAX_PROTOCOL_FEE_BPS).unwrap_or_else(|e| e.abort());
    if protocol_fee > 0 && config.fee_treasury.is_none() {
        VestingError::FeeTreasuryRequired.abort();
    }
    let broker_fee = match broker {
        Some(b) => compute_fee_ceil(total, b.bps, MAX_BROKER_FEE_BPS).unwrap_or_else(|e| e.abort()),
        None => 0,
    };
    total
        .checked_add(protocol_fee)
        .and_then(|s| s.checked_add(broker_fee))
        .unwrap_or_else(|| VestingError::ArithmeticOverflow.abort());
    (protocol_fee, broker_fee)
}

/// Token assets: initialize the escrow holding (and the fee vault holding when a fee is due),
/// then read the escrow's pre-funding balance.
fn init_token_escrow_and_read(
    input: &ReceiveInput,
    next: VestingActorState,
    asset_program_id: AccountId,
    definition: AccountId,
    escrow_account: AccountId,
    escrow_seed: [u8; 32],
    protocol_fee: u128,
) -> Response {
    let own_program = input.receiver.program_account_id;
    let mut resp = Response::set_state(next.encode()).send(token_call(
        asset_program_id,
        escrow_account,
        &TokenMessage::InitializeHolding { definition },
        Some(PdaSeed::new(escrow_seed)),
    ));
    if protocol_fee > 0 {
        // Idempotent per-token fee vault PDA initialization: enables multi-token fee
        // collection on LEZ v0.4's single-token-per-account holding model.
        resp = resp.send(token_call(
            asset_program_id,
            fee_vault_pda(own_program, &definition),
            &TokenMessage::InitializeHolding { definition },
            Some(fee_vault_seed(&definition)),
        ));
    }
    resp.send(asset_read(
        asset_program_id,
        Asset::Token { definition },
        escrow_account,
        None,
    ))
}

/// Move the allocation (and any fees) from the creator, then read the escrow's post balance.
#[allow(clippy::too_many_arguments)]
fn fund_escrow_and_read(
    input: &ReceiveInput,
    next: VestingActorState,
    asset_program_id: AccountId,
    asset: Asset,
    creator_holding: AccountId,
    escrow_account: AccountId,
    total_amount: u128,
    protocol_fee: u128,
    broker_fee: u128,
    broker_target: Option<AccountId>,
) -> Response {
    let own_program = input.receiver.program_account_id;
    let mut resp = Response::set_state(next.encode()).send(asset_transfer(
        asset_program_id,
        asset,
        creator_holding,
        escrow_account,
        total_amount,
        None,
    ));
    if protocol_fee > 0 {
        resp = resp.send(asset_transfer(
            asset_program_id,
            asset,
            creator_holding,
            fee_vault_pda(own_program, &asset.key()),
            protocol_fee,
            None,
        ));
    }
    if broker_fee > 0 {
        let broker_h = broker_target.expect("broker present when broker_fee > 0");
        resp = resp.send(asset_transfer(
            asset_program_id,
            asset,
            creator_holding,
            broker_h,
            broker_fee,
            None,
        ));
    }
    resp.send(asset_read(asset_program_id, asset, escrow_account, None))
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
            schedule.vested_high_water = schedule
                .vested_high_water
                .max(escapement_core::math::vested_at(&schedule, now_ms));
            let claimable = claimable_at(&schedule, now_ms);
            if claimable == 0 {
                abort_nothing_claimable(&schedule, now_ms);
            }
            let amount = match requested_amount {
                Some(req) => {
                    if req > claimable {
                        VestingError::ExceedsClaimable {
                            requested: req,
                            claimable,
                        }
                        .abort();
                    }
                    req
                }
                None => claimable,
            };
            schedule.claimed_amount = schedule
                .claimed_amount
                .checked_add(amount)
                .unwrap_or_else(|| VestingError::ArithmeticOverflow.abort());

            let asset_program_id = schedule.asset_program_id;
            let asset = schedule.asset;
            let escrow_account = schedule.escrow_account;
            let escrow_seed = PdaSeed::new(schedule.escrow_seed);
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
                .send(asset_transfer(
                    asset_program_id,
                    asset,
                    escrow_account,
                    destination,
                    amount,
                    Some(escrow_seed),
                ))
        }
        PendingOp::CancelReadClock {
            mut schedule,
            cancelled_by,
        } => {
            let (vested_at_cancel, unvested_refund) =
                split_on_cancel(&schedule, now_ms).unwrap_or_else(|e| e.abort());
            schedule.vested_high_water = vested_at_cancel;
            schedule.cancelled = Some(CancellationRecord {
                cancelled_at_ms: now_ms,
                vested_at_cancel,
                refunded_amount: unvested_refund,
            });
            let asset_program_id = schedule.asset_program_id;
            let asset = schedule.asset;
            let escrow_account = schedule.escrow_account;
            let escrow_seed = PdaSeed::new(schedule.escrow_seed);
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
                .send(asset_transfer(
                    asset_program_id,
                    asset,
                    escrow_account,
                    refund_holding,
                    unvested_refund,
                    Some(escrow_seed),
                ))
        }
        PendingOp::SignalMilestoneReadClock {
            mut schedule,
            milestone_index,
            signaled_by,
        } => {
            let ScheduleKind::Milestone { ref mut tranches } = schedule.kind else {
                VestingError::NotMilestoneSchedule.abort();
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

fn validate_authorities(
    cancelable: bool,
    kind: &ScheduleKind,
    cancel_authority: Option<AccountId>,
    milestone_authority: Option<AccountId>,
) {
    if let Some(a) = cancel_authority {
        if !cancelable {
            VestingError::InvalidAuthorityForSchedule.abort();
        }
        require_non_zero(a);
    }
    if let Some(a) = milestone_authority {
        if !matches!(kind, ScheduleKind::Milestone { .. }) {
            VestingError::InvalidAuthorityForSchedule.abort();
        }
        require_non_zero(a);
    }
}

fn validate_single_create(params: &CreateScheduleParams) {
    require_non_zero(params.creator_holding);
    require_non_zero(params.beneficiary);
    require_asset(params.asset);
    require_non_zero(params.refund_holding);
    validate_authorities(
        params.cancelable,
        &params.kind,
        params.cancel_authority,
        params.milestone_authority,
    );
    let broker_bps = match &params.broker {
        Some(b) => {
            require_non_zero(b.holding);
            b.bps
        }
        None => 0,
    };
    validate_schedule_params(params.total_amount, &params.kind, 0, broker_bps)
        .unwrap_or_else(|e| e.abort());
}

fn validate_batch_create(params: &BatchCreateParams) -> u128 {
    require_non_zero(params.creator_holding);
    require_asset(params.asset);
    require_non_zero(params.refund_holding);
    if params.items.is_empty() {
        VestingError::EmptyBatch.abort();
    }
    if let Some(b) = &params.broker {
        require_non_zero(b.holding);
        if b.bps > MAX_BROKER_FEE_BPS {
            VestingError::FeeRateExceedsCap {
                bps: b.bps,
                max_bps: MAX_BROKER_FEE_BPS,
            }
            .abort();
        }
    }
    let mut sum = 0u128;
    for item in &params.items {
        require_non_zero(item.beneficiary);
        validate_authorities(
            item.cancelable,
            &item.kind,
            item.cancel_authority,
            item.milestone_authority,
        );
        validate_schedule_params(item.total_amount, &item.kind, 0, 0).unwrap_or_else(|e| e.abort());
        sum = sum
            .checked_add(item.total_amount)
            .unwrap_or_else(|| VestingError::ArithmeticOverflow.abort());
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
        asset: schedule.asset,
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
