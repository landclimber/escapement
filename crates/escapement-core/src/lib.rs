//! Shared types, PDA derivations, messages, events, errors, and pure vesting math
//! for the Escapement LEZ v0.4 token vesting program.

pub mod event;
pub mod math;

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::AccountId, program::PdaSeed};
use lez_admin_authority::{Admin, AuthoritySlot, Gated, HasSlot};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};

/// Basis points denominator (100% = 10_000 bps).
pub const BPS_DENOMINATOR: u16 = 10_000;
/// Immutable compile-time ceiling on protocol creation fees (1.00%).
pub const MAX_PROTOCOL_FEE_BPS: u16 = 100;
/// Immutable compile-time ceiling on integrator broker fees (5.00%).
pub const MAX_BROKER_FEE_BPS: u16 = 500;
/// Maximum number of discrete milestone tranches per schedule.
pub const MAX_MILESTONES: usize = 64;
/// Reserved config PDA seed used by `lez-admin-authority`.
pub const CONFIG_SEED: PdaSeed = lez_admin_authority::seed(b"escapement/config/v1");

/// Zero account id sentinel rejected as beneficiary/authority.
pub const ZERO_ACCOUNT_ID: AccountId = AccountId::new([0u8; 32]);

/// Global protocol configuration stored at `config_account(program_id, &CONFIG_SEED)`.
///
/// `token_program_id` is write-once (immutable once set on initial `Configure`).
/// `admin` is exclusively managed by `lez-admin-authority` (Init / Nominate / Accept / Renounce).
#[derive(Debug, Default, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, HasSlot)]
pub struct Config {
    pub token_program_id: Option<AccountId>,
    pub fee_bps: u16,
    pub fee_treasury: Option<AccountId>,
    #[slot(Admin)]
    pub admin: AuthoritySlot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct MilestoneTranche {
    pub amount: u128,
    pub unlocked: bool,
    pub unlocked_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum ScheduleKind {
    CliffLinear {
        start_ts: u64,
        cliff_ts: u64,
        end_ts: u64,
        cliff_amount: u128,
    },
    Linear {
        start_ts: u64,
        end_ts: u64,
    },
    Milestone {
        tranches: Vec<MilestoneTranche>,
    },
}

impl ScheduleKind {
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::CliffLinear { .. } => 0,
            Self::Linear { .. } => 1,
            Self::Milestone { .. } => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CancellationRecord {
    pub cancelled_at_ms: u64,
    pub vested_at_cancel: u128,
    pub refunded_amount: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BrokerFee {
    pub holding: AccountId,
    pub bps: u16,
}

/// Persistent schedule state on a schedule PDA actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ScheduleAccount {
    pub version: u8,
    pub token_program_id: AccountId,
    pub creator: AccountId,
    pub beneficiary: AccountId,
    pub token_definition: AccountId,
    pub escrow_seed: PdaSeed,
    pub escrow_account: AccountId,
    pub refund_holding: AccountId,
    pub total_amount: u128,
    pub claimed_amount: u128,
    pub kind: ScheduleKind,
    pub cancelable: bool,
    pub transferable: bool,
    pub cancel_authority: Option<AccountId>,
    pub milestone_authority: Option<AccountId>,
    pub cancelled: Option<CancellationRecord>,
}

impl ScheduleAccount {
    #[must_use]
    pub fn effective_cancel_authority(&self) -> AccountId {
        self.cancel_authority.unwrap_or(self.creator)
    }

    #[must_use]
    pub fn effective_milestone_authority(&self) -> AccountId {
        self.milestone_authority.unwrap_or(self.creator)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CreateScheduleParams {
    pub salt: [u8; 32],
    pub token_definition: AccountId,
    pub creator_holding: AccountId,
    pub refund_holding: AccountId,
    pub beneficiary: AccountId,
    pub total_amount: u128,
    pub kind: ScheduleKind,
    pub cancelable: bool,
    pub transferable: bool,
    pub cancel_authority: Option<AccountId>,
    pub milestone_authority: Option<AccountId>,
    pub broker: Option<BrokerFee>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BatchRecipient {
    pub beneficiary: AccountId,
    pub total_amount: u128,
    pub kind: ScheduleKind,
    pub cancelable: bool,
    pub transferable: bool,
    pub cancel_authority: Option<AccountId>,
    pub milestone_authority: Option<AccountId>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BatchCreateParams {
    pub batch_id: [u8; 32],
    pub token_definition: AccountId,
    pub creator_holding: AccountId,
    pub refund_holding: AccountId,
    pub broker: Option<BrokerFee>,
    pub items: Vec<BatchRecipient>,
}

/// Transient state while a schedule or batch actor awaits a synchronous `StateReply` or `clock` reply.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum PendingOp {
    CreateReadConfig {
        creator: AccountId,
        params: Box<CreateScheduleParams>,
    },
    CreateVerifyRefund {
        creator: AccountId,
        token_program_id: AccountId,
        protocol_fee: u128,
        fee_treasury: Option<AccountId>,
        broker_fee: u128,
        params: Box<CreateScheduleParams>,
    },
    CreateVerifyEscrowPre {
        creator: AccountId,
        token_program_id: AccountId,
        escrow_seed: PdaSeed,
        escrow_account: AccountId,
        protocol_fee: u128,
        fee_treasury: Option<AccountId>,
        broker_fee: u128,
        params: Box<CreateScheduleParams>,
    },
    CreateVerifyEscrowPost {
        creator: AccountId,
        token_program_id: AccountId,
        escrow_seed: PdaSeed,
        escrow_account: AccountId,
        pre_balance: u128,
        params: Box<CreateScheduleParams>,
    },
    BatchReadConfig {
        creator: AccountId,
        total_batch_amount: u128,
        params: Box<BatchCreateParams>,
    },
    BatchVerifyRefund {
        creator: AccountId,
        token_program_id: AccountId,
        total_batch_amount: u128,
        protocol_fee: u128,
        fee_treasury: Option<AccountId>,
        broker_fee: u128,
        params: Box<BatchCreateParams>,
    },
    BatchVerifyEscrowPre {
        creator: AccountId,
        token_program_id: AccountId,
        escrow_seed: PdaSeed,
        escrow_account: AccountId,
        total_batch_amount: u128,
        protocol_fee: u128,
        fee_treasury: Option<AccountId>,
        broker_fee: u128,
        params: Box<BatchCreateParams>,
    },
    BatchVerifyEscrowPost {
        creator: AccountId,
        token_program_id: AccountId,
        escrow_seed: PdaSeed,
        escrow_account: AccountId,
        total_batch_amount: u128,
        pre_balance: u128,
        params: Box<BatchCreateParams>,
    },
    ClaimPublicReadClock {
        schedule: Box<ScheduleAccount>,
        destination: AccountId,
        requested_amount: Option<u128>,
    },
    CancelReadClock {
        schedule: Box<ScheduleAccount>,
        cancelled_by: AccountId,
    },
    SignalMilestoneReadClock {
        schedule: Box<ScheduleAccount>,
        milestone_index: u8,
        signaled_by: AccountId,
    },
}

/// Actor state stored on every non-config Escapement actor.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum VestingActorState {
    Schedule(Box<ScheduleAccount>),
    BatchCommitted {
        creator: AccountId,
        batch_id: [u8; 32],
        count: u32,
        total_amount: u128,
    },
    Pending(Box<PendingOp>),
}

impl VestingActorState {
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        Some(borsh::from_slice(bytes).expect("vesting actor state must decode"))
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("vesting actor state serialization is infallible")
    }
}

/// Public client-facing messages (guarded by `lez-admin-authority`).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Gated)]
pub enum Message {
    /// Admin-only protocol setup / fee switch update. `token_program_id` is write-once.
    #[only(Admin)]
    Configure {
        token_program_id: Option<AccountId>,
        fee_bps: u16,
        fee_treasury: Option<AccountId>,
    },
    /// Create and atomically fund one vesting schedule (sent to creator's actor).
    CreateSchedule(Box<CreateScheduleParams>),
    /// Create and atomically fund multiple schedules over one shared batch escrow (sent to creator's actor).
    BatchCreate(Box<BatchCreateParams>),
    /// Public claim reading live `clock_actor()` (sent to beneficiary's actor).
    ClaimPublic {
        schedule_id: AccountId,
        destination: AccountId,
        amount: Option<u128>,
    },
    /// Exact claim using `Response::timestamp_window(effective_ts..)` — safe for private PPTX claims.
    ClaimExact {
        schedule_id: AccountId,
        destination: AccountId,
        amount: u128,
        effective_ts: u64,
    },
    /// Cancel a cancelable schedule using live `clock_actor()` (sent to cancel authority's actor).
    Cancel {
        schedule_id: AccountId,
    },
    /// Irreversibly convert a cancelable schedule to non-cancelable (sent to cancel authority's actor).
    MakeNonCancelable {
        schedule_id: AccountId,
    },
    /// Unlock a discrete milestone tranche (sent to milestone authority's actor).
    SignalMilestone {
        schedule_id: AccountId,
        milestone_index: u8,
    },
    /// Transfer beneficiary rights when `transferable == true` (sent to beneficiary's actor).
    TransferBeneficiary {
        schedule_id: AccountId,
        new_beneficiary: AccountId,
    },
    /// Read any actor's state via `StateReply`.
    ReadState,
}

/// Internal messages decoded only when `input.from_own_program()` is true (tag byte < 255).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Internal {
    ReadConfig,
    CreateSingle {
        creator: AccountId,
        params: Box<CreateScheduleParams>,
    },
    CreateBatchCoord {
        creator: AccountId,
        params: Box<BatchCreateParams>,
    },
    InitBatchSchedule {
        batch_id: [u8; 32],
        schedule: Box<ScheduleAccount>,
    },
    ClaimPublic {
        destination: AccountId,
        amount: Option<u128>,
    },
    ClaimExact {
        destination: AccountId,
        amount: u128,
        effective_ts: u64,
    },
    Cancel,
    MakeNonCancelable,
    SignalMilestone {
        milestone_index: u8,
    },
    TransferBeneficiary {
        new_beneficiary: AccountId,
    },
}

/// Typed deterministic errors shared by guest, SDK, CLI, and UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VestingError {
    ZeroAmount,
    InvalidTimeRange,
    InvalidCliffAmount,
    InvalidMilestoneCount,
    InvalidMilestoneTranche,
    MilestoneSumMismatch,
    FeeRateExceedsCap { bps: u16, max_bps: u16 },
    FeeTreasuryRequired,
    TokenProgramImmutable,
    TokenProgramNotConfigured,
    ZeroAddress,
    EmptyBatch,
    Unauthorized,
    ScheduleAlreadyExists,
    BatchAlreadyExists,
    NotASchedule,
    NotCancelable,
    AlreadyCancelled,
    AlreadyNonCancelable,
    AlreadyFullyVested,
    NotTransferable,
    SameBeneficiary,
    NotMilestoneSchedule,
    MilestoneIndexOutOfBounds,
    MilestoneAlreadyUnlocked(u8),
    NothingClaimable { next_unlock_ts: Option<u64> },
    ExceedsClaimable { requested: u128, claimable: u128 },
    InvalidRefundHolding,
    EscrowFundingMismatch { expected: u128, actual: u128 },
    ArithmeticOverflow,
}

impl VestingError {
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::ZeroAmount => "E001: amount must be positive".into(),
            Self::InvalidTimeRange => "E002: invalid schedule time range".into(),
            Self::InvalidCliffAmount => "E003: invalid cliff amount".into(),
            Self::InvalidMilestoneCount => "E004: milestone count must be in 1..=64".into(),
            Self::InvalidMilestoneTranche => "E005: milestone tranche must be positive and locked".into(),
            Self::MilestoneSumMismatch => "E006: milestone tranche sum must equal total_amount".into(),
            Self::FeeRateExceedsCap { bps, max_bps } => {
                format!("E007: fee rate {bps} bps exceeds cap {max_bps} bps")
            }
            Self::FeeTreasuryRequired => "E008: fee_treasury is required when fee_bps > 0".into(),
            Self::TokenProgramImmutable => "E009: token_program_id is write-once and immutable".into(),
            Self::TokenProgramNotConfigured => "E010: token_program_id is not configured".into(),
            Self::ZeroAddress => "E011: zero address is not permitted".into(),
            Self::EmptyBatch => "E012: batch must contain at least one recipient".into(),
            Self::Unauthorized => "E013: caller is not authorized".into(),
            Self::ScheduleAlreadyExists => "E014: schedule already exists".into(),
            Self::BatchAlreadyExists => "E015: batch_id already exists".into(),
            Self::NotASchedule => "E016: account does not hold an active schedule".into(),
            Self::NotCancelable => "E017: schedule is not cancelable".into(),
            Self::AlreadyCancelled => "E018: schedule is already cancelled".into(),
            Self::AlreadyNonCancelable => "E019: schedule is already non-cancelable".into(),
            Self::AlreadyFullyVested => "E020: schedule is already fully vested; nothing to cancel".into(),
            Self::NotTransferable => "E021: schedule is non-transferable".into(),
            Self::SameBeneficiary => "E022: new_beneficiary equals current beneficiary".into(),
            Self::NotMilestoneSchedule => "E023: schedule is not milestone-based".into(),
            Self::MilestoneIndexOutOfBounds => "E024: milestone index out of bounds".into(),
            Self::MilestoneAlreadyUnlocked(idx) => {
                format!("E025: milestone index {idx} is already unlocked")
            }
            Self::NothingClaimable { next_unlock_ts } => match next_unlock_ts {
                Some(ts) => format!("E026: nothing claimable yet; next unlock at {ts} ms"),
                None => "E026: nothing claimable (awaiting milestone signal or fully claimed)".into(),
            },
            Self::ExceedsClaimable {
                requested,
                claimable,
            } => format!("E027: requested {requested} exceeds claimable {claimable}"),
            Self::InvalidRefundHolding => {
                "E028: refund_holding must be an initialized token holding for token_definition".into()
            }
            Self::EscrowFundingMismatch { expected, actual } => {
                format!("E029: escrow delta {actual} does not match expected {expected}")
            }
            Self::ArithmeticOverflow => "E030: arithmetic overflow".into(),
        }
    }

    pub fn panic_with(&self) -> ! {
        panic!("{}", self.message())
    }
}

fn hash_seed(parts: &[&[u8]]) -> PdaSeed {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(p);
    }
    let digest = Impl::hash_bytes(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    PdaSeed::new(out)
}

#[must_use]
pub fn config_pda(program_id: AccountId) -> AccountId {
    lez_admin_authority::config_account(program_id, &CONFIG_SEED)
}

#[must_use]
pub fn schedule_seed(creator: &AccountId, salt: &[u8; 32]) -> PdaSeed {
    hash_seed(&[b"escapement/sched/v1", creator.value(), salt])
}

#[must_use]
pub fn schedule_pda(program_id: AccountId, creator: &AccountId, salt: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(&program_id, &schedule_seed(creator, salt))
}

#[must_use]
pub fn single_escrow_seed(schedule_id: &AccountId) -> PdaSeed {
    hash_seed(&[b"escapement/escrow/v1", schedule_id.value()])
}

#[must_use]
pub fn single_escrow_pda(program_id: AccountId, schedule_id: &AccountId) -> AccountId {
    AccountId::for_public_pda(&program_id, &single_escrow_seed(schedule_id))
}

#[must_use]
pub fn batch_coord_seed(creator: &AccountId, batch_id: &[u8; 32]) -> PdaSeed {
    hash_seed(&[b"escapement/batch/v1", creator.value(), batch_id])
}

#[must_use]
pub fn batch_coord_pda(
    program_id: AccountId,
    creator: &AccountId,
    batch_id: &[u8; 32],
) -> AccountId {
    AccountId::for_public_pda(&program_id, &batch_coord_seed(creator, batch_id))
}

#[must_use]
pub fn batch_escrow_seed(creator: &AccountId, batch_id: &[u8; 32]) -> PdaSeed {
    hash_seed(&[b"escapement/bescrow/v1", creator.value(), batch_id])
}

#[must_use]
pub fn batch_escrow_pda(
    program_id: AccountId,
    creator: &AccountId,
    batch_id: &[u8; 32],
) -> AccountId {
    AccountId::for_public_pda(&program_id, &batch_escrow_seed(creator, batch_id))
}

#[must_use]
pub fn batch_schedule_seed(creator: &AccountId, batch_id: &[u8; 32], index: u32) -> PdaSeed {
    hash_seed(&[
        b"escapement/bsched/v1",
        creator.value(),
        batch_id,
        &index.to_le_bytes(),
    ])
}

#[must_use]
pub fn batch_schedule_pda(
    program_id: AccountId,
    creator: &AccountId,
    batch_id: &[u8; 32],
    index: u32,
) -> AccountId {
    AccountId::for_public_pda(&program_id, &batch_schedule_seed(creator, batch_id, index))
}
