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
/// Reserved config PDA seed used by `lez-admin-authority` (32-byte zero-padded label).
pub const CONFIG_SEED: PdaSeed = lez_admin_authority::seed(b"escapement/config/v1");

/// Zero account id sentinel rejected as beneficiary/authority/destination.
pub const ZERO_ACCOUNT_ID: AccountId = AccountId::new([0u8; 32]);

/// LEZ v0.4's hardcoded native token program address (`lee_core::native_token::NATIVE_TOKEN_PROGRAM_ID`).
/// A native balance lives at the actor `(account, NATIVE_PROGRAM_ID)`.
pub const NATIVE_PROGRAM_ID: AccountId = AccountId::new([0u8; 32]);

/// The asset a schedule escrows: the native LEZ balance, or one fungible token definition of the
/// configured (write-once) token program.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum Asset {
    Native,
    Token { definition: AccountId },
}

impl Asset {
    /// Key used for per-asset PDAs (fee vaults): the token definition, or the zero id for native.
    #[must_use]
    pub const fn key(&self) -> AccountId {
        match self {
            Self::Native => NATIVE_PROGRAM_ID,
            Self::Token { definition } => *definition,
        }
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }
}

/// Global protocol configuration stored at `config_account(program_id, &CONFIG_SEED)`.
///
/// - `token_program_id` is write-once (immutable once set on initial `Configure`).
/// - `fee_treasury` is the authorized controller allowed to withdraw accrued fees from
///   each per-asset protocol fee vault PDA (`fee_vault_pda(program_id, &asset.key())`).
/// - Native schedules need only an initialized config; token schedules need `token_program_id`.
/// - `admin` is exclusively managed by `lez-admin-authority` (Init / Nominate / Accept / Renounce).
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

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
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
    /// Program holding the escrowed balance: `NATIVE_PROGRAM_ID` for `Asset::Native`, else the
    /// configured token program at creation time.
    pub asset_program_id: AccountId,
    pub creator: AccountId,
    pub beneficiary: AccountId,
    pub asset: Asset,
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
    pub asset: Asset,
    /// Token holding funding the schedule; for `Asset::Native` it must be the creator itself.
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
    pub asset: Asset,
    /// Token holding funding the batch; for `Asset::Native` it must be the creator itself.
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
        asset_program_id: AccountId,
        protocol_fee: u128,
        broker_fee: u128,
        params: Box<CreateScheduleParams>,
    },
    CreateVerifyEscrowPre {
        creator: AccountId,
        asset_program_id: AccountId,
        escrow_seed: PdaSeed,
        escrow_account: AccountId,
        protocol_fee: u128,
        broker_fee: u128,
        params: Box<CreateScheduleParams>,
    },
    CreateVerifyEscrowPost {
        creator: AccountId,
        asset_program_id: AccountId,
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
        asset_program_id: AccountId,
        total_batch_amount: u128,
        protocol_fee: u128,
        broker_fee: u128,
        params: Box<BatchCreateParams>,
    },
    BatchVerifyEscrowPre {
        creator: AccountId,
        asset_program_id: AccountId,
        escrow_seed: PdaSeed,
        escrow_account: AccountId,
        total_batch_amount: u128,
        protocol_fee: u128,
        broker_fee: u128,
        params: Box<BatchCreateParams>,
    },
    BatchVerifyEscrowPost {
        creator: AccountId,
        asset_program_id: AccountId,
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
        borsh::from_slice(bytes).ok()
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
    /// Withdraw accrued creation fees from a per-asset fee vault PDA (authorized by `config.fee_treasury`).
    WithdrawFees {
        asset: Asset,
        destination: AccountId,
        amount: u128,
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
    Cancel { schedule_id: AccountId },
    /// Irreversibly convert a cancelable schedule to non-cancelable (sent to cancel authority's actor).
    MakeNonCancelable { schedule_id: AccountId },
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
    /// A user transition sent by another program as one of its own PDAs (a multisig, DAO or
    /// launchpad vault). Accepted only when the immediate sender's program derives the receiving
    /// account from `seed` (`for_public_pda(sender_program, seed) == receiver`), so neither a
    /// signer's authority nor an inherited seed grant can be relayed by a third program.
    AsPda { seed: PdaSeed, call: Box<PdaCall> },
}

/// User transitions a program may send as its own PDA through `Message::AsPda`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum PdaCall {
    WithdrawFees {
        asset: Asset,
        destination: AccountId,
        amount: u128,
    },
    CreateSchedule(Box<CreateScheduleParams>),
    BatchCreate(Box<BatchCreateParams>),
    ClaimPublic {
        schedule_id: AccountId,
        destination: AccountId,
        amount: Option<u128>,
    },
    ClaimExact {
        schedule_id: AccountId,
        destination: AccountId,
        amount: u128,
        effective_ts: u64,
    },
    Cancel {
        schedule_id: AccountId,
    },
    MakeNonCancelable {
        schedule_id: AccountId,
    },
    SignalMilestone {
        schedule_id: AccountId,
        milestone_index: u8,
    },
    TransferBeneficiary {
        schedule_id: AccountId,
        new_beneficiary: AccountId,
    },
}

impl From<PdaCall> for Message {
    fn from(call: PdaCall) -> Self {
        match call {
            PdaCall::WithdrawFees {
                asset,
                destination,
                amount,
            } => Self::WithdrawFees {
                asset,
                destination,
                amount,
            },
            PdaCall::CreateSchedule(p) => Self::CreateSchedule(p),
            PdaCall::BatchCreate(p) => Self::BatchCreate(p),
            PdaCall::ClaimPublic {
                schedule_id,
                destination,
                amount,
            } => Self::ClaimPublic {
                schedule_id,
                destination,
                amount,
            },
            PdaCall::ClaimExact {
                schedule_id,
                destination,
                amount,
                effective_ts,
            } => Self::ClaimExact {
                schedule_id,
                destination,
                amount,
                effective_ts,
            },
            PdaCall::Cancel { schedule_id } => Self::Cancel { schedule_id },
            PdaCall::MakeNonCancelable { schedule_id } => Self::MakeNonCancelable { schedule_id },
            PdaCall::SignalMilestone {
                schedule_id,
                milestone_index,
            } => Self::SignalMilestone {
                schedule_id,
                milestone_index,
            },
            PdaCall::TransferBeneficiary {
                schedule_id,
                new_beneficiary,
            } => Self::TransferBeneficiary {
                schedule_id,
                new_beneficiary,
            },
        }
    }
}

/// Internal messages decoded only when `input.from_own_program()` is true (tag byte < 255).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Internal {
    ReadConfig,
    /// No-op delivered with a fee vault's seed so LEZ admits the vault account before a native
    /// fee credit reaches it (native balances need no holding initialization).
    AdmitFeeVault {
        asset_key: AccountId,
    },
    WithdrawFees {
        asset: Asset,
        destination: AccountId,
        amount: u128,
    },
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
    InvalidDestination,
    MalformedMessage,
    InvalidAuthorityForSchedule,
    InvalidTokenProgram,
    NotRootOrDirectPda,
}

impl VestingError {
    /// Deterministic non-zero guest exit code (`1..=35`).
    ///
    /// On LEZ v0.4, exiting with a non-zero code (`env::exit(code)`) produces
    /// `LeeError::ProgramExitedWithCode { code, cycles }` and bills only metered cycles
    /// executed rather than burning the caller's entire declared `gas_limit`.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Self::ZeroAmount => 1,
            Self::InvalidTimeRange => 2,
            Self::InvalidCliffAmount => 3,
            Self::InvalidMilestoneCount => 4,
            Self::InvalidMilestoneTranche => 5,
            Self::MilestoneSumMismatch => 6,
            Self::FeeRateExceedsCap { .. } => 7,
            Self::FeeTreasuryRequired => 8,
            Self::TokenProgramImmutable => 9,
            Self::TokenProgramNotConfigured => 10,
            Self::ZeroAddress => 11,
            Self::EmptyBatch => 12,
            Self::Unauthorized => 13,
            Self::ScheduleAlreadyExists => 14,
            Self::BatchAlreadyExists => 15,
            Self::NotASchedule => 16,
            Self::NotCancelable => 17,
            Self::AlreadyCancelled => 18,
            Self::AlreadyNonCancelable => 19,
            Self::AlreadyFullyVested => 20,
            Self::NotTransferable => 21,
            Self::SameBeneficiary => 22,
            Self::NotMilestoneSchedule => 23,
            Self::MilestoneIndexOutOfBounds => 24,
            Self::MilestoneAlreadyUnlocked(_) => 25,
            Self::NothingClaimable { .. } => 26,
            Self::ExceedsClaimable { .. } => 27,
            Self::InvalidRefundHolding => 28,
            Self::EscrowFundingMismatch { .. } => 29,
            Self::ArithmeticOverflow => 30,
            Self::InvalidDestination => 31,
            Self::MalformedMessage => 32,
            Self::InvalidAuthorityForSchedule => 33,
            Self::InvalidTokenProgram => 34,
            Self::NotRootOrDirectPda => 35,
        }
    }

    /// Maps a non-zero guest exit code back to a static human-readable label.
    #[must_use]
    pub const fn describe_code(code: u32) -> &'static str {
        match code {
            1 => "E001: amount must be positive",
            2 => "E002: invalid schedule time range",
            3 => "E003: invalid cliff amount",
            4 => "E004: milestone count must be in 1..=64",
            5 => "E005: milestone tranche must be positive and locked",
            6 => "E006: milestone tranche sum must equal total_amount",
            7 => "E007: fee rate exceeds immutable cap",
            8 => "E008: fee_treasury is required when fee_bps > 0",
            9 => "E009: token_program_id is write-once and immutable",
            10 => "E010: token_program_id is not configured",
            11 => "E011: zero address is not permitted",
            12 => "E012: batch must contain at least one recipient",
            13 => "E013: caller is not authorized",
            14 => "E014: schedule already exists",
            15 => "E015: batch_id already exists",
            16 => "E016: account does not hold an active schedule",
            17 => "E017: schedule is not cancelable",
            18 => "E018: schedule is already cancelled",
            19 => "E019: schedule is already non-cancelable",
            20 => "E020: schedule is already fully vested; nothing to cancel",
            21 => "E021: schedule is non-transferable",
            22 => "E022: new_beneficiary equals current beneficiary",
            23 => "E023: schedule is not milestone-based",
            24 => "E024: milestone index out of bounds",
            25 => "E025: milestone index is already unlocked",
            26 => "E026: nothing claimable yet",
            27 => "E027: requested amount exceeds claimable",
            28 => "E028: refund_holding is not a valid refund account for this asset",
            29 => "E029: escrow delta does not match expected deposit",
            30 => "E030: arithmetic overflow",
            31 => "E031: invalid destination or beneficiary PDA self-lock",
            32 => "E032: malformed message or missing sender",
            33 => "E033: authority option is invalid for this schedule configuration",
            34 => "E034: invalid token_program_id",
            35 => {
                "E035: call must come from the signer directly or from the program owning this PDA"
            }
            _ => "E999: unknown vesting exit code",
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::ZeroAmount => "E001: amount must be positive".into(),
            Self::InvalidTimeRange => "E002: invalid schedule time range".into(),
            Self::InvalidCliffAmount => "E003: invalid cliff amount".into(),
            Self::InvalidMilestoneCount => "E004: milestone count must be in 1..=64".into(),
            Self::InvalidMilestoneTranche => {
                "E005: milestone tranche must be positive and locked".into()
            }
            Self::MilestoneSumMismatch => {
                "E006: milestone tranche sum must equal total_amount".into()
            }
            Self::FeeRateExceedsCap { bps, max_bps } => {
                format!("E007: fee rate {bps} bps exceeds cap {max_bps} bps")
            }
            Self::FeeTreasuryRequired => "E008: fee_treasury is required when fee_bps > 0".into(),
            Self::TokenProgramImmutable => {
                "E009: token_program_id is write-once and immutable".into()
            }
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
            Self::AlreadyFullyVested => {
                "E020: schedule is already fully vested; nothing to cancel".into()
            }
            Self::NotTransferable => "E021: schedule is non-transferable".into(),
            Self::SameBeneficiary => "E022: new_beneficiary equals current beneficiary".into(),
            Self::NotMilestoneSchedule => "E023: schedule is not milestone-based".into(),
            Self::MilestoneIndexOutOfBounds => "E024: milestone index out of bounds".into(),
            Self::MilestoneAlreadyUnlocked(idx) => {
                format!("E025: milestone index {idx} is already unlocked")
            }
            Self::NothingClaimable { next_unlock_ts } => match next_unlock_ts {
                Some(ts) => format!("E026: nothing claimable yet; next unlock at {ts} ms"),
                None => {
                    "E026: nothing claimable (awaiting milestone signal or fully claimed)".into()
                }
            },
            Self::ExceedsClaimable {
                requested,
                claimable,
            } => format!("E027: requested {requested} exceeds claimable {claimable}"),
            Self::InvalidRefundHolding => {
                "E028: refund_holding is not a valid refund account for this asset".into()
            }
            Self::EscrowFundingMismatch { expected, actual } => {
                format!("E029: escrow delta {actual} does not match expected {expected}")
            }
            Self::ArithmeticOverflow => "E030: arithmetic overflow".into(),
            Self::InvalidDestination => {
                "E031: invalid destination or beneficiary PDA self-lock".into()
            }
            Self::MalformedMessage => "E032: malformed message or missing sender".into(),
            Self::InvalidAuthorityForSchedule => {
                "E033: authority option is invalid for this schedule configuration".into()
            }
            Self::InvalidTokenProgram => "E034: invalid token_program_id".into(),
            Self::NotRootOrDirectPda => {
                "E035: call must come from the signer directly or from the program owning this PDA"
                    .into()
            }
        }
    }

    /// Terminates execution with a cycle-metered guest exit code on zkVM, or panics on host.
    pub fn abort(&self) -> ! {
        #[cfg(target_os = "zkvm")]
        {
            risc0_zkvm::guest::env::exit(self.code())
        }
        #[cfg(not(target_os = "zkvm"))]
        {
            panic!("{}", self.message())
        }
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

/// Deterministic per-asset protocol fee vault PDA seed (`asset_key = Asset::key()`).
///
/// LEZ v0.4 token holdings are single-token-per-account; routing protocol creation fees into
/// a dedicated per-asset PDA ensures multi-asset schedule creation always works
/// permissionlessly whenever `fee_bps > 0`, even after `AdminOp::Renounce`.
#[must_use]
pub fn fee_vault_seed(asset_key: &AccountId) -> PdaSeed {
    hash_seed(&[b"escapement/feevault/v1", asset_key.value()])
}

#[must_use]
pub fn fee_vault_pda(program_id: AccountId, asset_key: &AccountId) -> AccountId {
    AccountId::for_public_pda(&program_id, &fee_vault_seed(asset_key))
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
