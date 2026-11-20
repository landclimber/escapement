//! Structured `ProgramEvent` types and deterministic 8-byte selectors for Escapement.
//!
//! Selectors follow LEZ's convention: `sha256("escapement::<EventName>")[..8]`.
//! Private destinations and blinded aliases are intentionally omitted from `Claimed`.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::AccountId, program::ProgramEvent};
use risc0_zkvm::sha::{Impl, Sha256 as _};

pub trait VestingEvent: BorshSerialize {
    const NAME: &'static str;

    #[must_use]
    fn to_program_event(&self) -> ProgramEvent {
        ProgramEvent {
            selector: selector(Self::NAME),
            data: borsh::to_vec(self).expect("borsh serialization of event is infallible"),
        }
    }
}

#[must_use]
pub fn selector(name: &str) -> [u8; 8] {
    let mut input = Vec::with_capacity(12 + name.len());
    input.extend_from_slice(b"escapement::");
    input.extend_from_slice(name.as_bytes());
    let digest = Impl::hash_bytes(&input);
    let bytes = digest.as_bytes();
    [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ScheduleCreated {
    pub schedule_id: AccountId,
    pub batch_id: Option<[u8; 32]>,
    pub creator: AccountId,
    pub beneficiary: AccountId,
    pub token_definition: AccountId,
    pub escrow_account: AccountId,
    pub refund_holding: AccountId,
    pub total_amount: u128,
    pub kind_tag: u8,
    pub cancelable: bool,
    pub transferable: bool,
    pub cancel_authority: Option<AccountId>,
    pub milestone_authority: Option<AccountId>,
}

impl VestingEvent for ScheduleCreated {
    const NAME: &'static str = "ScheduleCreated";
}

/// Emitted on every claim (public or private). Never contains the destination private
/// account or blinded alias.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Claimed {
    pub schedule_id: AccountId,
    pub beneficiary: AccountId,
    pub amount: u128,
    pub total_claimed: u128,
    pub timestamp_ms: u64,
}

impl VestingEvent for Claimed {
    const NAME: &'static str = "Claimed";
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Cancelled {
    pub schedule_id: AccountId,
    pub cancelled_by: AccountId,
    pub cancelled_at_ms: u64,
    pub vested_at_cancel: u128,
    pub refunded_amount: u128,
    pub refund_holding: AccountId,
}

impl VestingEvent for Cancelled {
    const NAME: &'static str = "Cancelled";
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MilestoneSignaled {
    pub schedule_id: AccountId,
    pub milestone_index: u8,
    pub amount_unlocked: u128,
    pub signaled_by: AccountId,
    pub unlocked_at_ms: u64,
}

impl VestingEvent for MilestoneSignaled {
    const NAME: &'static str = "MilestoneSignaled";
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BeneficiaryTransferred {
    pub schedule_id: AccountId,
    pub old_beneficiary: AccountId,
    pub new_beneficiary: AccountId,
}

impl VestingEvent for BeneficiaryTransferred {
    const NAME: &'static str = "BeneficiaryTransferred";
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MadeNonCancelable {
    pub schedule_id: AccountId,
    pub by: AccountId,
}

impl VestingEvent for MadeNonCancelable {
    const NAME: &'static str = "MadeNonCancelable";
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeConfigUpdated {
    pub token_program_id: AccountId,
    pub fee_bps: u16,
    pub fee_treasury: Option<AccountId>,
}

impl VestingEvent for FeeConfigUpdated {
    const NAME: &'static str = "FeeConfigUpdated";
}
