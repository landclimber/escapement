//! Structured `ProgramEvent` types and compile-time 8-byte selectors for Escapement.
//!
//! Selectors follow LEZ's convention: `sha256("escapement::<EventName>")[..8]`.
//! Private destinations and blinded aliases are intentionally omitted from `Claimed` and `FeeWithdrawn`.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::AccountId, program::ProgramEvent};

use crate::Asset;
use risc0_zkvm::sha::{Impl, Sha256 as _};

pub trait VestingEvent: BorshSerialize {
    const NAME: &'static str;
    /// Precomputed `sha256("escapement::<NAME>")[..8]` — zero runtime hashing or allocation in guest.
    const SELECTOR: [u8; 8];

    #[must_use]
    fn to_program_event(&self) -> ProgramEvent {
        ProgramEvent {
            selector: Self::SELECTOR,
            data: borsh::to_vec(self).expect("borsh serialization of event is infallible"),
        }
    }
}

/// Reference SHA-256 selector derivation used by offchain tooling and unit tests to verify constants.
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
    pub asset: Asset,
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
    const SELECTOR: [u8; 8] = [25, 185, 161, 161, 180, 170, 107, 240];
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
    const SELECTOR: [u8; 8] = [182, 14, 75, 118, 213, 169, 126, 164];
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
    const SELECTOR: [u8; 8] = [7, 132, 91, 212, 214, 204, 37, 25];
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
    const SELECTOR: [u8; 8] = [223, 57, 15, 31, 158, 156, 122, 209];
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BeneficiaryTransferred {
    pub schedule_id: AccountId,
    pub old_beneficiary: AccountId,
    pub new_beneficiary: AccountId,
}

impl VestingEvent for BeneficiaryTransferred {
    const NAME: &'static str = "BeneficiaryTransferred";
    const SELECTOR: [u8; 8] = [224, 54, 194, 69, 41, 244, 191, 225];
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MadeNonCancelable {
    pub schedule_id: AccountId,
    pub by: AccountId,
}

impl VestingEvent for MadeNonCancelable {
    const NAME: &'static str = "MadeNonCancelable";
    const SELECTOR: [u8; 8] = [62, 163, 1, 169, 231, 1, 144, 194];
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeConfigUpdated {
    pub token_program_id: AccountId,
    pub fee_bps: u16,
    pub fee_treasury: Option<AccountId>,
}

impl VestingEvent for FeeConfigUpdated {
    const NAME: &'static str = "FeeConfigUpdated";
    const SELECTOR: [u8; 8] = [39, 110, 61, 35, 80, 218, 24, 101];
}

/// Emitted when `fee_treasury` withdraws accrued creation fees from a per-asset fee vault PDA.
/// Omits destination so treasury sweeps can target either public or private accounts.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeWithdrawn {
    pub asset: Asset,
    pub amount: u128,
    pub withdrawn_by: AccountId,
}

impl VestingEvent for FeeWithdrawn {
    const NAME: &'static str = "FeeWithdrawn";
    const SELECTOR: [u8; 8] = [142, 238, 4, 228, 212, 147, 236, 196];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_time_selectors_match_sha256() {
        assert_eq!(ScheduleCreated::SELECTOR, selector(ScheduleCreated::NAME));
        assert_eq!(Claimed::SELECTOR, selector(Claimed::NAME));
        assert_eq!(Cancelled::SELECTOR, selector(Cancelled::NAME));
        assert_eq!(
            MilestoneSignaled::SELECTOR,
            selector(MilestoneSignaled::NAME)
        );
        assert_eq!(
            BeneficiaryTransferred::SELECTOR,
            selector(BeneficiaryTransferred::NAME)
        );
        assert_eq!(
            MadeNonCancelable::SELECTOR,
            selector(MadeNonCancelable::NAME)
        );
        assert_eq!(FeeConfigUpdated::SELECTOR, selector(FeeConfigUpdated::NAME));
        assert_eq!(FeeWithdrawn::SELECTOR, selector(FeeWithdrawn::NAME));
    }
}
