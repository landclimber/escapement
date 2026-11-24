//! Errors the SDK returns before a transaction is proven or sent, and program refusals after.

use lee_core::account::AccountId;

use crate::{codes::Refusal, unlock::NextUnlockReason};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SdkError {
    /// The private-claim path was given a target that is not a private (shielded) account.
    #[error(
        "{account_id} is not a private account ({reason}). A private claim must go to a private \
         account of your wallet; choose one, or claim to a public account instead."
    )]
    NonShieldedPrivateTarget {
        account_id: AccountId,
        reason: &'static str,
    },

    /// Nothing is claimable now.
    #[error("{}", nothing_claimable_message(*next_unlock_ms, reason))]
    NothingClaimableYet {
        next_unlock_ms: Option<u64>,
        reason: NextUnlockReason,
    },

    /// The requested amount is more than is claimable now.
    #[error("You asked to claim {requested} but only {claimable} is claimable now; claim at most {claimable}.")]
    ExceedsClaimable { requested: u128, claimable: u128 },

    /// A zero claim amount.
    #[error("A claim amount must be positive.")]
    ZeroAmount,

    /// The private fee payer cannot cover the in-proof fee reserve.
    #[error(
        "The private fee payer holds {available} but this private claim needs a fee reserve of \
         {required} (short by {shortfall}). Move at least {shortfall} native units to that private \
         account, or claim to a public account instead. Nothing was proven or sent."
    )]
    InsufficientPrivateGas {
        required: u128,
        available: u128,
        shortfall: u128,
    },

    /// The caller did not confirm the privacy disclosure shown for this exact claim.
    #[error(
        "The privacy disclosure for this claim was not confirmed. Show it to the user and pass the \
         confirmation token of that disclosure (CLI: --accept-privacy-disclosure after reading it)."
    )]
    PrivacyDisclosureNotConfirmed,

    /// The caller is not the schedule's beneficiary.
    #[error("Only the beneficiary {beneficiary} can claim from this schedule.")]
    NotBeneficiary { beneficiary: AccountId },

    /// A batch larger than the measured single-transaction ceiling was given to a one-shot call.
    #[error("A batch of {requested} exceeds the {ceiling} schedules that fit in one transaction; use batch_create_chunked.")]
    BatchTooLarge { requested: usize, ceiling: usize },

    /// The program refused the transaction with an exit code.
    #[error("The vesting program refused the transaction: {}", .0.message)]
    Refused(Refusal),
}

fn nothing_claimable_message(next_unlock_ms: Option<u64>, reason: &NextUnlockReason) -> String {
    let when = next_unlock_ms.map_or_else(String::new, |ms| {
        format!(" Next unlock at {} (unix ms {ms}).", crate::unlock::utc(ms))
    });
    format!("Nothing is claimable yet: {}.{when}", reason.describe())
}
