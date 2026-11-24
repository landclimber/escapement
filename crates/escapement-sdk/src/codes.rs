//! The program's refusal codes (`env::exit(code)`, LEZ reports `ProgramExitedWithCode { code, cycles }`
//! and charges only the cycles used), each with a message a user can act on (U7).

use escapement_core::VestingError;

/// One refusal, as the SDK reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: u8,
    pub name: &'static str,
    /// What went wrong and what to do.
    pub message: &'static str,
    /// True when retrying later can succeed with no change (e.g. after the next unlock).
    pub retry_later: bool,
}

/// `(code, name, message, retry_later)` for every `VestingError` code.
pub const TABLE: [(u8, &str, &str, bool); 35] = [
    (1, "ZeroAmount", "An amount is zero (a schedule total, a claim or a withdrawal); give a positive amount.", false),
    (2, "InvalidTimeRange", "The schedule's times are out of order: they must satisfy start <= cliff <= end and start < end.", false),
    (3, "InvalidCliffAmount", "The cliff amount must be at most the total (and zero when the cliff is at the start).", false),
    (4, "InvalidMilestoneCount", "A milestone schedule needs 1 to 64 tranches.", false),
    (5, "InvalidMilestoneTranche", "Every milestone tranche must be positive and not yet unlocked at creation.", false),
    (6, "MilestoneSumMismatch", "The milestone tranches must add up to the schedule's total.", false),
    (7, "FeeRateExceedsCap", "A fee rate is above its cap (protocol 100 bps, broker 500 bps); lower it.", false),
    (8, "FeeTreasuryRequired", "A non-zero protocol fee needs a fee treasury; set one.", false),
    (9, "TokenProgramImmutable", "The token program is fixed once configured; it cannot be changed.", false),
    (10, "TokenProgramNotConfigured", "Token schedules need the token program configured first (native schedules do not).", true),
    (11, "ZeroAddress", "An account given is the zero id; give a real account.", false),
    (12, "EmptyBatch", "A batch needs at least one recipient.", false),
    (13, "Unauthorized", "The signer is not the account this operation needs (beneficiary, cancel or milestone authority, treasury, or the creator funding a native schedule).", false),
    (14, "ScheduleAlreadyExists", "A schedule already exists for this creator and salt; use a new salt.", false),
    (15, "BatchAlreadyExists", "A batch already exists for this creator and batch id; use a new batch id.", false),
    (16, "NotASchedule", "No schedule exists at this account; check the schedule id.", false),
    (17, "NotCancelable", "This schedule is not cancelable (set at creation or made non-cancelable).", false),
    (18, "AlreadyCancelled", "This schedule is already cancelled; vested tokens remain claimable by the beneficiary.", false),
    (19, "AlreadyNonCancelable", "This schedule is already non-cancelable; nothing to do.", false),
    (20, "AlreadyFullyVested", "Everything has vested: there is nothing left to return.", false),
    (21, "NotTransferable", "This position was created non-transferable; the beneficiary cannot be changed.", false),
    (22, "SameBeneficiary", "The new beneficiary is the current one; nothing to do.", false),
    (23, "NotMilestoneSchedule", "Milestones can only be signalled on a milestone schedule.", false),
    (24, "MilestoneIndexOutOfBounds", "The milestone index is past the schedule's last tranche.", false),
    (25, "MilestoneAlreadyUnlocked", "This milestone was already signalled; signalling it again unlocks nothing.", false),
    (26, "NothingClaimable", "Nothing is claimable yet; retry after the next unlock shown in the schedule view.", true),
    (27, "ExceedsClaimable", "You asked for more than is claimable now (another claim may have landed first); refresh and claim at most the claimable amount.", true),
    (28, "InvalidRefundHolding", "The refund account is not valid for this asset (a token holding of another token, or one of the schedule's own accounts).", false),
    (29, "EscrowFundingMismatch", "The escrow did not receive exactly the schedule total (a misbehaving token program); nothing was created.", false),
    (30, "ArithmeticOverflow", "An amount overflows (a batch total, or a total plus its fees); split the batch or lower the amounts.", false),
    (31, "InvalidDestination", "The destination is one of the schedule's own accounts (its escrow, the schedule, a fee vault); choose your own account.", false),
    (32, "MalformedMessage", "The message could not be decoded; update the SDK/CLI to the version matching the deployed program.", false),
    (33, "InvalidAuthorityForSchedule", "A cancel authority needs a cancelable schedule, and a milestone authority a milestone schedule.", false),
    (34, "InvalidTokenProgram", "The token program id cannot be this program, its config or the clock.", false),
    (35, "NotRootOrDirectPda", "This operation must be signed directly by its account, or sent by the program that owns that PDA through AsPda; a relaying program cannot act in your name.", false),
];

/// The refusal for a guest exit code, if it is one of the program's.
#[must_use]
pub fn refusal(code: u32) -> Option<Refusal> {
    TABLE
        .iter()
        .find(|(c, ..)| u32::from(*c) == code)
        .map(|&(code, name, message, retry_later)| Refusal {
            code,
            name,
            message,
            retry_later,
        })
}

/// The program's own short label for a code (`E0xx: ...`), as `escapement-core` defines it.
#[must_use]
pub fn label(code: u32) -> &'static str {
    VestingError::describe_code(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_program_code_has_an_actionable_message() {
        for code in 1..=35_u32 {
            let r = refusal(code).unwrap_or_else(|| panic!("code {code} missing"));
            assert!(r.message.len() > 20, "code {code}: message too short");
            assert!(
                label(code).starts_with(&format!("E{code:03}")),
                "code {code}: {}",
                label(code)
            );
        }
        assert!(refusal(36).is_none());
        assert!(refusal(26).unwrap().retry_later);
    }
}
