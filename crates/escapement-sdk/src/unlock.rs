//! Why nothing is claimable now and when the next unlock comes (U7), from a schedule's on-chain
//! state, with the program's own math (`escapement_core::math`).
//!
//! `now_ms` is the LEZ clock as the program reads it on a public claim (on LEZ v0.4.0-rc3, the
//! previous block's timestamp); a private claim names its own `effective_ts`, which must not be in
//! the future.

use escapement_core::{
    math::{claimable_at, next_unlock_after},
    ScheduleAccount, ScheduleKind,
};

/// Why nothing (more) is claimable now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextUnlockReason {
    /// Before the cliff: the accrued amount unlocks at once at `cliff_ms`.
    BeforeCliff { cliff_ms: u64 },
    /// Before a linear schedule's start.
    BeforeStart { start_ms: u64 },
    /// Linear accrual: the next whole unit vests at the time given.
    LinearAccrual,
    /// Waiting for the milestone authority to signal tranche `next_index` (`pending` remain).
    MilestonePending { next_index: u8, pending: u32 },
    /// Everything has vested and been claimed.
    FullyClaimed,
    /// Cancelled, and the vested part is already claimed: nothing more will unlock.
    CancelledAndClaimed,
}

impl NextUnlockReason {
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::BeforeCliff { cliff_ms } => {
                format!("the cliff has not passed (cliff at {})", utc(*cliff_ms))
            }
            Self::BeforeStart { start_ms } => {
                format!("vesting has not started (starts at {})", utc(*start_ms))
            }
            Self::LinearAccrual => {
                "everything vested so far is claimed; tokens keep accruing linearly".into()
            }
            Self::MilestonePending {
                next_index,
                pending,
            } => format!(
                "no signalled milestone is left to claim; {pending} tranche(s) wait for the milestone authority (next: index {next_index})"
            ),
            Self::FullyClaimed => "the schedule is fully vested and fully claimed".into(),
            Self::CancelledAndClaimed => {
                "the schedule was cancelled and its vested part is already claimed".into()
            }
        }
    }
}

/// The next time more becomes claimable (`None` when it waits on a milestone signal or never
/// comes), and why nothing more is claimable now.
#[must_use]
pub fn next_unlock(schedule: &ScheduleAccount, now_ms: u64) -> (Option<u64>, NextUnlockReason) {
    if schedule.cancelled.is_some() {
        return (None, NextUnlockReason::CancelledAndClaimed);
    }
    if schedule.claimed_amount >= schedule.total_amount {
        return (None, NextUnlockReason::FullyClaimed);
    }
    let reason = match &schedule.kind {
        ScheduleKind::Milestone { tranches } => {
            let pending: Vec<usize> = (0..tranches.len())
                .filter(|i| !tranches[*i].unlocked)
                .collect();
            return match pending.first() {
                Some(&next) => (
                    None,
                    NextUnlockReason::MilestonePending {
                        next_index: u8::try_from(next).unwrap_or(u8::MAX),
                        pending: u32::try_from(pending.len()).unwrap_or(u32::MAX),
                    },
                ),
                None => (None, NextUnlockReason::FullyClaimed),
            };
        }
        ScheduleKind::CliffLinear { cliff_ts, .. } if now_ms < *cliff_ts => {
            NextUnlockReason::BeforeCliff {
                cliff_ms: *cliff_ts,
            }
        }
        ScheduleKind::Linear { start_ts, .. } if now_ms < *start_ts => {
            NextUnlockReason::BeforeStart {
                start_ms: *start_ts,
            }
        }
        _ => NextUnlockReason::LinearAccrual,
    };
    (next_unlock_after(schedule, now_ms), reason)
}

/// What is claimable at `now_ms` (the program's `claimable_at`).
#[must_use]
pub fn claimable(schedule: &ScheduleAccount, now_ms: u64) -> u128 {
    claimable_at(schedule, now_ms)
}

/// A unix-millisecond time as `YYYY-MM-DD hh:mm:ss UTC` (no time-zone database needed).
#[must_use]
pub fn utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (H. Hinnant), for days since 1970-01-01.
    let z = i64::try_from(days)
        .unwrap_or(i64::MAX)
        .saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use escapement_core::{Asset, MilestoneTranche};
    use lee_core::account::AccountId;

    use super::*;

    fn schedule(kind: ScheduleKind, claimed: u128) -> ScheduleAccount {
        let a = AccountId::new([1; 32]);
        ScheduleAccount {
            version: 1,
            asset_program_id: a,
            creator: a,
            beneficiary: a,
            asset: Asset::Native,
            escrow_seed: [2; 32],
            escrow_account: a,
            refund_holding: a,
            total_amount: 1_000,
            claimed_amount: claimed,
            vested_high_water: claimed,
            kind,
            cancelable: true,
            transferable: false,
            cancel_authority: None,
            milestone_authority: None,
            cancelled: None,
        }
    }

    #[test]
    fn before_the_cliff_names_the_cliff_and_the_exact_unlock() {
        let s = schedule(
            ScheduleKind::CliffLinear {
                start_ts: 0,
                cliff_ts: 500,
                end_ts: 1_000,
                cliff_amount: 500,
            },
            0,
        );
        assert_eq!(claimable(&s, 499), 0);
        let (when, reason) = next_unlock(&s, 100);
        assert_eq!(when, Some(500));
        assert_eq!(reason, NextUnlockReason::BeforeCliff { cliff_ms: 500 });
        assert!(reason.describe().contains("1970-01-01"));
    }

    #[test]
    fn milestones_wait_on_the_authority() {
        let t = |unlocked| MilestoneTranche {
            amount: 500,
            unlocked,
            unlocked_at_ms: None,
        };
        let s = schedule(
            ScheduleKind::Milestone {
                tranches: vec![t(true), t(false)],
            },
            500,
        );
        assert_eq!(
            next_unlock(&s, 10),
            (
                None,
                NextUnlockReason::MilestonePending {
                    next_index: 1,
                    pending: 1
                }
            )
        );
    }

    #[test]
    fn utc_formats_known_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_795_478_400_000), "2026-11-24 00:00:00 UTC");
    }
}
