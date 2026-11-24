//! Overflow-free 256-bit arithmetic and vesting schedule math.
//!
//! Pure Rust single source of truth shared between the RISC Zero guest, SDK, CLI, and formal/fuzz suites.

use crate::{
    CancellationRecord, MilestoneTranche, ScheduleAccount, ScheduleKind, VestingError,
    BPS_DENOMINATOR, MAX_BROKER_FEE_BPS, MAX_MILESTONES, MAX_PROTOCOL_FEE_BPS,
};

/// Exact `(hi, lo)` 256-bit product of two `u128` values.
#[must_use]
pub const fn wide_mul_u128(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a & 0xFFFF_FFFF_FFFF_FFFF;
    let a_hi = a >> 64;
    let b_lo = b & 0xFFFF_FFFF_FFFF_FFFF;
    let b_hi = b >> 64;

    let p0 = a_lo * b_lo;
    let p1 = a_lo * b_hi;
    let p2 = a_hi * b_lo;
    let p3 = a_hi * b_hi;

    let mid = (p0 >> 64) + (p1 & 0xFFFF_FFFF_FFFF_FFFF) + (p2 & 0xFFFF_FFFF_FFFF_FFFF);
    let lo = (p0 & 0xFFFF_FFFF_FFFF_FFFF) | (mid << 64);
    let hi = p3 + (p1 >> 64) + (p2 >> 64) + (mid >> 64);
    (hi, lo)
}

/// Computes `(floor(a * b / d), (a * b) % d)` with full 256-bit intermediate precision.
///
/// Returns `None` if `d == 0` or the quotient overflows `u128`.
#[must_use]
pub fn mul_div_rem_u128(a: u128, b: u128, d: u128) -> Option<(u128, u128)> {
    if d == 0 {
        return None;
    }
    if a == 0 || b == 0 {
        return Some((0, 0));
    }
    if let Some(prod) = a.checked_mul(b) {
        return Some((prod / d, prod % d));
    }
    let (hi, lo) = wide_mul_u128(a, b);
    if hi >= d {
        return None;
    }
    let mut rem = hi;
    let mut quot = 0u128;
    let mut i = 128u32;
    while i > 0 {
        i -= 1;
        let bit = (lo >> i) & 1;
        let carry = rem >> 127;
        rem = (rem << 1) | bit;
        quot <<= 1;
        if carry != 0 || rem >= d {
            rem = rem.wrapping_sub(d);
            quot |= 1;
        }
    }
    Some((quot, rem))
}

/// Computes `floor(a * b / d)` without intermediate overflow.
#[must_use]
pub fn mul_div_floor_u128(a: u128, b: u128, d: u128) -> Option<u128> {
    mul_div_rem_u128(a, b, d).map(|(q, _)| q)
}

/// Computes `ceil(a * b / d)` without intermediate overflow.
#[must_use]
pub fn mul_div_ceil_u128(a: u128, b: u128, d: u128) -> Option<u128> {
    let (q, r) = mul_div_rem_u128(a, b, d)?;
    if r == 0 {
        Some(q)
    } else {
        q.checked_add(1)
    }
}

/// Computes protocol or broker fee: `0` when `bps == 0`, else `ceil(amount * bps / 10_000)`.
pub fn compute_fee_ceil(amount: u128, bps: u16, max_bps: u16) -> Result<u128, VestingError> {
    if bps > max_bps {
        return Err(VestingError::FeeRateExceedsCap { bps, max_bps });
    }
    if bps == 0 {
        return Ok(0);
    }
    mul_div_ceil_u128(amount, u128::from(bps), u128::from(BPS_DENOMINATOR))
        .ok_or(VestingError::ArithmeticOverflow)
}

/// Validates creation parameters for any schedule kind.
pub fn validate_schedule_params(
    total_amount: u128,
    kind: &ScheduleKind,
    protocol_fee_bps: u16,
    broker_fee_bps: u16,
) -> Result<(), VestingError> {
    if total_amount == 0 {
        return Err(VestingError::ZeroAmount);
    }
    if protocol_fee_bps > MAX_PROTOCOL_FEE_BPS {
        return Err(VestingError::FeeRateExceedsCap {
            bps: protocol_fee_bps,
            max_bps: MAX_PROTOCOL_FEE_BPS,
        });
    }
    if broker_fee_bps > MAX_BROKER_FEE_BPS {
        return Err(VestingError::FeeRateExceedsCap {
            bps: broker_fee_bps,
            max_bps: MAX_BROKER_FEE_BPS,
        });
    }
    match kind {
        ScheduleKind::Linear { start_ts, end_ts } => {
            if end_ts <= start_ts {
                return Err(VestingError::InvalidTimeRange);
            }
        }
        ScheduleKind::CliffLinear {
            start_ts,
            cliff_ts,
            end_ts,
            cliff_amount,
        } => {
            if end_ts <= start_ts || cliff_ts < start_ts || cliff_ts > end_ts {
                return Err(VestingError::InvalidTimeRange);
            }
            if *cliff_amount > total_amount {
                return Err(VestingError::InvalidCliffAmount);
            }
            if cliff_ts == end_ts && *cliff_amount != total_amount {
                return Err(VestingError::InvalidCliffAmount);
            }
        }
        ScheduleKind::Milestone { tranches } => {
            validate_milestones(total_amount, tranches)?;
        }
    }
    Ok(())
}

fn validate_milestones(
    total_amount: u128,
    tranches: &[MilestoneTranche],
) -> Result<(), VestingError> {
    if tranches.is_empty() || tranches.len() > MAX_MILESTONES {
        return Err(VestingError::InvalidMilestoneCount);
    }
    let mut sum = 0u128;
    for t in tranches {
        if t.amount == 0 || t.unlocked || t.unlocked_at_ms.is_some() {
            return Err(VestingError::InvalidMilestoneTranche);
        }
        sum = sum
            .checked_add(t.amount)
            .ok_or(VestingError::ArithmeticOverflow)?;
    }
    if sum != total_amount {
        return Err(VestingError::MilestoneSumMismatch);
    }
    Ok(())
}

/// Computes cumulative vested amount at millisecond timestamp `timestamp_ms`.
///
/// Monotonically non-decreasing in `timestamp_ms`, bounded by `[0, schedule.total_amount]`,
/// and frozen at `rec.vested_at_cancel` once cancelled.
#[must_use]
pub fn vested_at(schedule: &ScheduleAccount, timestamp_ms: u64) -> u128 {
    if let Some(CancellationRecord {
        vested_at_cancel, ..
    }) = schedule.cancelled
    {
        return vested_at_cancel;
    }
    vested_uncancelled(schedule.total_amount, &schedule.kind, timestamp_ms)
}

#[must_use]
pub fn vested_uncancelled(total_amount: u128, kind: &ScheduleKind, timestamp_ms: u64) -> u128 {
    match kind {
        ScheduleKind::Linear { start_ts, end_ts } => {
            if timestamp_ms <= *start_ts {
                0
            } else if timestamp_ms >= *end_ts {
                total_amount
            } else {
                let elapsed = u128::from(timestamp_ms - *start_ts);
                let duration = u128::from(*end_ts - *start_ts);
                mul_div_floor_u128(total_amount, elapsed, duration)
                    .expect("elapsed < duration guarantees result <= total_amount")
            }
        }
        ScheduleKind::CliffLinear {
            start_ts: _,
            cliff_ts,
            end_ts,
            cliff_amount,
        } => {
            if timestamp_ms < *cliff_ts {
                0
            } else if timestamp_ms >= *end_ts {
                total_amount
            } else {
                let post_cliff_total = total_amount - *cliff_amount;
                let elapsed = u128::from(timestamp_ms - *cliff_ts);
                let duration = u128::from(*end_ts - *cliff_ts);
                let linear_part = mul_div_floor_u128(post_cliff_total, elapsed, duration)
                    .expect("elapsed < duration guarantees result <= post_cliff_total");
                *cliff_amount + linear_part
            }
        }
        ScheduleKind::Milestone { tranches } => tranches
            .iter()
            .filter(|t| t.unlocked)
            .fold(0u128, |acc, t| acc + t.amount),
    }
}

/// Computes currently claimable amount at `timestamp_ms`.
#[must_use]
pub fn claimable_at(schedule: &ScheduleAccount, timestamp_ms: u64) -> u128 {
    vested_at(schedule, timestamp_ms).saturating_sub(schedule.claimed_amount)
}

/// Returns the exact first millisecond `t > timestamp_ms` at which vested tokens increase
/// above `max(vested_at(schedule, timestamp_ms), schedule.claimed_amount)`, if deterministic
/// from time.
#[must_use]
pub fn next_unlock_after(schedule: &ScheduleAccount, timestamp_ms: u64) -> Option<u64> {
    if schedule.cancelled.is_some() || schedule.claimed_amount >= schedule.total_amount {
        return None;
    }
    let current = vested_uncancelled(schedule.total_amount, &schedule.kind, timestamp_ms);
    let baseline = current.max(schedule.claimed_amount);
    if baseline >= schedule.total_amount {
        return None;
    }
    let target = baseline + 1;
    match &schedule.kind {
        ScheduleKind::Linear { start_ts, end_ts } => {
            let duration = u128::from(*end_ts - *start_ts);
            let dt = mul_div_ceil_u128(target, duration, schedule.total_amount)
                .expect("target <= total_amount guarantees dt <= duration");
            Some(start_ts.saturating_add(dt as u64).min(*end_ts))
        }
        ScheduleKind::CliffLinear {
            cliff_ts,
            end_ts,
            cliff_amount,
            ..
        } => {
            if timestamp_ms < *cliff_ts && *cliff_amount >= target {
                return Some(*cliff_ts);
            }
            let post_cliff_total = schedule.total_amount - *cliff_amount;
            let target_linear = target - *cliff_amount;
            let duration = u128::from(*end_ts - *cliff_ts);
            let dt = mul_div_ceil_u128(target_linear, duration, post_cliff_total)
                .expect("target_linear <= post_cliff_total guarantees dt <= duration");
            Some(cliff_ts.saturating_add(dt as u64).min(*end_ts))
        }
        ScheduleKind::Milestone { .. } => None,
    }
}

/// Computes `(vested_at_cancel, unvested_refund)` at live chain timestamp `now_ms`.
///
/// Clamps `vested_at_cancel >= schedule.claimed_amount` so neither LEZ v0.4's end-of-block
/// `Clock::Tick` 1-block lag relative to `ClaimExact`'s `timestamp_window` nor sequencer
/// wall-clock regression can ever under-count vested tokens or over-refund from a shared
/// batch escrow.
pub fn split_on_cancel(
    schedule: &ScheduleAccount,
    now_ms: u64,
) -> Result<(u128, u128), VestingError> {
    if !schedule.cancelable {
        return Err(VestingError::NotCancelable);
    }
    if schedule.cancelled.is_some() {
        return Err(VestingError::AlreadyCancelled);
    }
    let vested = vested_uncancelled(schedule.total_amount, &schedule.kind, now_ms)
        .max(schedule.claimed_amount);
    let unvested = schedule
        .total_amount
        .checked_sub(vested)
        .ok_or(VestingError::ArithmeticOverflow)?;
    if unvested == 0 {
        return Err(VestingError::AlreadyFullyVested);
    }
    Ok((vested, unvested))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lee_core::{account::AccountId, program::PdaSeed};
    use proptest::prelude::*;

    fn dummy_schedule(
        total_amount: u128,
        claimed_amount: u128,
        kind: ScheduleKind,
    ) -> ScheduleAccount {
        let a = AccountId::new([1u8; 32]);
        ScheduleAccount {
            version: 1,
            token_program_id: a,
            creator: a,
            beneficiary: a,
            token_definition: a,
            escrow_seed: PdaSeed::new([2u8; 32]),
            escrow_account: a,
            refund_holding: a,
            total_amount,
            claimed_amount,
            kind,
            cancelable: true,
            transferable: false,
            cancel_authority: None,
            milestone_authority: None,
            cancelled: None,
        }
    }

    #[test]
    fn mul_div_extremes_never_overflow() {
        assert_eq!(mul_div_floor_u128(u128::MAX, 1, 1), Some(u128::MAX));
        assert_eq!(
            mul_div_floor_u128(u128::MAX, u128::MAX - 1, u128::MAX),
            Some(u128::MAX - 1)
        );
        assert_eq!(
            mul_div_floor_u128(u128::MAX, 500_000, 1_000_000),
            Some(u128::MAX / 2)
        );
        assert_eq!(mul_div_floor_u128(100, 1, 0), None);
        assert_eq!(mul_div_ceil_u128(1, 1, 10_000), Some(1));
        assert_eq!(mul_div_ceil_u128(10_000, 1, 10_000), Some(1));
        assert_eq!(mul_div_ceil_u128(10_001, 1, 10_000), Some(2));
    }

    #[test]
    fn fee_boundary_classes() {
        assert_eq!(compute_fee_ceil(10_000, 0, MAX_PROTOCOL_FEE_BPS), Ok(0));
        assert_eq!(compute_fee_ceil(10_000, 99, MAX_PROTOCOL_FEE_BPS), Ok(99));
        assert_eq!(compute_fee_ceil(10_000, 100, MAX_PROTOCOL_FEE_BPS), Ok(100));
        assert_eq!(
            compute_fee_ceil(10_000, 101, MAX_PROTOCOL_FEE_BPS),
            Err(VestingError::FeeRateExceedsCap {
                bps: 101,
                max_bps: 100
            })
        );
        assert_eq!(compute_fee_ceil(10_000, 499, MAX_BROKER_FEE_BPS), Ok(499));
        assert_eq!(compute_fee_ceil(10_000, 500, MAX_BROKER_FEE_BPS), Ok(500));
        assert_eq!(
            compute_fee_ceil(10_000, 501, MAX_BROKER_FEE_BPS),
            Err(VestingError::FeeRateExceedsCap {
                bps: 501,
                max_bps: 500
            })
        );
    }

    #[test]
    fn split_on_cancel_clamps_to_claimed_under_clock_lag() {
        let kind = ScheduleKind::CliffLinear {
            start_ts: 1_000,
            cliff_ts: 2_000,
            end_ts: 5_000,
            cliff_amount: 50_000,
        };
        // Claimed 50,000 at block_ts = 2,000 via ClaimExact, then Cancel reads clock = 1,999.
        let s = dummy_schedule(100_000, 50_000, kind.clone());
        assert_eq!(split_on_cancel(&s, 1_999), Ok((50_000, 50_000)));
        // Fully claimed at end_ts = 5,000 via ClaimExact, then Cancel reads clock = 4,999.
        let full = dummy_schedule(100_000, 100_000, kind);
        assert_eq!(
            split_on_cancel(&full, 4_999),
            Err(VestingError::AlreadyFullyVested)
        );
    }

    #[test]
    fn degenerate_bounds_and_validation_negatives() {
        // Pure cliff (cliff_ts == end_ts requires cliff_amount == total_amount).
        let pure_cliff = ScheduleKind::CliffLinear {
            start_ts: 100,
            cliff_ts: 500,
            end_ts: 500,
            cliff_amount: 1_000,
        };
        assert_eq!(validate_schedule_params(1_000, &pure_cliff, 0, 0), Ok(()));
        assert_eq!(vested_uncancelled(1_000, &pure_cliff, 499), 0);
        assert_eq!(vested_uncancelled(1_000, &pure_cliff, 500), 1_000);
        let s_pure = dummy_schedule(1_000, 0, pure_cliff);
        assert_eq!(next_unlock_after(&s_pure, 499), Some(500));
        assert_eq!(next_unlock_after(&s_pure, 500), None);

        // Coarse vesting: 10 tokens over 1,000 ms -> next unit unlocks every 100 ms, NOT +1 ms!
        let coarse = dummy_schedule(
            10,
            0,
            ScheduleKind::Linear {
                start_ts: 1_000,
                end_ts: 2_000,
            },
        );
        assert_eq!(next_unlock_after(&coarse, 500), Some(1_100));
        assert_eq!(next_unlock_after(&coarse, 1_000), Some(1_100));
        assert_eq!(next_unlock_after(&coarse, 1_099), Some(1_100));
        assert_eq!(next_unlock_after(&coarse, 1_100), Some(1_200));

        // Negative validation checks (codes 1..=6).
        assert_eq!(
            validate_schedule_params(
                0,
                &ScheduleKind::Linear {
                    start_ts: 1,
                    end_ts: 2
                },
                0,
                0
            ),
            Err(VestingError::ZeroAmount)
        );
        assert_eq!(
            validate_schedule_params(
                10,
                &ScheduleKind::Linear {
                    start_ts: 5,
                    end_ts: 5
                },
                0,
                0
            ),
            Err(VestingError::InvalidTimeRange)
        );
        assert_eq!(
            validate_schedule_params(
                10,
                &ScheduleKind::CliffLinear {
                    start_ts: 1,
                    cliff_ts: 5,
                    end_ts: 5,
                    cliff_amount: 9,
                },
                0,
                0
            ),
            Err(VestingError::InvalidCliffAmount)
        );
        assert_eq!(
            validate_schedule_params(10, &ScheduleKind::Milestone { tranches: vec![] }, 0, 0),
            Err(VestingError::InvalidMilestoneCount)
        );
        assert_eq!(
            validate_schedule_params(
                10,
                &ScheduleKind::Milestone {
                    tranches: vec![MilestoneTranche {
                        amount: 10,
                        unlocked: true,
                        unlocked_at_ms: None,
                    }],
                },
                0,
                0
            ),
            Err(VestingError::InvalidMilestoneTranche)
        );
        assert_eq!(
            validate_schedule_params(
                10,
                &ScheduleKind::Milestone {
                    tranches: vec![MilestoneTranche {
                        amount: 9,
                        unlocked: false,
                        unlocked_at_ms: None,
                    }],
                },
                0,
                0
            ),
            Err(VestingError::MilestoneSumMismatch)
        );
    }

    /// Independent base-10_000 reference for `ceil(amount * bps / 10_000)` that shares no
    /// code with `mul_div_*`: `amount = 10_000*q + r` implies
    /// `ceil(amount*bps/10_000) = q*bps + ceil(r*bps/10_000)` with `q*bps < 2^128`
    /// for every `bps <= 500`, so plain `u128` arithmetic is exact here.
    fn fee_ceil_reference(amount: u128, bps: u16) -> u128 {
        let d = u128::from(BPS_DENOMINATOR);
        let (q, r) = (amount / d, amount % d);
        q * u128::from(bps) + (r * u128::from(bps)).div_ceil(d)
    }

    /// Splits `total` into `n` strictly-positive tranches summing to `total`
    /// (only valid for `total >= n`).
    fn split_tranches(total: u128, n: u128) -> Vec<MilestoneTranche> {
        (0..n)
            .map(|i| MilestoneTranche {
                amount: total / n + u128::from(i < total % n),
                unlocked: false,
                unlocked_at_ms: None,
            })
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn mul_div_rem_identity(
            a in any::<u128>(),
            d in 1u128..=u128::MAX,
            b_frac in any::<u128>(),
        ) {
            let b = b_frac % d;
            let (q, r) = mul_div_rem_u128(a, b, d).expect("b < d guarantees no overflow");
            prop_assert!(r < d);
            let (lhs_hi, lhs_lo) = wide_mul_u128(a, b);
            let (qd_hi, qd_lo) = wide_mul_u128(q, d);
            let (rhs_lo, carry) = qd_lo.overflowing_add(r);
            let rhs_hi = qd_hi + u128::from(carry);
            prop_assert_eq!((lhs_hi, lhs_lo), (rhs_hi, rhs_lo));
        }

        #[test]
        fn cliff_linear_monotonic_bounded_and_exact_terminal(
            total in 1u128..=u128::MAX,
            start in 0u64..=10_000_000_000_000u64,
            cliff_offset in 0u64..=5_000_000_000_000u64,
            tail_offset in 1u64..=5_000_000_000_000u64,
            cliff_ratio in 0u16..=10_000u16,
            t1 in any::<u64>(),
            t2 in any::<u64>(),
        ) {
            let cliff_ts = start.saturating_add(cliff_offset);
            let end_ts = cliff_ts.saturating_add(tail_offset);
            prop_assume!(end_ts > start && cliff_ts < end_ts);
            let cliff_amount = mul_div_floor_u128(total, u128::from(cliff_ratio), 10_000).unwrap();
            let kind = ScheduleKind::CliffLinear {
                start_ts: start,
                cliff_ts,
                end_ts,
                cliff_amount,
            };
            validate_schedule_params(total, &kind, 0, 0).unwrap();

            if cliff_ts > 0 {
                prop_assert_eq!(vested_uncancelled(total, &kind, cliff_ts - 1), 0);
            }
            prop_assert_eq!(vested_uncancelled(total, &kind, cliff_ts), cliff_amount);
            prop_assert_eq!(vested_uncancelled(total, &kind, end_ts), total);
            prop_assert_eq!(vested_uncancelled(total, &kind, u64::MAX), total);

            let (lo, hi) = if t1 <= t2 { (t1, t2) } else { (t2, t1) };
            let v_lo = vested_uncancelled(total, &kind, lo);
            let v_hi = vested_uncancelled(total, &kind, hi);
            prop_assert!(v_lo <= v_hi);
            prop_assert!(v_hi <= total);
        }

        #[test]
        fn linear_monotonic_bounded_and_exact_terminal(
            total in 1u128..=u128::MAX,
            start in 0u64..=10_000_000_000_000u64,
            dur in 1u64..=10_000_000_000_000u64,
            t1 in any::<u64>(),
            t2 in any::<u64>(),
        ) {
            let end_ts = start.saturating_add(dur);
            prop_assume!(end_ts > start);
            let kind = ScheduleKind::Linear { start_ts: start, end_ts };
            validate_schedule_params(total, &kind, 0, 0).unwrap();

            prop_assert_eq!(vested_uncancelled(total, &kind, start), 0);
            prop_assert_eq!(vested_uncancelled(total, &kind, end_ts), total);

            let (lo, hi) = if t1 <= t2 { (t1, t2) } else { (t2, t1) };
            let v_lo = vested_uncancelled(total, &kind, lo);
            let v_hi = vested_uncancelled(total, &kind, hi);
            prop_assert!(v_lo <= v_hi);
            prop_assert!(v_hi <= total);
        }

        #[test]
        fn next_unlock_after_is_exact_first_millisecond(
            total in 1u128..=1_000_000_000_000u128,
            start in 1u64..=1_000_000_000u64,
            cliff_offset in 0u64..=500_000_000u64,
            tail_offset in 1u64..=500_000_000u64,
            cliff_ratio in 0u16..=10_000u16,
            use_cliff in any::<bool>(),
            t in 0u64..=2_500_000_000u64,
        ) {
            let kind = if use_cliff {
                let cliff_ts = start + cliff_offset;
                let end_ts = cliff_ts + tail_offset;
                let cliff_amount = mul_div_floor_u128(total, u128::from(cliff_ratio), 10_000).unwrap();
                ScheduleKind::CliffLinear {
                    start_ts: start,
                    cliff_ts,
                    end_ts,
                    cliff_amount,
                }
            } else {
                ScheduleKind::Linear {
                    start_ts: start,
                    end_ts: start + cliff_offset + tail_offset,
                }
            };
            let s = dummy_schedule(total, 0, kind);
            let cur = vested_at(&s, t);
            match next_unlock_after(&s, t) {
                None => prop_assert_eq!(cur, total),
                Some(next_ts) => {
                    prop_assert!(next_ts > t, "next_ts {next_ts} must exceed t {t}");
                    prop_assert!(vested_at(&s, next_ts) > cur, "must unlock at least 1 unit at next_ts");
                    prop_assert_eq!(vested_at(&s, next_ts - 1), cur, "next_ts must be the exact first ms");
                }
            }
        }

        #[test]
        fn fee_ceil_matches_independent_base_10k_reference(
            amount in any::<u128>(),
            bps in 0u16..=MAX_BROKER_FEE_BPS,
        ) {
            prop_assert_eq!(
                compute_fee_ceil(amount, bps, MAX_BROKER_FEE_BPS),
                Ok(fee_ceil_reference(amount, bps))
            );
        }

        #[test]
        fn split_on_cancel_conserves_total_and_never_refunds_claimed(
            total in 1u128..=u128::MAX,
            start in 0u64..=10_000_000_000_000u64,
            cliff_offset in 0u64..=5_000_000_000_000u64,
            tail_offset in 1u64..=5_000_000_000_000u64,
            cliff_ratio in 0u16..=10_000u16,
            kind_tag in 0u8..=2u8,
            unlocked_count in 0u128..=4u128,
            now in any::<u64>(),
            claim_bias in any::<u128>(),
        ) {
            let kind = match kind_tag {
                0 => ScheduleKind::Linear {
                    start_ts: start,
                    end_ts: start.saturating_add(cliff_offset).saturating_add(tail_offset),
                },
                _ => {
                    let cliff_ts = start.saturating_add(cliff_offset);
                    let cliff_amount =
                        mul_div_floor_u128(total, u128::from(cliff_ratio), 10_000).unwrap();
                    ScheduleKind::CliffLinear {
                        start_ts: start,
                        cliff_ts,
                        end_ts: cliff_ts.saturating_add(tail_offset),
                        cliff_amount,
                    }
                }
            };
            let kind = if kind_tag == 2 {
                let n = 1 + (unlocked_count % 4);
                prop_assume!(total >= n);
                let mut tranches = split_tranches(total, n);
                let k = (unlocked_count % (n + 1)) as usize;
                for t in tranches.iter_mut().take(k) {
                    t.unlocked = true;
                }
                ScheduleKind::Milestone { tranches }
            } else {
                prop_assume!(match &kind {
                    ScheduleKind::Linear { start_ts, end_ts } => end_ts > start_ts,
                    ScheduleKind::CliffLinear { start_ts, cliff_ts, end_ts, .. } => {
                        end_ts > start_ts && cliff_ts < end_ts
                    }
                    _ => false,
                });
                kind
            };
            // `claimed` intentionally spans 0..=total (possibly above vested) so the
            // `vested_at_cancel >= claimed_amount` clamp is exercised too.
            let claimed = if total == u128::MAX {
                claim_bias
            } else {
                claim_bias % (total + 1)
            };
            let vested_now = vested_uncancelled(total, &kind, now);
            let s = dummy_schedule(total, claimed, kind);
            let res = split_on_cancel(&s, now);
            if res == Err(VestingError::AlreadyFullyVested) {
                prop_assert_eq!(vested_now.max(claimed), total);
            } else {
                let (vested, refund) = res.expect("only AlreadyFullyVested is reachable here");
                prop_assert!(refund > 0, "Ok split must have a positive refund");
                prop_assert_eq!(vested + refund, total, "vested + refund must conserve total");
                prop_assert!(vested >= claimed, "vested_at_cancel must never drop below claimed");
                prop_assert!(vested >= vested_now, "clamping must never under-count vested");
                prop_assert_eq!(refund, total - vested);
            }
        }

        #[test]
        fn claimable_bounded_by_total_minus_claimed_and_cancel_freezes_all_queries(
            total in 1u128..=u128::MAX,
            start in 0u64..=10_000_000_000_000u64,
            cliff_offset in 0u64..=5_000_000_000_000u64,
            tail_offset in 1u64..=5_000_000_000_000u64,
            cliff_ratio in 0u16..=10_000u16,
            kind_tag in 0u8..=2u8,
            unlocked_count in 0u128..=4u128,
            now in any::<u64>(),
            t_probe in any::<u64>(),
            cancel_bias in any::<u128>(),
            claim_bias in any::<u128>(),
        ) {
            let kind = match kind_tag {
                0 => ScheduleKind::Linear {
                    start_ts: start,
                    end_ts: start.saturating_add(cliff_offset).saturating_add(tail_offset),
                },
                _ => {
                    let cliff_ts = start.saturating_add(cliff_offset);
                    let cliff_amount =
                        mul_div_floor_u128(total, u128::from(cliff_ratio), 10_000).unwrap();
                    ScheduleKind::CliffLinear {
                        start_ts: start,
                        cliff_ts,
                        end_ts: cliff_ts.saturating_add(tail_offset),
                        cliff_amount,
                    }
                }
            };
            let kind = if kind_tag == 2 {
                let n = 1 + (unlocked_count % 4);
                prop_assume!(total >= n);
                let mut tranches = split_tranches(total, n);
                let k = (unlocked_count % (n + 1)) as usize;
                for t in tranches.iter_mut().take(k) {
                    t.unlocked = true;
                }
                ScheduleKind::Milestone { tranches }
            } else {
                prop_assume!(match &kind {
                    ScheduleKind::Linear { start_ts, end_ts } => end_ts > start_ts,
                    ScheduleKind::CliffLinear { start_ts, cliff_ts, end_ts, .. } => {
                        end_ts > start_ts && cliff_ts < end_ts
                    }
                    _ => false,
                });
                kind
            };
            let claimed = if total == u128::MAX {
                claim_bias
            } else {
                claim_bias % (total + 1)
            };
            let s = dummy_schedule(total, claimed, kind.clone());

            // Claimable can be fully expressed as a checked subtraction: the result never
            // exceeds total - claimed and always lets the beneficiary reach `vested`.
            let vested_now = vested_uncancelled(total, &s.kind, now);
            prop_assert!(claimable_at(&s, now) <= total - claimed);
            prop_assert_eq!(
                claimable_at(&s, now),
                vested_now.max(claimed) - claimed
            );
            if claimed >= total {
                prop_assert_eq!(next_unlock_after(&s, t_probe), None);
            }

            // Once cancelled, every future or past query is frozen at vested_at_cancel and
            // `next_unlock_after` must be None (no further runtime unlocks to wait for).
            let cancel_v = if total == u128::MAX {
                cancel_bias
            } else {
                cancel_bias % (total + 1)
            };
            let cancelled = ScheduleAccount {
                cancelled: Some(CancellationRecord {
                    cancelled_at_ms: now,
                    vested_at_cancel: cancel_v,
                    refunded_amount: total - cancel_v,
                }),
                ..s
            };
            prop_assert_eq!(vested_at(&cancelled, t_probe), cancel_v);
            prop_assert_eq!(vested_at(&cancelled, now), cancel_v);
            prop_assert_eq!(claimable_at(&cancelled, t_probe), cancel_v.saturating_sub(claimed));
            prop_assert_eq!(next_unlock_after(&cancelled, t_probe), None);
        }
    }

    #[test]
    fn fee_ceil_reference_extremes_and_caps() {
        // bps = 0 is exactly 0 fee; the reference agrees with compute_fee_ceil at the extremes.
        assert_eq!(compute_fee_ceil(u128::MAX, 0, MAX_BROKER_FEE_BPS), Ok(0));
        assert_eq!(
            compute_fee_ceil(u128::MAX, MAX_BROKER_FEE_BPS, MAX_BROKER_FEE_BPS),
            Ok(fee_ceil_reference(u128::MAX, MAX_BROKER_FEE_BPS))
        );
        // The mul_div ceil fast path (exact multiple -> no +1) is preserved.
        assert_eq!(compute_fee_ceil(20_000, 50, MAX_BROKER_FEE_BPS), Ok(100));
        assert_eq!(
            compute_fee_ceil(20_001, 50, MAX_BROKER_FEE_BPS),
            Ok(fee_ceil_reference(20_001, 50))
        );
    }
}
