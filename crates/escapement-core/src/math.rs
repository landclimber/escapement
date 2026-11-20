//! Overflow-free 256-bit arithmetic and vesting schedule math.
//!
//! Single source of truth shared between the RISC Zero guest, SDK, CLI, and formal/fuzz suites.

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

/// Returns the next unlock timestamp in ms after `timestamp_ms`, if deterministic from time.
#[must_use]
pub fn next_unlock_after(schedule: &ScheduleAccount, timestamp_ms: u64) -> Option<u64> {
    if schedule.cancelled.is_some() {
        return None;
    }
    match &schedule.kind {
        ScheduleKind::Linear { start_ts, end_ts } => {
            if timestamp_ms < *start_ts {
                Some(*start_ts)
            } else if timestamp_ms < *end_ts {
                Some(timestamp_ms.saturating_add(1).min(*end_ts))
            } else {
                None
            }
        }
        ScheduleKind::CliffLinear {
            cliff_ts, end_ts, ..
        } => {
            if timestamp_ms < *cliff_ts {
                Some(*cliff_ts)
            } else if timestamp_ms < *end_ts {
                Some(timestamp_ms.saturating_add(1).min(*end_ts))
            } else {
                None
            }
        }
        ScheduleKind::Milestone { .. } => None,
    }
}

/// Computes `(vested_at_cancel, unvested_refund)` at live chain timestamp `now_ms`.
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
    let vested = vested_uncancelled(schedule.total_amount, &schedule.kind, now_ms);
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
    use proptest::prelude::*;

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
        // Nearest valid (99), exact limit (100), first beyond (101).
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
        // Broker boundary classes: 499, 500, 501.
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn mul_div_rem_identity(
            a in any::<u128>(),
            d in 1u128..=u128::MAX,
            b_frac in any::<u128>(),
        ) {
            // Ensure b <= d so quotient always fits in u128 (matches vesting elapsed <= duration).
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

            // Pre-cliff is 0 (if cliff_ts > 0), exact cliff is cliff_amount, end_ts is total.
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
    }
}
