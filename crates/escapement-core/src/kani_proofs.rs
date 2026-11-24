//! Kani bounded proofs over the vesting math (`cargo kani -p escapement-core`).
//!
//! Bounds are stated per harness and are what the solver checked, nothing wider: amounts and times
//! are drawn from 8-bit ranges (so `a * b` takes the fast path of `mul_div_rem_u128`), fee rates over
//! the full `u16` domain. The full-width (256-bit) path of `mul_div_rem_u128` is covered by the
//! property tests in `math.rs` (4,096 cases per suite against an independent reference), not here,
//! and so are the monotonicity of the linear and cliff curves: harnesses for those timed out at 150 s
//! each at 8-bit bounds (24 Nov 2026) and were left out rather than kept unproven.

use crate::{
    math::{compute_fee_ceil, mul_div_rem_u128, split_on_cancel},
    Asset, ScheduleAccount, ScheduleKind, BPS_DENOMINATOR,
};
use lee_core::account::AccountId;

fn schedule(total_amount: u128, claimed_amount: u128, kind: ScheduleKind) -> ScheduleAccount {
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

/// `q * d + r == a * b` and `r < d`, for 8-bit `a`, `b` and non-zero 8-bit `d`.
#[kani::proof]
#[kani::unwind(130)]
fn mul_div_rem_identity_8bit() {
    let (a, b, d): (u8, u8, u8) = (kani::any(), kani::any(), kani::any());
    kani::assume(d > 0);
    let (a, b, d) = (u128::from(a), u128::from(b), u128::from(d));
    let (q, r) = mul_div_rem_u128(a, b, d).expect("no overflow for 8-bit inputs");
    assert!(r < d);
    assert_eq!(q * d + r, a * b);
}

/// Cancellation conserves the schedule (`vested + refund == total`) and never refunds tokens
/// already claimed (`vested >= claimed`), whatever the clock says, for 8-bit values.
#[kani::proof]
#[kani::unwind(130)]
fn split_on_cancel_conserves_and_never_refunds_claimed() {
    let total = u128::from(kani::any::<u8>());
    let claimed = u128::from(kani::any::<u8>());
    let (start, end, now): (u8, u8, u8) = (kani::any(), kani::any(), kani::any());
    kani::assume(claimed <= total && start < end);
    let s = schedule(
        total,
        claimed,
        ScheduleKind::Linear {
            start_ts: u64::from(start),
            end_ts: u64::from(end),
        },
    );
    if let Ok((vested, refund)) = split_on_cancel(&s, u64::from(now)) {
        assert_eq!(vested + refund, total);
        assert!(vested >= claimed);
        assert!(refund > 0);
    }
}

/// Fees: a rate above the cap is refused, `0` bps is free, and an accepted fee is the exact
/// ceiling of `amount * bps / 10,000`: for every `u16` rate and cap, and 8-bit amounts.
#[kani::proof]
#[kani::unwind(130)]
fn fee_ceiling_exact_and_capped_full_u16_rates() {
    let amount = u128::from(kani::any::<u8>());
    let (bps, max_bps): (u16, u16) = (kani::any(), kani::any());
    match compute_fee_ceil(amount, bps, max_bps) {
        Err(_) => assert!(bps > max_bps),
        Ok(fee) => {
            assert!(bps <= max_bps);
            let scaled = amount * u128::from(bps);
            let denom = u128::from(BPS_DENOMINATOR);
            assert!(fee * denom >= scaled);
            if fee > 0 {
                assert!((fee - 1) * denom < scaled);
            } else {
                assert_eq!(scaled, 0);
            }
        }
    }
}
