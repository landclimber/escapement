//! Fee estimates for the pre-claim summary and the private-path gas check (U4), with LEZ
//! v0.4.0-rc3's own formulas (`fee_core`).
//!
//! A privacy-preserving transaction pays its fee inside the proof: one `Credit(reserve)` from a
//! private account to the fee inbox, published in plaintext. Settlement charges
//! `private_fee_required(cycles)` = `(PRIVATE_VERIFY_GAS + public cycles) * base_fee_exec +
//! PRIVATE_GAS_STOR * base_fee_stor` and returns the surplus to the payer's alias (if it is over
//! `MIN_PRIVATE_REFUND`, else it is kept as tip).
//!
//! **Reserve policy.** LEZ's rc3 wallet reserves `min(headroom, balance)` (at least the fee at the
//! head), so whenever the payer holds less than the headroom, the published reserve *is* the payer's
//! whole balance. This SDK never does that: it always reserves the headroom (a function of public
//! cycles and public base fees only) and refuses with [`SdkError::InsufficientPrivateGas`] when the
//! payer cannot cover it.

use fee_core::{assess, market};

use crate::SdkError;

/// LEZ rc3 wallet default (`lez/wallet/src/config.rs`, `default_fee_headroom_blocks`): price the
/// reserve at the base fees after this many full blocks.
pub const DEFAULT_HEADROOM_BLOCKS: u64 = 5;

/// The head fee market (`getFeeState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeQuote {
    pub base_fee_exec: u64,
    pub base_fee_stor: u64,
}

/// The fee of one private claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateFeeEstimate {
    /// Public cycles of the claim's public part (from a simulation).
    pub public_cycles: u64,
    /// `PRIVATE_VERIFY_GAS + public_cycles`.
    pub exec_gas: u64,
    /// `PRIVATE_GAS_STOR` (flat).
    pub stor_gas: u64,
    pub base_fee_exec: u64,
    pub base_fee_stor: u64,
    /// The fee if included at today's base fees.
    pub fee_at_head: u128,
    pub exec_ceiling: u64,
    pub stor_ceiling: u64,
    /// What the proof credits to the fee inbox (public): the fee at the ceilings.
    pub reserve: u128,
}

fn ceiling(
    base: u64,
    max_gas: u64,
    target: u64,
    damping: u64,
    lo: u64,
    hi: u64,
    blocks: u64,
) -> u64 {
    (0..blocks).fold(base, |fee, _| {
        market::next_base_fee(fee, max_gas, target, damping, lo, hi)
    })
}

/// The private claim's fee at `quote`, with the reserve priced `headroom_blocks` full blocks ahead.
#[must_use]
pub fn estimate_private_fee(
    public_cycles: u64,
    quote: FeeQuote,
    headroom_blocks: u64,
) -> PrivateFeeEstimate {
    let exec_ceiling = ceiling(
        quote.base_fee_exec,
        market::MAX_GAS_EXEC,
        market::TARGET_GAS_EXEC,
        market::D_EXEC,
        market::BASE_FEE_EXEC_MIN,
        market::BASE_FEE_EXEC_MAX,
        headroom_blocks,
    );
    let stor_ceiling = ceiling(
        quote.base_fee_stor,
        market::MAX_GAS_STOR,
        market::TARGET_GAS_STOR,
        market::D_STOR,
        market::BASE_FEE_STOR_MIN,
        market::BASE_FEE_STOR_MAX,
        headroom_blocks,
    );
    PrivateFeeEstimate {
        public_cycles,
        exec_gas: market::PRIVATE_VERIFY_GAS.saturating_add(public_cycles),
        stor_gas: market::PRIVATE_GAS_STOR,
        base_fee_exec: quote.base_fee_exec,
        base_fee_stor: quote.base_fee_stor,
        fee_at_head: assess::private_fee_required(
            public_cycles,
            quote.base_fee_exec,
            quote.base_fee_stor,
        ),
        exec_ceiling,
        stor_ceiling,
        reserve: assess::private_fee_required(public_cycles, exec_ceiling, stor_ceiling),
    }
}

/// Refuses before proving unless the private fee payer covers the full reserve. `available` is
/// what the payer holds before the transaction (plus, for a native claim whose payer is the
/// destination, the claimed amount: the credit lands before the fee transfer).
pub fn check_private_gas(estimate: &PrivateFeeEstimate, available: u128) -> Result<(), SdkError> {
    if available >= estimate.reserve {
        return Ok(());
    }
    Err(SdkError::InsufficientPrivateGas {
        required: estimate.reserve,
        available,
        shortfall: estimate.reserve.saturating_sub(available),
    })
}

/// A public claim's fee: the payer must hold the reserve `gas_limit * base_fee_exec + bytes *
/// base_fee_stor` (the door's check); it is charged the cycles used. `gas_limit` is the simulated
/// cycles plus 25% (the rc3 wallet's `public_gas_margin_percent`).
#[must_use]
pub fn estimate_public_fee(cycles: u64, tx_bytes: u64, quote: FeeQuote) -> (u64, u128, u128) {
    let gas_limit = cycles.saturating_add(cycles.div_ceil(4));
    let reserve = assess::fee_for(
        gas_limit,
        tx_bytes,
        0,
        quote.base_fee_exec,
        quote.base_fee_stor,
    );
    let expected = assess::fee_for(
        cycles,
        tx_bytes,
        0,
        quote.base_fee_exec,
        quote.base_fee_stor,
    );
    (gas_limit, reserve, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS: FeeQuote = FeeQuote {
        base_fee_exec: 8,
        base_fee_stor: 8,
    };

    #[test]
    fn matches_the_spike_measurement_at_genesis_fees() {
        // Measured in the private-claim spike (LEZ v0.4.0-rc3 harness): public part 61,008 cycles,
        // fee charged 5,558,680, the rc3 wallet's reserve 9,032,855.
        let e = estimate_private_fee(61_008, GENESIS, DEFAULT_HEADROOM_BLOCKS);
        assert_eq!(e.exec_gas, 470_772);
        assert_eq!(e.stor_gas, 224_063);
        assert_eq!(e.fee_at_head, 5_558_680);
        assert_eq!((e.exec_ceiling, e.stor_ceiling), (13, 13));
        assert_eq!(e.reserve, 9_032_855);
    }

    #[test]
    fn refuses_a_payer_below_the_reserve_with_the_shortfall() {
        let e = estimate_private_fee(61_008, GENESIS, DEFAULT_HEADROOM_BLOCKS);
        assert_eq!(check_private_gas(&e, 9_032_855), Ok(()));
        assert_eq!(
            check_private_gas(&e, 9_000_000),
            Err(SdkError::InsufficientPrivateGas {
                required: 9_032_855,
                available: 9_000_000,
                shortfall: 32_855
            })
        );
    }

    #[test]
    fn the_reserve_depends_on_public_inputs_only() {
        // Two payers with different balances publish the same reserve.
        let a = estimate_private_fee(61_008, GENESIS, DEFAULT_HEADROOM_BLOCKS);
        let b = estimate_private_fee(61_008, GENESIS, DEFAULT_HEADROOM_BLOCKS);
        assert_eq!(a.reserve, b.reserve);
    }

    #[test]
    fn public_fee_uses_the_wallet_margin() {
        let (limit, reserve, expected) = estimate_public_fee(61_008, 912, GENESIS);
        assert_eq!(limit, 76_260);
        assert_eq!(expected, 495_360); // the spike's public claim to an existing account: 61,008 cycles, 912 bytes
        assert!(reserve > expected);
    }
}
