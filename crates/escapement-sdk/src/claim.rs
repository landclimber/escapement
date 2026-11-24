//! The claim gates: everything checked before a claim is proven (private) or signed (public).
//!
//! A private claim (`ClaimExact`) always names a fixed amount and an `effective_ts` at or before the
//! block that includes it: the program checks `claimed + amount <= vested(effective_ts)` and binds
//! the transaction to blocks with `timestamp >= effective_ts`, so a proof that takes minutes stays
//! valid while time passes (the claimable amount only grows; a cancellation keeps the vested part).

use escapement_core::{Asset, ScheduleAccount};
use lee_core::account::AccountId;

use crate::{
    destination::{validate_private_target, AccountLookup, PrivateAccountKeys, PrivateDestination},
    disclosure::{ConfirmationToken, PrivacyDisclosure},
    fees::{
        check_private_gas, estimate_private_fee, estimate_public_fee, FeeQuote, PrivateFeeEstimate,
        DEFAULT_HEADROOM_BLOCKS,
    },
    summary::{DestinationKind, PreClaimSummary},
    unlock::{claimable, next_unlock},
    SdkError,
};

/// What a claim is about (read from the chain and the wallet).
pub struct ClaimContext<'a> {
    /// The schedule's account id.
    pub schedule_account: AccountId,
    /// The schedule's on-chain state (`VestingActorState::Schedule`).
    pub schedule: &'a ScheduleAccount,
    /// The account that will sign (must be the beneficiary).
    pub signer: AccountId,
    /// How the asset is shown to the user.
    pub asset_label: String,
    /// The LEZ clock as the program reads it (public claims), or the private claim's `effective_ts`.
    pub now_ms: u64,
    /// `None`: everything claimable now (fixed at this moment).
    pub requested: Option<u128>,
    pub quote: FeeQuote,
    /// Public cycles of the claim, from a simulation.
    pub public_cycles: u64,
}

/// The amount to claim now, or why there is none.
fn amount(ctx: &ClaimContext<'_>) -> Result<(u128, u128), SdkError> {
    if ctx.signer != ctx.schedule.beneficiary {
        return Err(SdkError::NotBeneficiary {
            beneficiary: ctx.schedule.beneficiary,
        });
    }
    if ctx.requested == Some(0) {
        return Err(SdkError::ZeroAmount);
    }
    let now_claimable = claimable(ctx.schedule, ctx.now_ms);
    if now_claimable == 0 {
        let (next_unlock_ms, reason) = next_unlock(ctx.schedule, ctx.now_ms);
        return Err(SdkError::NothingClaimableYet {
            next_unlock_ms,
            reason,
        });
    }
    match ctx.requested {
        None => Ok((now_claimable, now_claimable)),
        Some(requested) if requested <= now_claimable => Ok((requested, now_claimable)),
        Some(requested) => Err(SdkError::ExceedsClaimable {
            requested,
            claimable: now_claimable,
        }),
    }
}

/// The private fee payer.
pub struct PrivatePayer<'a> {
    /// The wallet's label for it (printed instead of its id).
    pub label: &'a str,
    /// Its native balance before the transaction.
    pub balance: u128,
    /// It is also the destination (then a native claim's credit can pay the fee).
    pub is_destination: bool,
}

/// A private claim that passed every check, waiting for the disclosure's confirmation.
pub struct PreparedPrivateClaim {
    pub destination: PrivateDestination,
    pub amount: u128,
    pub effective_ts: u64,
    pub fee: PrivateFeeEstimate,
    pub summary: PreClaimSummary,
    pub disclosure: PrivacyDisclosure,
}

/// A private claim the user confirmed: what the prover needs.
pub struct ConfirmedPrivateClaim {
    pub destination: PrivateDestination,
    pub amount: u128,
    pub effective_ts: u64,
    pub reserve: u128,
}

impl PreparedPrivateClaim {
    /// The only way to a [`ConfirmedPrivateClaim`]: the token of this claim's disclosure.
    ///
    /// # Errors
    /// [`SdkError::PrivacyDisclosureNotConfirmed`] if `token` is not this disclosure's.
    pub fn confirm(self, token: &ConfirmationToken) -> Result<ConfirmedPrivateClaim, SdkError> {
        if !self.disclosure.accepts(token) {
            return Err(SdkError::PrivacyDisclosureNotConfirmed);
        }
        Ok(ConfirmedPrivateClaim {
            destination: self.destination,
            amount: self.amount,
            effective_ts: self.effective_ts,
            reserve: self.fee.reserve,
        })
    }
}

/// Checks a private claim in order: the target is private (+Privacy 3), the signer is the
/// beneficiary, something is claimable (U7), the private payer covers the full reserve (U4); then
/// fills the summary and the disclosure (U5, +Privacy 2).
///
/// # Errors
/// The first failed check, before anything is proven or sent.
pub fn prepare_private_claim(
    ctx: &ClaimContext<'_>,
    target: AccountId,
    target_keys: Option<&PrivateAccountKeys>,
    payer: &PrivatePayer<'_>,
    chain: &impl AccountLookup,
) -> Result<PreparedPrivateClaim, SdkError> {
    let destination =
        validate_private_target(target, target_keys, ctx.schedule.beneficiary, chain)?;
    let (amount, now_claimable) = amount(ctx)?;
    let fee = estimate_private_fee(ctx.public_cycles, ctx.quote, DEFAULT_HEADROOM_BLOCKS);
    let available = if payer.is_destination && ctx.schedule.asset == Asset::Native {
        payer.balance.saturating_add(amount)
    } else {
        payer.balance
    };
    check_private_gas(&fee, available)?;
    let summary = PreClaimSummary {
        schedule_account: ctx.schedule_account,
        asset: ctx.asset_label.clone(),
        claimable_now: now_claimable,
        requested_amount: amount,
        estimated_exec_gas: fee.exec_gas,
        estimated_stor_gas: fee.stor_gas,
        estimated_fee_native: fee.fee_at_head,
        required_balance_native: fee.reserve,
        base_fee_exec: fee.base_fee_exec,
        base_fee_stor: fee.base_fee_stor,
        fee_payer: format!("private account {}", payer.label),
        fee_payer_balance: payer.balance,
        sufficient_gas: true,
        destination_kind: DestinationKind::Private,
    };
    let disclosure = PrivacyDisclosure {
        schedule_account: ctx.schedule_account,
        beneficiary: ctx.schedule.beneficiary,
        amount,
        asset: ctx.asset_label.clone(),
        alias: destination.alias(),
        fee_reserve: fee.reserve,
    };
    Ok(PreparedPrivateClaim {
        destination,
        amount,
        effective_ts: ctx.now_ms,
        fee,
        summary,
        disclosure,
    })
}

/// A public claim that passed every check.
pub struct PreparedPublicClaim {
    pub destination: AccountId,
    pub amount: u128,
    pub gas_limit: u64,
    pub summary: PreClaimSummary,
}

/// Checks a public claim: the signer is the beneficiary, something is claimable, and reports
/// whether the public payer holds the fee reserve. (`tx_bytes`: the signed transaction's size.)
///
/// # Errors
/// The first failed check.
pub fn prepare_public_claim(
    ctx: &ClaimContext<'_>,
    destination: AccountId,
    payer: AccountId,
    payer_balance: u128,
    tx_bytes: u64,
) -> Result<PreparedPublicClaim, SdkError> {
    let (amount, now_claimable) = amount(ctx)?;
    let (gas_limit, reserve, expected) =
        estimate_public_fee(ctx.public_cycles, tx_bytes, ctx.quote);
    let summary = PreClaimSummary {
        schedule_account: ctx.schedule_account,
        asset: ctx.asset_label.clone(),
        claimable_now: now_claimable,
        requested_amount: amount,
        estimated_exec_gas: ctx.public_cycles,
        estimated_stor_gas: tx_bytes,
        estimated_fee_native: expected,
        required_balance_native: reserve,
        base_fee_exec: ctx.quote.base_fee_exec,
        base_fee_stor: ctx.quote.base_fee_stor,
        fee_payer: payer.to_string(),
        fee_payer_balance: payer_balance,
        sufficient_gas: payer_balance >= reserve,
        destination_kind: DestinationKind::Public,
    };
    Ok(PreparedPublicClaim {
        destination,
        amount,
        gas_limit,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use escapement_core::ScheduleKind;
    use lee_core::{encryption::ViewingPublicKey, NullifierPublicKey, NullifierSecretKey};

    use super::*;
    use crate::unlock::NextUnlockReason;

    struct Chain;
    impl AccountLookup for Chain {
        fn public_account_exists(&self, _: AccountId) -> bool {
            false
        }
    }

    fn keys() -> PrivateAccountKeys {
        let nsk: NullifierSecretKey = [7; 32];
        PrivateAccountKeys {
            npk: NullifierPublicKey::from(&nsk),
            vpk: ViewingPublicKey::from_seed(&[7; 32], &[8; 32]),
        }
    }

    fn schedule(claimed: u128) -> ScheduleAccount {
        let a = AccountId::new([3; 32]);
        ScheduleAccount {
            version: 1,
            asset_program_id: AccountId::new([0; 32]),
            creator: AccountId::new([9; 32]),
            beneficiary: a,
            asset: Asset::Native,
            escrow_seed: [2; 32],
            escrow_account: AccountId::new([4; 32]),
            refund_holding: AccountId::new([9; 32]),
            total_amount: 1_000_000_000_000,
            claimed_amount: claimed,
            kind: ScheduleKind::Linear {
                start_ts: 0,
                end_ts: 100_000_000,
            },
            cancelable: true,
            transferable: false,
            cancel_authority: None,
            milestone_authority: None,
            cancelled: None,
        }
    }

    fn ctx(s: &ScheduleAccount, now_ms: u64, requested: Option<u128>) -> ClaimContext<'_> {
        ClaimContext {
            schedule_account: AccountId::new([2; 32]),
            schedule: s,
            signer: AccountId::new([3; 32]),
            asset_label: "LGO".into(),
            now_ms,
            requested,
            quote: FeeQuote {
                base_fee_exec: 8,
                base_fee_stor: 8,
            },
            public_cycles: 61_008,
        }
    }

    #[test]
    fn pr3_a_public_target_on_the_private_path_is_refused_before_anything_is_built() {
        let s = schedule(0);
        let payer = PrivatePayer {
            label: "savings",
            balance: u128::MAX,
            is_destination: false,
        };
        let r = prepare_private_claim(
            &ctx(&s, 50_000_000, None),
            AccountId::new([7; 32]),
            None,
            &payer,
            &Chain,
        );
        assert!(matches!(r, Err(SdkError::NonShieldedPrivateTarget { .. })));
    }

    #[test]
    fn u7_nothing_claimable_carries_the_next_unlock() {
        let s = schedule(500_000_000_000);
        let r = prepare_public_claim(
            &ctx(&s, 50_000_000, None),
            AccountId::new([3; 32]),
            AccountId::new([3; 32]),
            u128::MAX,
            900,
        );
        match r {
            Err(SdkError::NothingClaimableYet {
                next_unlock_ms: Some(t),
                reason: NextUnlockReason::LinearAccrual,
            }) => assert!(t > 50_000_000),
            Err(e) => panic!("unexpected {e}"),
            Ok(_) => panic!("claim accepted with nothing claimable"),
        }
    }

    #[test]
    fn u4_an_underfunded_private_payer_is_refused_with_the_shortfall() {
        let s = schedule(0);
        let k = keys();
        let payer = PrivatePayer {
            label: "fees",
            balance: 1_000,
            is_destination: false,
        };
        let r = prepare_private_claim(
            &ctx(&s, 50_000_000, Some(10)),
            k.account_id(),
            Some(&k),
            &payer,
            &Chain,
        );
        match r {
            Err(SdkError::InsufficientPrivateGas {
                available,
                shortfall,
                ..
            }) => {
                assert_eq!(available, 1_000);
                assert!(shortfall > 0);
            }
            Err(e) => panic!("unexpected {e}"),
            Ok(_) => panic!("underfunded private claim accepted"),
        }
    }

    #[test]
    fn u5_a_private_claim_needs_the_confirmation_of_its_own_disclosure() {
        let s = schedule(0);
        let k = keys();
        let payer = PrivatePayer {
            label: "dest",
            balance: 0,
            is_destination: true,
        };
        let p = prepare_private_claim(
            &ctx(&s, 50_000_000, None),
            k.account_id(),
            Some(&k),
            &payer,
            &Chain,
        )
        .expect("a self-funded native private claim passes");
        assert!(p.summary.render().contains("private account"));
        let wrong = crate::disclosure::ConfirmationToken([0; 32]);
        let token = p.disclosure.token();
        let p2 = prepare_private_claim(
            &ctx(&s, 50_000_000, None),
            k.account_id(),
            Some(&k),
            &payer,
            &Chain,
        )
        .unwrap();
        assert!(matches!(
            p2.confirm(&wrong),
            Err(SdkError::PrivacyDisclosureNotConfirmed)
        ));
        let c = p.confirm(&token).expect("own token confirms");
        assert_eq!(c.amount, 500_000_000_000);
    }

    #[test]
    fn only_the_beneficiary_may_claim_and_overclaims_are_refused() {
        let s = schedule(0);
        let mut c = ctx(&s, 50_000_000, Some(600_000_000_000));
        assert!(matches!(
            prepare_public_claim(&c, AccountId::new([3; 32]), AccountId::new([3; 32]), 0, 900),
            Err(SdkError::ExceedsClaimable { .. })
        ));
        c.signer = AccountId::new([8; 32]);
        assert!(matches!(
            prepare_public_claim(&c, AccountId::new([3; 32]), AccountId::new([8; 32]), 0, 900),
            Err(SdkError::NotBeneficiary { .. })
        ));
    }
}
