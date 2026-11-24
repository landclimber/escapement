//! The privacy disclosure shown before every private claim (RFP-017 U5, +Privacy 2), and the
//! confirmation token that proves this exact text was shown for this exact claim.
//!
//! Wording follows the RFP's legally reviewed phrasing (logos-co/rfp PR #235): what is "recorded in
//! public on-chain state" and what is "not recorded in public on-chain state". Every statement is
//! checked against what Escapement's one-transaction private claim publishes on LEZ v0.4.0-rc3.

use lee_core::account::AccountId;
use sha2::{Digest as _, Sha256};

/// The facts of one private claim that the disclosure names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyDisclosure {
    /// The vesting schedule's account (its id).
    pub schedule_account: AccountId,
    pub beneficiary: AccountId,
    pub amount: u128,
    /// How the asset is shown to the user (e.g. "LGO", or a token's label).
    pub asset: String,
    /// The one-time alias published as the claim's destination.
    pub alias: AccountId,
    /// The fee reserve the proof credits, in plaintext, to the fee inbox.
    pub fee_reserve: u128,
}

/// SHA-256 of the rendered disclosure: passing it back shows the caller rendered and accepted
/// exactly this text for exactly this claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationToken(pub [u8; 32]);

impl std::fmt::Display for ConfirmationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl PrivacyDisclosure {
    /// The exact text the SDK's callers (mini-app, CLI) show before a private claim.
    #[must_use]
    pub fn render(&self) -> String {
        let Self {
            schedule_account,
            beneficiary,
            amount,
            asset,
            alias,
            fee_reserve,
        } = self;
        format!(
            "PRIVATE CLAIM: WHAT IS AND IS NOT RECORDED IN PUBLIC ON-CHAIN STATE\n\
             \n\
             Recorded in public on-chain state:\n\
             - Claim amount: {amount} {asset}.\n\
             - Beneficiary address (it signs this claim): {beneficiary}.\n\
             - Vesting schedule address: {schedule_account}, with all of its terms\n\
             \x20 (asset, total, type, start, cliff and end, cancel and milestone authorities).\n\
             - The claim's time: the block and the schedule's Claimed event\n\
             \x20 (schedule, beneficiary, amount, claimed so far, time).\n\
             - A one-time alias as the destination, {alias}. Without a secret that stays in your\n\
             \x20 wallet it does not identify your private account.\n\
             - That this is a privacy-preserving transaction, and its fee reserve of {fee_reserve} native\n\
             \x20 units, computed from public fee data, not from your balance.\n\
             \n\
             Not recorded in public on-chain state:\n\
             - Which private account receives the tokens, and its balance.\n\
             - Later movements of the claimed tokens made by private transfers.\n\
             - Whether this claim and your other claims went to the same private account.\n\
             - Which private account paid the fee.\n\
             \n\
             Limits:\n\
             - Your beneficiary address is public and tied to this schedule since its creation; this\n\
             \x20 claim is visible as yours.\n\
             - Moving exactly {amount} to a public account soon after can be matched by amount and\n\
             \x20 time; wait, split, or keep the tokens private.\n\
             - The schedule's creator sees the claim amount and time like everyone else, but not the\n\
             \x20 destination.\n\
             - If the receiving private account held nothing before, its balance afterwards is the\n\
             \x20 claim amount less the fee reserve: the account is not identified, but that number can\n\
             \x20 be inferred.\n\
             - Your RPC provider sees your network address when you send the transaction.\n"
        )
    }

    /// The token for this exact disclosure.
    #[must_use]
    pub fn token(&self) -> ConfirmationToken {
        ConfirmationToken(Sha256::digest(self.render().as_bytes()).into())
    }

    /// True if `token` is this disclosure's.
    #[must_use]
    pub fn accepts(&self, token: &ConfirmationToken) -> bool {
        self.token() == *token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disclosure() -> PrivacyDisclosure {
        PrivacyDisclosure {
            schedule_account: AccountId::new([2; 32]),
            beneficiary: AccountId::new([3; 32]),
            amount: 1_000_000,
            asset: "LGO".into(),
            alias: AccountId::new([4; 32]),
            fee_reserve: 9_032_855,
        }
    }

    #[test]
    fn names_the_rfp_items_recorded_and_not_recorded() {
        let text = disclosure().render();
        for must in [
            "Claim amount: 1000000 LGO",
            "Beneficiary address",
            &AccountId::new([3; 32]).to_string(),
            "Vesting schedule address",
            &AccountId::new([2; 32]).to_string(),
            "Not recorded in public on-chain state",
            "Which private account receives the tokens",
            "Later movements of the claimed tokens",
            "9032855",
        ] {
            assert!(text.contains(must), "missing {must:?}");
        }
        for banned in ["untraceable", "hidden", "anonymous"] {
            assert!(
                !text.to_lowercase().contains(banned),
                "absolute claim {banned:?}"
            );
        }
    }

    #[test]
    fn the_token_binds_the_exact_claim() {
        let d = disclosure();
        let t = d.token();
        assert!(d.accepts(&t));
        let other = PrivacyDisclosure {
            amount: 999_999,
            ..disclosure()
        };
        assert!(
            !other.accepts(&t),
            "another amount needs another confirmation"
        );
        let other_alias = PrivacyDisclosure {
            alias: AccountId::new([5; 32]),
            ..disclosure()
        };
        assert!(!other_alias.accepts(&t));
    }
}
