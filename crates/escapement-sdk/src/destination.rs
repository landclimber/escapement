//! Claim destinations, and the check that a private claim's target is a private account
//! (RFP-017 +Privacy 3).
//!
//! A LEZ account id does not say whether it is public or private: both are 32-byte hashes. So the
//! SDK cannot recognise a private account from its id alone; it requires the account's private key
//! material (its nullifier public key and viewing public key, which only the owner's wallet holds)
//! and derives the id from it. A [`PrivateDestination`] can only be built that way, and the on-chain
//! destination of the claim is a fresh blinded alias of it, never the id itself.

use std::io::Read as _;

use lee_core::{account::AccountId, encryption::ViewingPublicKey, NullifierPublicKey};

use crate::SdkError;

/// The public half of a regular private account's keys, as the owner's wallet holds them.
#[derive(Clone)]
pub struct PrivateAccountKeys {
    pub npk: NullifierPublicKey,
    pub vpk: ViewingPublicKey,
}

impl PrivateAccountKeys {
    /// `AccountId::for_regular_private_account(npk, vpk)`.
    #[must_use]
    pub fn account_id(&self) -> AccountId {
        AccountId::for_regular_private_account(&self.npk, &self.vpk)
    }
}

/// A private account to claim into, under a one-time blinded alias.
///
/// Not `Clone`: a destination is used once, so an alias never appears in two claims.
pub struct PrivateDestination {
    owner: AccountId,
    factor: [u8; 32],
}

impl PrivateDestination {
    /// A destination with a fresh blinding factor from the operating system's randomness.
    ///
    /// # Panics
    /// If the system's randomness cannot be read.
    #[must_use]
    pub fn fresh(keys: &PrivateAccountKeys) -> Self {
        let mut factor = [0_u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut factor))
            .expect("system randomness");
        Self::with_factor(keys, factor)
    }

    /// A destination with a given factor (tests; a wallet uses [`Self::fresh`]).
    #[must_use]
    pub fn with_factor(keys: &PrivateAccountKeys, factor: [u8; 32]) -> Self {
        Self {
            owner: keys.account_id(),
            factor,
        }
    }

    /// The address published as the claim's destination: `owner.blinded(factor)`. Nobody without
    /// the factor can tell which account it names.
    #[must_use]
    pub fn alias(&self) -> AccountId {
        self.owner.blinded(&self.factor)
    }

    /// The private account itself. Never put this in a public message.
    #[must_use]
    pub const fn owner(&self) -> AccountId {
        self.owner
    }

    /// The opening the prover's witness carries (`PrivateWitness::address_openings`) so the alias
    /// resolves to the account inside the proof.
    #[must_use]
    pub const fn opening(&self) -> [u8; 32] {
        self.factor
    }
}

/// Where claimed tokens go.
pub enum ClaimDestination {
    /// A public account: fully visible, as on every other chain.
    Public(AccountId),
    /// A private account of the claimer's wallet, reached through a one-time alias.
    Private(PrivateDestination),
}

/// What the SDK can learn about an account id from the chain (`getAccount`).
pub trait AccountLookup {
    /// True if a public account with state exists at `account_id`.
    fn public_account_exists(&self, account_id: AccountId) -> bool;
}

/// Checks an account id a user picked as a private claim target and returns the destination.
///
/// Refuses with [`SdkError::NonShieldedPrivateTarget`] when the wallet holds no private keys for
/// the id, when the keys do not derive it, when it is the beneficiary's own public account, or when
/// a public account exists at it (a private account id cannot also be a public one).
pub fn validate_private_target(
    target: AccountId,
    wallet_keys: Option<&PrivateAccountKeys>,
    beneficiary: AccountId,
    chain: &impl AccountLookup,
) -> Result<PrivateDestination, SdkError> {
    let refuse = |reason| {
        Err(SdkError::NonShieldedPrivateTarget {
            account_id: target,
            reason,
        })
    };
    if target == beneficiary {
        return refuse("it is the beneficiary's public account");
    }
    let Some(keys) = wallet_keys else {
        return refuse("the wallet holds no private-account keys for it");
    };
    if keys.account_id() != target {
        return refuse("the private keys given do not derive this account id");
    }
    if chain.public_account_exists(target) {
        return refuse("a public account exists at this id");
    }
    Ok(PrivateDestination::fresh(keys))
}

#[cfg(test)]
mod tests {
    use lee_core::NullifierSecretKey;

    use super::*;

    struct Chain(Vec<AccountId>);
    impl AccountLookup for Chain {
        fn public_account_exists(&self, account_id: AccountId) -> bool {
            self.0.contains(&account_id)
        }
    }

    fn keys(seed: u8) -> PrivateAccountKeys {
        let nsk: NullifierSecretKey = [seed; 32];
        PrivateAccountKeys {
            npk: NullifierPublicKey::from(&nsk),
            vpk: ViewingPublicKey::from_seed(&[seed; 32], &[seed.wrapping_add(1); 32]),
        }
    }

    #[test]
    fn a_private_account_of_the_wallet_is_accepted_under_a_fresh_alias() {
        let k = keys(1);
        let beneficiary = AccountId::new([9; 32]);
        let a = validate_private_target(
            k.account_id(),
            Some(&k),
            beneficiary,
            &Chain(vec![beneficiary]),
        )
        .unwrap();
        let b = validate_private_target(
            k.account_id(),
            Some(&k),
            beneficiary,
            &Chain(vec![beneficiary]),
        )
        .unwrap();
        assert_eq!(a.owner(), k.account_id());
        assert_ne!(
            a.alias(),
            k.account_id(),
            "the published destination is not the account"
        );
        assert_ne!(a.alias(), b.alias(), "every claim gets a new alias");
        assert_eq!(a.alias(), k.account_id().blinded(&a.opening()));
    }

    #[test]
    fn non_shielded_targets_are_refused() {
        let k = keys(1);
        let beneficiary = AccountId::new([9; 32]);
        let public = AccountId::new([7; 32]);
        let chain = Chain(vec![beneficiary, public]);
        let reason = |r: Result<PrivateDestination, SdkError>| match r {
            Err(SdkError::NonShieldedPrivateTarget { reason, .. }) => reason,
            _ => "accepted",
        };
        assert_eq!(
            reason(validate_private_target(
                beneficiary,
                Some(&k),
                beneficiary,
                &chain
            )),
            "it is the beneficiary's public account"
        );
        assert_eq!(
            reason(validate_private_target(public, None, beneficiary, &chain)),
            "the wallet holds no private-account keys for it"
        );
        assert_eq!(
            reason(validate_private_target(
                public,
                Some(&k),
                beneficiary,
                &chain
            )),
            "the private keys given do not derive this account id"
        );
        // Keys that derive an id at which a public account exists (cannot happen honestly).
        let chain_with = Chain(vec![k.account_id()]);
        assert_eq!(
            reason(validate_private_target(
                k.account_id(),
                Some(&k),
                beneficiary,
                &chain_with
            )),
            "a public account exists at this id"
        );
    }
}
