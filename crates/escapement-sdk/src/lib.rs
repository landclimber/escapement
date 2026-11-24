//! Client SDK of the Escapement vesting program (LEZ v0.4.0-rc3): everything a wallet, a Logos
//! module or the CLI checks and builds before a transaction is proven or signed.
//!
//! - [`builders`]: every program operation as `(root actor, declared actors, message bytes)`, for
//!   both assets (native LEZ and tokens), including `AsPda` calls for multisig/DAO PDAs.
//! - [`claim`]: the claim gates. A private claim goes through [`claim::prepare_private_claim`]:
//!   1. the destination is built only from private-account key material, anything else is refused
//!      with [`SdkError::NonShieldedPrivateTarget`] (+Privacy 3; [`destination`]);
//!   2. if nothing is claimable, [`SdkError::NothingClaimableYet`] carries the next unlock time (U7;
//!      [`unlock`]);
//!   3. the in-proof fee is priced with LEZ's own `fee_core` and refused with
//!      [`SdkError::InsufficientPrivateGas`] before proving if the payer cannot cover the reserve
//!      (U4; [`fees`]);
//!   4. the [`summary::PreClaimSummary`] (U4) and the [`disclosure::PrivacyDisclosure`] (U5,
//!      +Privacy 2) are filled, and the claim needs the confirmation token of that exact disclosure.
//! - [`codes`]: every program exit code (1..=35) as an actionable message.
//!
//! Schedule terms and math come from `escapement-core`, the crate the on-chain program uses: the
//! SDK has no formula of its own.

pub mod builders;
pub mod claim;
pub mod codes;
pub mod destination;
pub mod disclosure;
pub mod error;
pub mod fees;
pub mod summary;
pub mod unlock;

pub use claim::{
    prepare_private_claim, prepare_public_claim, ClaimContext, PreparedPrivateClaim,
    PreparedPublicClaim, PrivatePayer,
};
pub use destination::{ClaimDestination, PrivateAccountKeys, PrivateDestination};
pub use disclosure::{ConfirmationToken, PrivacyDisclosure};
pub use error::SdkError;
pub use fees::{FeeQuote, PrivateFeeEstimate};
pub use summary::{DestinationKind, PreClaimSummary};
pub use unlock::{next_unlock, NextUnlockReason};
