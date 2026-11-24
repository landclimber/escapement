//! Test-only guests: `RELAY_ELF` / `RELAY_ID`. A relay stands in for any other program a user might
//! sign a transaction for (a malicious one, or a multisig/launchpad acting as one of its own PDAs).
//! Registered under several program ids in tests so one relay can call another.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::Actor, program::PdaSeed};

/// A relay forwards `message` to `to` as a sync message, granting `seeds` (seeds of the relay
/// program's own PDAs only: LEZ ignores any other), or as an asynchronous message (LEZ passes no
/// grant on with those). It forwards at any call depth; anything else sent to it is recorded as its
/// actor state.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum RelayMessage {
    Forward {
        to: Actor,
        message: Vec<u8>,
        seeds: Vec<PdaSeed>,
    },
    ForwardAsync {
        to: Actor,
        message: Vec<u8>,
    },
}
