//! Test relay (never deployed): forwards a `Forward` message to any actor, granting seeds of its own
//! PDAs; anything else sent to it is recorded as its actor state.

use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use lee_core::{
    account::Actor,
    program::{PdaSeed, ReceiveInput, Response, SyncMessage},
};

#[derive(BorshDeserialize)]
enum RelayMessage {
    Forward {
        to: Actor,
        message: Vec<u8>,
        seeds: Vec<PdaSeed>,
    },
}

fn entry(input: &ReceiveInput) -> Response {
    match borsh::from_slice::<RelayMessage>(&input.message) {
        Ok(RelayMessage::Forward { to, message, seeds }) => Response::keep_state().send(SyncMessage {
            to,
            message,
            pda_seeds: seeds.into_iter().collect::<BTreeSet<_>>(),
        }),
        Err(_) => Response::set_state(input.message.clone()),
    }
}

lee_core::actor_entrypoint!(raw entry);
