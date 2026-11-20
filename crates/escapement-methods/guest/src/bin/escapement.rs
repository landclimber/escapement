//! Escapement RISC Zero guest binary: one actor delivery per run.

lee_core::actor_entrypoint!(raw escapement_program::handle_message);
