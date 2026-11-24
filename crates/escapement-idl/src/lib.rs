//! The SPEL IDL v2 of the Escapement program, generated from `crates/escapement-core` by SPEL's own
//! generator (`spel_framework_core::idl_gen::generate_idl`, what `spel generate-idl` runs):
//!
//! ```text
//! spel generate-idl crates/escapement-core --message Message --state VestingActorState --events event --namespace escapement
//! ```
//!
//! Program messages travel inside `lez_authority::Wire::Program`, which encodes the `Message` bytes
//! unchanged; `Wire::Library` (tag byte 255) carries `lez-admin-authority`'s admin operations.

use std::path::PathBuf;

use spel_framework_core::{
    idl::SpelIdl,
    idl_gen::{generate_idl, GenOptions},
};

/// `crates/escapement-core`.
#[must_use]
pub fn core_crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../escapement-core")
}

/// `idl/escapement.idl.json`.
#[must_use]
pub fn idl_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../idl/escapement.idl.json")
}

/// The IDL as SPEL generates it now, and its JSON text (pretty, newline-terminated).
///
/// # Panics
/// If generation fails (a renamed type, an undescribable field).
#[must_use]
pub fn generate() -> (SpelIdl, String) {
    let options = GenOptions {
        crate_dir: core_crate_dir(),
        message: "Message".to_owned(),
        state: Some("VestingActorState".to_owned()),
        events: Some("event".to_owned()),
        namespace: Some("escapement".to_owned()),
    };
    let idl =
        generate_idl(&options, |warning| eprintln!("spel: {warning}")).expect("the IDL generates");
    let mut json = idl.to_json_pretty().expect("the IDL serializes");
    json.push('\n');
    (idl, json)
}
