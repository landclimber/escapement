//! `escapement_core_module`: Escapement's vesting module for Logos Core (prototype, unaudited).
//!
//! Rust-first, as the builder's Rust template: the trait below is the module's contract. The builder derives the
//! `.lidl` from it (`codegen.rust.trait` in metadata.json) and generates the C-ABI scaffold included below. Each method
//! takes and returns one JSON string; the work is done by `escapement-module-calls` (`calls/`), which runs and is tested
//! without the scaffold.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// The module's methods. The trait's name is the module's name in PascalCase.
pub trait EscapementCoreModule: Send + 'static {
    /// The module's version, what was staged (Escapement's commit, each crate's sources' SHA-256), the methods.
    fn version(&mut self) -> String;

    /// `{rpc_url, program, read_only?, asset_label?, decimals?}`: the LEZ v0.4 sequencer and the Escapement program.
    fn configure(&mut self, request: String) -> String;

    /// The network, the key's account (never the key), its balance, the pending transaction.
    fn status(&mut self, request: String) -> String;

    /// `{action: import|new|show|forget, path?}`: the signing key (from a key file, or made into the module's data
    /// directory); only the account id and public key are returned.
    fn key(&mut self, request: String) -> String;

    /// `{beneficiary?, creator?, ids?}`: the known schedules read live: positions (locked, claimable now, next
    /// unlock UTC) and the creator's schedules.
    fn schedules(&mut self, request: String) -> String;

    /// `{schedule}`: remember a schedule id on this network.
    fn track(&mut self, request: String) -> String;

    /// `{schedule, amount?, to?}`: a public claim, checked and built, waiting for approval (nothing signed).
    fn prepare_claim(&mut self, request: String) -> String;

    /// `{beneficiary, total, kind, start_ms, end_ms, cliff_ms?, cliff_amount?, cancelable?}`: a new native schedule,
    /// checked and built, waiting for approval (nothing signed).
    fn prepare_create(&mut self, request: String) -> String;

    /// `{schedule}`: a cancellation, checked and built, waiting for approval (nothing signed).
    fn prepare_cancel(&mut self, request: String) -> String;

    /// `{pending_id}`: sign the prepared transaction (only now), send it, report its block and outcome.
    fn approve(&mut self, request: String) -> String;

    /// `{pending_id?}`: drop the prepared transaction.
    fn reject(&mut self, request: String) -> String;

    /// `{tx_hash}`: a sent transaction's block and outcome.
    fn tx_status(&mut self, request: String) -> String;

    /// Called once the module is wired to the host.
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

// The builder injects the generated scaffold here: `install`, `RustModuleContext`, `context()`.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

/// The caller of the call being dispatched, as Logos Core names it (the SDK's `current_caller`): `module:<name>`,
/// `host`, or `unknown` (every other kind, which the module refuses). `calls::call` serves only the view and the host.
fn caller_name() -> String {
    match logos_rust_sdk::current_caller() {
        logos_rust_sdk::LogosCaller::Module { name, .. } => format!("module:{name}"),
        logos_rust_sdk::LogosCaller::HostAnchor => "host".to_string(),
        _ => "unknown".to_string(),
    }
}

#[derive(Default)]
struct Escapement;

/// One method through `calls::call`, with the caller; a panic must not cross into the host: reported as JSON instead.
fn guarded(method: &str, request: &str) -> String {
    let caller = caller_name();
    catch_unwind(AssertUnwindSafe(|| escapement_module_calls::call(method, request, &caller)))
        .unwrap_or_else(|_| serde_json::json!({ "ok": false, "error": format!("{method} failed inside the module (panic)") }).to_string())
}

impl EscapementCoreModule for Escapement {
    fn version(&mut self) -> String {
        guarded("version", "")
    }
    fn configure(&mut self, request: String) -> String {
        guarded("configure", &request)
    }
    fn status(&mut self, request: String) -> String {
        guarded("status", &request)
    }
    fn key(&mut self, request: String) -> String {
        guarded("key", &request)
    }
    fn schedules(&mut self, request: String) -> String {
        guarded("schedules", &request)
    }
    fn track(&mut self, request: String) -> String {
        guarded("track", &request)
    }
    fn prepare_claim(&mut self, request: String) -> String {
        guarded("prepare_claim", &request)
    }
    fn prepare_create(&mut self, request: String) -> String {
        guarded("prepare_create", &request)
    }
    fn prepare_cancel(&mut self, request: String) -> String {
        guarded("prepare_cancel", &request)
    }
    fn approve(&mut self, request: String) -> String {
        guarded("approve", &request)
    }
    fn reject(&mut self, request: String) -> String {
        guarded("reject", &request)
    }
    fn tx_status(&mut self, request: String) -> String {
        guarded("tx_status", &request)
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<Escapement>();
}
