# RFP-017 Requirement Traceability Matrix

Every hard requirement, privacy requirement, and soft requirement from `RFP-017-token-vesting.md`, mapped to its implementation status as of 2026-11-20, target milestone, and named automated test.

**Status legend:**
- **PROVEN (v0.4 prototype):** Already implemented and passing in this repository against real compiled `ESCAPEMENT_ELF`, `TOKEN_ELF`, and `CLOCK_ELF` on LEZ `v0.4.0-rc3`.
- **PLANNED (M1–M6):** Scheduled in the grant milestones below.

| Req ID | Requirement Summary | Status (2026-11-20) | Milestone | Named Test / Artifact |
|---|---|---|---|---|
| **F1** | Cliff+linear, fully linear, milestone schedules escrowed on LEZ | **PROVEN** (guest + core) | M1 (hardening + Kani) | `full_lifecycle_all_schedule_types_authorities_and_refusals`, `math::tests::*` |
| **F2** | Beneficiary set at creation; claim public or private; creator never learns private dest | **PROVEN** (guest + real proof) | M2 (sequencer E2E) | `s1_private_claim_blinded_alias_single_tx_and_unlinkability`, `s1_real_proof_dev_mode_0`, `adversarial_20_claim_privacy_linkability_suite` |
| **F3** | Cancelable default; irreversible `MakeNonCancelable`; unvested -> creator, vested stays claimable | **PROVEN** (guest) | M1–M2 | `s2_time_asymmetry_validity_window_and_live_clock_cancel`, `full_lifecycle_all_schedule_types_authorities_and_refusals` |
| **F4** | Transferability set at creation, immutable afterwards | **PROVEN** (guest) | M2 | `full_lifecycle_all_schedule_types_authorities_and_refusals` |
| **F5** | Multi-recipient batch creation up to LEZ tx limit; `N_max` documented | **PROVEN** (`N_max = 204` measured) | M1 (SDK chunking in M3) | `batch_create_concurrent_claims_and_exact_ceiling_benchmark` |
| **F6** | Log event (`ProgramEvent`) on all 5 transitions; schema documented | **PROVEN** (guest + selectors) | M1–M2 (`docs/events.md` + decoder) | `s1_*`, `s2_*`, `s3_*`, `full_lifecycle_*`, `crates/escapement-core/src/event.rs` |
| **Fee 1–4** | Who pays, when collected, rate + governance switch, routing | **PROVEN** (`lez-admin-authority` v0.2.0) | M1 | `s3_lez_admin_authority_fee_switch_and_immutability` |
| **U1** | SDK + Logos Core module exposing full lifecycle (public & private) | PLANNED | M3 | `escapement-sdk` + `escapement_core_module` (`u1_sdk_and_module_full_lifecycle`) |
| **U2** | Basecamp QML/C++ mini-app (recipient + creator views, `.lgx`, git-loadable) | PLANNED | M4 | `escapement_ui` (`u2_basecamp_recipient_and_creator_flows`) |
| **U3** | CLI covering create, claim, cancel, signal milestone, query claimable | PLANNED | M3 | `escapement-cli` (`u3_cli_core_lifecycle_e2e`) |
| **U4** | Pre-claim confirmation summary + private-path native gas sufficiency check | PLANNED | M4 | `u4_preclaim_summary_and_insufficient_gas_error` |
| **U5** | Pre-claim privacy disclosure before each private claim | PLANNED | M4 | `u5_privacy_disclosure_gates_private_claim` |
| **U6** | Program IDL (actor IDL v2 via `idl-gen` + SPEL parity when v0.4 ships) | PLANNED | M2 | `artifacts/escapement-idl.json` (`u6_idl_generation_and_drift_check`) |
| **U7** | Actionable errors incl. nothing-yet-claimable with next unlock time | **PROVEN** (core + exit codes 1..30) | M1–M4 | `full_lifecycle_*` (`exit code 26` + `next_unlock_after`) |
| **R1** | Atomic claims; failed/rejected claim loses zero tokens and retries cleanly | **PROVEN** (public + private) | M2 | `s1_private_claim_blinded_alias_single_tx_and_unlinkability` (uninit + unpromoted rollback & retry) |
| **R2** | Atomic cancellation; partial failure leaves prior state intact | **PROVEN** (runtime atomicity) | M2 | `s2_*`, `stateful_handler_conservation_invariant_suite` |
| **R3** | Concurrent claims on independent schedules do not corrupt shared state | **PROVEN** (incl. shared batch escrow) | M2 | `batch_create_concurrent_claims_and_exact_ceiling_benchmark`, `stateful_handler_conservation_invariant_suite` |
| **R4** | Idempotent milestone signalling per index; double-signal deterministically rejected | **PROVEN** (`exit code 25`) | M1 | `full_lifecycle_all_schedule_types_authorities_and_refusals` |
| **P1** | Single claim completes in 1 LEZ transaction (public & private) | **PROVEN** (public + real-proof private) | M2 | `s1_private_claim_blinded_alias_single_tx_and_unlinkability`, `s1_real_proof_dev_mode_0` |
| **P2** | Measured CU (cycle) cost per operation on LEZ testnet 0.4 | **PROVEN** (in-process `v0.4.0-rc3`); testnet 0.4 in M5 | M5 | `batch_create_concurrent_claims_and_exact_ceiling_benchmark`, `docs/EVIDENCE.md` |
| **S1** | Deployed and tested on LEZ testnet 0.4 | PLANNED (testnet 0.4 not live yet) | M5 | `DEPLOYMENTS.md` + `scripts/verify-testnet.sh` |
| **S2** | E2E integration tests against standalone LEZ sequencer in green CI on `main` | PLANNED (in-process CI ready now; standalone sequencer in M1) | M1–M5 | `.github/workflows/ci.yml` |
| **S3** | Every hard requirement mapped to at least one named automated test | **PROVEN** (matrix live; full coverage by M5) | M5 | `docs/traceability.md` |
| **S4** | README documenting deploy, addresses, CLI + mini-app usage | PLANNED (prototype README live now) | M5 | `README.md` |
| **Pr1** | SDK & mini-app support claiming to public and private accounts | Program **PROVEN**; SDK/UI PLANNED | M2–M4 | `s1_*`, M3/M4 suites |
| **Pr2** | Pre-confirmation privacy disclosure in mini-app before every private claim | PLANNED | M4 | `u5_privacy_disclosure_gates_private_claim` |
| **Pr3** | SDK validates shielded target before submit, rejecting public targets | PLANNED | M3 | `pr3_sdk_rejects_public_target` |
| **Soft-1** | Exclusive nominated `cancel_authority` distinct from creator, pinned refund | **PROVEN** (guest) | M2 (PDA multisig E2E) | `full_lifecycle_all_schedule_types_authorities_and_refusals` |
| **Soft-2** | Exclusive nominated `milestone_authority` distinct from creator | **PROVEN** (guest) | M2 (PDA multisig E2E) | `full_lifecycle_all_schedule_types_authorities_and_refusals` |
