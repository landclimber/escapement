# RFP-017 requirement traceability

A one-page summary. The clause-by-clause map that CI enforces (every clause quoted verbatim, every
named test checked to exist and to run in CI) is [REQUIREMENTS.md](REQUIREMENTS.md), generated from
[requirements-map.json](requirements-map.json) by `scripts/check-reqmap.py`.

Every requirement of RFP-017 (logos-co/rfp, `RFPs/RFP-017-token-vesting.md`, as published on
24 Nov 2026), its status, and the test or artefact that shows it.

**Status words, strictly:**
- **shown**: a test in this repository asserts it, and it passed on the run recorded in
  `docs/EVIDENCE.md` (in-process on LEZ `v0.4.0-rc3`'s state machine with the real guest, and/or on a
  standalone LEZ `v0.4.0-rc3` sequencer through `e2e/run_e2e.sh`);
- **in part**: the program or SDK side is shown; the named remainder is not built yet;
- **not yet**: nothing built;
- **waits on Logos**: needs LEZ testnet 0.4, which has not launched (latest LEZ tag `v0.4.0-rc3`).

Test files: `T` = `crates/escapement-tests/tests/escapement_e2e.rs`, `M` = `escapement-core` math
tests, `SDK` = `crates/escapement-sdk`, `IDL` = `crates/escapement-idl/tests/idl.rs`,
`E2E` = `e2e/run_e2e.sh` steps (standalone sequencer).

## Hard requirements

| Req | Requirement (short) | Status | Shown by |
|---|---|---|---|
| F1 | Escrowed schedules: cliff+linear, linear, milestone | shown | T `full_lifecycle_all_schedule_types_authorities_and_refusals`, `native_asset_lifecycle_*`; M property suites; E2E `create-linear`, `create-milestone`, `escrow-holds-total` |
| F2 | Beneficiary fixed at creation; claim to public or private account; creator does not learn the private account | shown | T `s1_private_claim_blinded_alias_single_tx_and_fresh_values_per_claim`, `adversarial_20_claim_no_leak_and_distinct_values_suite`, `native_asset_*` (private native claim); E2E `claim-public-partial`, `claim-private-new-account-*`, `claim-private-same-account-*`, `claim-private-token-*` (`private_account_id_in_tx_bytes == false`) |
| F3 | Cancelable by default; one-way non-cancelable; unvested back to creator; vested stays claimable | in part: shown except that the refund goes to the `refund_holding` the creator names at creation, which may be an account other than its own (default: the creator's account; see REQUIREMENTS F3c) | T `s2_time_asymmetry_*`, `c1_same_block_clock_lag_*`, `full_lifecycle_*`; SDK `f3a_requests_default_to_cancelable_*`; E2E `cancel-by-creator`, `cancel-froze-vesting`, `claim-vested-after-cancel`, `refusal-cancel-after-noncancelable-*` |
| F4 | Transferability set at creation, immutable | shown | T `full_lifecycle_*` (code 21); E2E `transfer-beneficiary`, `refusal-old-beneficiary-*`, `claim-by-new-beneficiary` |
| F5 | Batch creation; maximum per transaction documented | shown (testnet re-measure waits on Logos) | T `batch_create_concurrent_claims_and_exact_ceiling_benchmark`, `native_asset_*`; `docs/gas-and-batch.md` |
| F6 | An event per transition; schema documented | in part: emitted and asserted in-process (private claims included); schema in `docs/events.md` and the IDL; read-back through an indexer waits on Logos (testnet 0.4) | T (every suite decodes its events); `event::tests::compile_time_selectors_match_sha256`; IDL test; E2E `getEvents-is-not-a-sequencer-rpc-on-rc3` |
| U1 | SDK for Logos modules: full lifecycle, public and private claims | in part: Rust SDK (builders for every operation and both assets, claim gates, error mapping) and a CLI that drives a sequencer with it; a Logos Core module wrapper is not built | SDK tests (20); E2E (every step goes through SDK builders) |
| U2 | Basecamp mini-app (recipient and creator views) | not yet | |
| U3 | CLI: create, claim, cancel, signal, query claimable | in part: native and token schedules on a local sequencer (create, claim public and private, cancel, signal, show/claimable, token definition and holdings, private accounts); remote endpoints and wallet-held keys for testnet 0.4 not yet | `crates/escapement-cli` (unit tests: key file); E2E (all steps) |
| U4 | Pre-claim summary (claimable, fee); private-path gas check with an actionable error | in part: SDK and CLI (the CLI checks the private account's balance against the exact fee reserve before proving); mini-app display not yet | SDK `u4_an_underfunded_private_payer_is_refused_with_the_shortfall`, `fees::tests::*`; E2E `claim-private-*-applied`, `private-token-holding-applied` (balance after = credit − the reserve shown) |
| U5 | Privacy disclosure before each private claim | in part: SDK disclosure bound to a confirmation token; the CLI prints it with its token and sends only with `--confirm <token>`; mini-app not yet | SDK `u5_*`, `disclosure::tests::*`; E2E `*-disclosure-shown-and-nothing-sent`, `claim-private-wrong-token-refused`, `claim-private-wrong-token-changed-nothing` |
| U6 | IDL with SPEL | shown (SPEL's v0.4 generator from its `refactor/lez-v0.4.x` branch; released SPEL predates LEZ v0.4) | `idl/escapement.idl.json`; IDL `u6_generated_idl_matches_committed`, `u6_idl_covers_all_messages_states_events_and_round_trips` |
| U7 | Actionable errors, incl. next unlock time when nothing is claimable | in part: exit codes, SDK messages with the next unlock, CLI `show` and refusal before sending; mini-app display not yet | `VestingError` codes 1..=35 (T `comprehensive_error_codes_*`); SDK `codes::tests::*`, `u7_nothing_claimable_carries_the_next_unlock`; CLI `show` |
| R1 | Atomic claims; a failed claim loses nothing and can be retried | shown | T `s1_*` (rollbacks incl. a raced proven claim), `negative_guards_*`; E2E `refusal-overclaim-reverted-state-unchanged` |
| R2 | Atomic cancellation | shown | T `stateful_handler_conservation_invariant_suite` (double-cancel probe), `c1_*` (a cancel refused after its clock read, code 20: every account compared before and after); E2E `refusal-cancel-after-noncancelable-reverted-state-unchanged` |
| R3 | Concurrent claims on independent schedules do not corrupt state | shown | T `batch_create_concurrent_*`, `stateful_handler_conservation_invariant_suite` |
| R4 | Milestone signalling idempotent, deterministic error | shown | T `full_lifecycle_*` (code 25), `negative_guards_*`; E2E `refusal-double-signal-reverted-state-unchanged` |
| P1 | One claim, one transaction | in part: one transaction per claim (public: native and token; private: native, and token into an existing private holding); a fresh private token account first needs one private `InitializeHolding` transaction (folded into the claim in M2) | T `s1_*`, `native_asset_*`; E2E `claim-public-partial`, `claim-token-public`, `claim-private-new-account-confirm`, `claim-private-token-confirm`, `private-token-holding` |
| P2 | Cost of each operation, measured on testnet 0.4 | waits on Logos (measured on LEZ `v0.4.0-rc3`: `docs/gas-and-batch.md`) | T benchmark suites |
| S1 | Deployed and tested on testnet 0.4 | waits on Logos (immutable deployment and admin init shown on a standalone rc3 sequencer: E2E `deploy-immutable-and-init-admin`) | |
| S2 | E2E tests against a standalone sequencer, in CI, green on the default branch | shown: CI job `e2e-standalone-sequencer` (`.github/workflows/ci.yml`) green on the default branch (first public run, 24 Nov 2026, see EVIDENCE "CI"); it re-runs on every push | `e2e/run_e2e.sh` (EVIDENCE E-12, E-13) |
| S3 | A test for every hard requirement | in part (U2 has none) | this table |
| S4 | README with deployment, addresses, CLI and mini-app usage | in part: deployment and CLI usage; testnet addresses and mini-app usage not yet | `README.md` |

## +Privacy

| Req | Requirement (short) | Status | Shown by |
|---|---|---|---|
| Pr1 | Mini-app and SDK support public and private claims | in part: SDK and CLI; mini-app not yet | SDK, CLI, E2E `claim-private-new-account-*`, `claim-private-token-*` |
| Pr2 | Disclosure in the mini-app before each private claim | in part: SDK/CLI disclosure; mini-app not yet | SDK `u5_*` |
| Pr3 | SDK validates the private target before submitting | shown (the CLI runs the same check on its key file's account before building anything) | SDK `pr3_a_public_target_on_the_private_path_is_refused_before_anything_is_built`, `destination::tests::*` |

## Soft requirements and fee statements

| Req | Status | Shown by |
|---|---|---|
| SR1 separate cancellation authority | shown (exclusive; a multisig/DAO PDA acts through `AsPda`) | T `full_lifecycle_*`, `sec_pda_cpi_succeeds_and_inherited_seed_relay_refused` |
| SR2 separate milestone authority, creator excluded | shown | T `full_lifecycle_*` (creator refused, 13), `sec_pda_*`; E2E `refusal-creator-signal-reverted-state-unchanged`, `signal-by-authority` |
| FS1–FS4 who pays, when, rate, routing | shown: creator only, at creation, 0 bps at launch (cap 100 bps, broker up to 500 bps), per-asset fee vaults withdrawn by the treasury | T `s3_lez_admin_authority_fee_switch_multi_token_vaults_and_immutability`, `native_asset_*` |

## Security properties beyond the RFP

| Property | Shown by |
|---|---|
| A program the user signs for cannot act in the user's name (code 35), by a sync or an asynchronous message | T `sec_relay_eoa_refused`, `sec_pda_*`, `sec_signer_authority_review_gaps` |
| Cancel never refunds claimed or claim-proven vested tokens under clock lag | T `c1_*`, `audit_lagged_cancel_*`; M `split_on_cancel_*`; Kani harness (claimed tokens; see EVIDENCE) |
| Reproducible guest (image id independent of build path) | `scripts/build-guest.sh --check`, `image-ids.tsv` |
| Immutable deployment, header read back | E2E `deploy-immutable-and-init-admin`, `header-immutable-and-image-id` |
