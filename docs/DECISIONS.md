# Escapement — Public Architecture Decision Log

All decisions recorded with UTC date, rationale, and rejected alternatives. Every LEZ v0.4 fact was verified against `logos-blockchain/logos-execution-zone` tag `v0.4.0-rc3`, `logos-blockchain/lez-programs` branch `refactor/lez-v0.4.x` (`cad71fc6`), and `mmlado/lez-admin-authority` tag `v0.2.0`.

---

## D-01 (2026-11-20): Native LEZ v0.4 actor architecture instead of v0.2/v0.3 `ChainedCall`

- **Decision:** Build Escapement directly on LEZ v0.4's actor-message runtime (`lee_core::actor_entrypoint!(raw handle_message)`, `SyncMessage`, `AsyncMessage`, `StateReply`, `Response::timestamp_window`, `clock_core::Message::ReadTimestamp`).
- **Reason:** RFP-017 Supportability #1 targets **LEZ testnet 0.4**. LEZ v0.4 removed `ChainedCall` and `pre_states` account lists; every program now processes one actor per delivery.
- **Alternative rejected:** Writing a v0.2/v0.3 program with a deferred v0.4 port. That creates double work and hides real v0.4 constraints (actor admission, single-actor authorization, promoted async token settlement, clock-expiry in PPTXs).

## D-02 (2026-11-20): Asymmetric time verification (`timestamp_window` for private claims vs live `clock_actor()` for public claims and `Cancel`)

- **Decision:** `ClaimExact` (private path) enforces `block_ts >= effective_ts` via `Response::timestamp_window(effective_ts..)` without calling `clock_actor()`. `ClaimPublic`, `Cancel`, and `SignalMilestone` synchronously read `clock_actor()` with `ReadTimestamp { granularity: 1 }`.
- **Reason:** `clock_core/src/lib.rs` explicitly notes that a privacy-preserving transaction reading `clock` expires as soon as the rounded clock value changes. Under 25–300 s CPU RISC Zero proving, fine-grained clock reads cause private claims to fail on arrival, while coarse rounding (e.g., 1 hour) delays cliff unlocks. `timestamp_window(effective_ts..)` is sound whenever the caller's incentive is to inflate `t` (claiming earlier), never expires during proving, saves ~46k public cycles, and preserves 1-ms precision. Conversely, `Cancel` MUST read live `clock_actor()` because a malicious creator would otherwise supply a stale `effective_ts` to claw back already-vested tokens.
- **Alternative rejected:** Coarse-granularity `ReadTimestamp` on private claims (adds UX lag at cliff unlock and still expires on bucket boundaries) or caller-supplied `effective_ts` on `Cancel` (exploitable by creator).

## D-03 (2026-11-20): Single-transaction private token claim via blinded-alias promoted `AsyncMessage`

- **Decision:** `ClaimExact` transfers vested tokens from `escrow_pda` to a fresh per-claim blinded alias `dest_priv.blinded(fresh_factor)`. The PPTX supplies `fresh_factor` in `PrivateWitness.address_openings` and promotes `token`'s `Internal::IncreaseBalance` via `public_context.promotions`.
- **Reason:** Verified in `s1_private_claim_blinded_alias_single_tx_and_unlinkability` and `s1_real_proof_dev_mode_0`: completes in **1 LEZ transaction** (`P1`), leaves **zero** mailbox publications, emits **zero** `Transferred` events (`M::EMITS_EVENTS == false` on private execution), never exposes `dest_priv` in any public byte or event (`F2`), makes repeated claims to the same private wallet pairwise unlinkable (`20/20` distinct aliases), and fails atomically (`UnboundAsyncDestination`) if promotion is omitted (`R1`).
- **Alternative rejected:** Public-to-private mailbox credit (`Publication::Clear`, which exposes `dest_priv` in plaintext, requires a pre-registered `recovery_binding`, and takes 2 transactions) or intermediate public burn/shield hop (2 transactions, violates `P1`).

## D-04 (2026-11-20): Cycle-metered guest exit codes (`env::exit(1..=30)`) instead of panics

- **Decision:** Every deterministic vesting refusal (`VestingError`, codes `1..=30`) exits with `risc0_zkvm::guest::env::exit(code)` on `target_os = "zkvm"` rather than `panic!`.
- **Reason:** Verified in LEZ `v0.4.0-rc3` (`validated_state_diff/mod.rs:503-513`): panics lose the cycle count and bill the caller's entire declared `gas_limit` (up to `10,000,000` cycles). Non-zero exit codes return `LeeError::ProgramExitedWithCode { code, cycles }` and bill only metered cycles executed (`16,003` cycles measured on a pre-cliff refusal — `0.16%` of the 10M cap, a 625× savings over a panic).
- **Alternative rejected:** `panic!` on user errors (penalizes accidental early claims or stale retries with full gas-limit burn).

## D-05 (2026-11-20): Creator-paid, creation-only fee switch (`0 bps` default, `<= 100 bps` immutable cap) via `lez-admin-authority` v0.2.0

- **Decision:** Reuse `mmlado/lez-admin-authority` `v0.2.0` (RFP-001 on LEZ v0.4) to gate `Message::Configure`. Initial protocol fee is `0 bps`; immutable compile-time cap is `100 bps` (1.00%); optional integrator broker fee is caller-supplied up to `500 bps` (default `0`). Fees are additive and collected strictly from the creator at schedule creation, never from beneficiaries and never retroactively on existing schedules. `token_program_id` is write-once and immutable once set.
- **Reason:** Matches RFP-017's recommended baseline and the zero-fee market equilibrium (Sablier, Hedgey, Jupiter Lock), avoids any beneficiary skim on private claims, and guarantees existing schedules are immune to governance capture.
- **Implementation note:** `lez-admin-authority` v0.2.0 forwards seat messages to `config_pda` without `pda_seeds`, which triggers `UnadmittedPublicActor` on `AdminOp::Init` against live `V03State`. Our guest attaches `CONFIG_SEED` to seat->config forwards so `config_pda` admits cleanly onchain without requiring extra wallet-side `admission_evidence`.

## D-06 (2026-11-20): Exclusive delegated authorities (`Soft-1`, `Soft-2`) with immutably pinned `refund_holding`

- **Decision:** When `cancel_authority` is `Some(addr)`, `addr` exclusively replaces `creator` for `Cancel` and `MakeNonCancelable`; when `milestone_authority` is `Some(addr)`, `addr` exclusively replaces `creator` for `SignalMilestone`. `refund_holding` is validated via `token::ReadState` at creation and frozen immutably.
- **Reason:** Allowing `creator` to retain fallback milestone authority when delegated to a governance multisig would reintroduce the exact self-dealing vulnerability RFP-017 Soft-2 exists to prevent (creator collateral vesting from RFP-015/016 launchpads). Pinning `refund_holding` ensures a delegated `cancel_authority` can never redirect unvested tokens to itself.

## D-07 (2026-11-20): Dedicated single-schedule escrow PDA + shared batch escrow PDA + donation-proof balance-delta checks

- **Decision:** Single schedules use a dedicated `escrow_pda`; `BatchCreate` uses a write-once `batch_coord_pda` and a shared `batch_escrow_pda` funded in one `token::Transfer`, creating independent per-recipient `schedule_pda_i` actors. Creation verifies exact balance delta `post - pre == total_amount` via `token::ReadState` before and after transfer; vesting and cancellation math never read `escrow_account.balance`.
- **Reason:** Achieves `N_max = 204` schedules in a single LEZ v0.4 transaction (`9,896,440` cycles, `98.96%` of 10M cap) while keeping claims completely isolated per schedule and immune to unsolicited direct donations to escrow addresses.

## D-08 (2026-11-20): Zero-dependency 256-bit `mul_div` in `escapement-core`

- **Decision:** Implement exact 256-bit `wide_mul_u128` + restoring long division directly in `escapement-core/src/math.rs`, fuzz-verified over 12,288 `proptest` cases across full `u128`/`u64` domains.
- **Reason:** Zero external math crate bloat inside the RISC Zero guest ELF (`472,612` bytes), zero `unsafe`, exact overflow-free precision up to `u128::MAX`, floor rounding on intermediate claims, and exact terminal release with zero stranded dust.

## D-09 (2026-11-20): Actor IDL v2 (`idl-gen`) on LEZ v0.4 with SPEL parity once upstream supports v0.4

- **Decision:** Generate and CI-drift-check the program's LEZ v0.4 actor IDL v2 using `lez-programs`'s `tools/idl-gen` format (used by `token`, `nft`, `twap_oracle`, `ata`, and `amm` on `refactor/lez-v0.4.x`), and add SPEL IDL regeneration if `logos-co/spel` releases v0.4 actor support prior to M5.
- **Reason:** As of 2026-11-20, `logos-co/spel` (`v0.7.0`) still pins LEZ `v0.2.5-rc2` and emits removed v0.2 macros (`read_lee_call`, `ProgramOutput`). Shipping actor IDL v2 gives v0.4 consumers a machine-checked schema immediately.
