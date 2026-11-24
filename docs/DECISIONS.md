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

## D-04 (2026-11-20): Cycle-metered guest exit codes (`env::exit(1..=34)`) instead of panics

- **Decision:** Every deterministic vesting refusal (`VestingError`, codes `1..=34`) exits with `risc0_zkvm::guest::env::exit(code)` on `target_os = "zkvm"` rather than `panic!`.
- **Reason:** Verified in LEZ `v0.4.0-rc3` (`validated_state_diff/mod.rs:503-513`): panics lose the cycle count and bill the caller's entire declared `gas_limit` (up to `10,000,000` cycles). Non-zero exit codes return `LeeError::ProgramExitedWithCode { code, cycles }` and bill only metered cycles executed (`15,836` cycles measured on a pre-cliff refusal, `0.16%` of the 10M cap, 631× less than a panic).
- **Alternative rejected:** `panic!` on user errors (penalizes accidental early claims or stale retries with full gas-limit burn).

## D-05 (2026-11-20): Creator-paid, creation-only fee switch (`0 bps` default, `<= 100 bps` immutable cap) via `lez-admin-authority` v0.2.0

- **Decision:** Reuse `mmlado/lez-admin-authority` `v0.2.0` (RFP-001 on LEZ v0.4) to gate `Message::Configure`. Initial protocol fee is `0 bps`; immutable compile-time cap is `100 bps` (1.00%); optional integrator broker fee is caller-supplied up to `500 bps` (default `0`). Fees are additive and collected strictly from the creator at schedule creation, never from beneficiaries and never retroactively on existing schedules. `token_program_id` is write-once and immutable once set.
- **Reason:** Matches RFP-017's recommended baseline and the zero-fee market equilibrium (Sablier, Hedgey, Jupiter Lock), avoids any beneficiary skim on private claims, and guarantees existing schedules are immune to governance capture.
- **Implementation note:** `lez-admin-authority` v0.2.0 forwards seat messages to `config_pda` without `pda_seeds`, which triggers `UnadmittedPublicActor` on `AdminOp::Init` against live `V03State`. Our guest attaches `CONFIG_SEED` only to `lez-authority` library forwards (first byte `LIBRARY_TAG`) so `config_pda` admits cleanly onchain without extra wallet-side `admission_evidence`; schedule operations aimed at `config_pda` exit with `NotASchedule` (code `16`).
- **Fee routing (revised 2026-11-20 after review):** protocol fees go to a program-owned fee vault PDA per token (`sha256("escapement/feevault/v1" ‖ token_definition)`), initialized idempotently on first fee-bearing creation; `config.fee_treasury` withdraws with `WithdrawFees` (event `FeeWithdrawn`). The first design sent fees straight to one `fee_treasury` account, but a LEZ v0.4 token holding holds one token only, so any `fee_bps > 0` would have blocked schedule creation for every other token, permanently after `Renounce`. `token_program_id` cannot be set to the program, its config PDA, or the clock (code `34`).

## D-06 (2026-11-20): Exclusive delegated authorities (`Soft-1`, `Soft-2`) with immutably pinned `refund_holding`

- **Decision:** When `cancel_authority` is `Some(addr)`, `addr` exclusively replaces `creator` for `Cancel` and `MakeNonCancelable`; when `milestone_authority` is `Some(addr)`, `addr` exclusively replaces `creator` for `SignalMilestone`. `refund_holding` is validated via `token::ReadState` at creation and frozen immutably.
- **Reason:** Allowing `creator` to retain fallback milestone authority when delegated to a governance multisig would reintroduce the exact self-dealing vulnerability RFP-017 Soft-2 exists to prevent (creator collateral vesting from RFP-015/016 launchpads). Pinning `refund_holding` ensures a delegated `cancel_authority` can never redirect unvested tokens to itself.

## D-07 (2026-11-20): Dedicated single-schedule escrow PDA + shared batch escrow PDA + donation-proof balance-delta checks

- **Decision:** Single schedules use a dedicated `escrow_pda`; `BatchCreate` uses a write-once `batch_coord_pda` and a shared `batch_escrow_pda` funded in one `token::Transfer`, creating independent per-recipient `schedule_pda_i` actors. Creation verifies exact balance delta `post - pre == total_amount` via `token::ReadState` before and after transfer; vesting and cancellation math never read `escrow_account.balance`.
- **Reason:** Achieves up to `N_max = 208` schedules in a single LEZ v0.4 transaction (`Linear`; `9,992,839` cycles, `99.93%` of the 10M cap; 179 for `CliffLinear` with a cancel authority, 149 for 4-tranche `Milestone` with both authorities) while keeping claims completely isolated per schedule and immune to unsolicited direct donations to escrow addresses.

## D-08 (2026-11-20): Zero-dependency 256-bit `mul_div` in `escapement-core`

- **Decision:** Implement exact 256-bit `wide_mul_u128` + restoring long division directly in `escapement-core/src/math.rs`, fuzz-verified over 12,288 `proptest` cases (28,672 across all seven property suites) across full `u128`/`u64` domains.
- **Reason:** Zero external math crate bloat inside the RISC Zero guest ELF (`482,284` bytes), zero `unsafe`, exact overflow-free precision up to `u128::MAX`, floor rounding on intermediate claims, and exact terminal release with zero stranded dust.

## D-09 (2026-11-20): IDL from SPEL's v0.4 actor IDL v2 generator

- **Decision:** Generate and CI-drift-check the program's actor IDL v2 with `spel-framework-core` (feature `idl-gen`) from SPEL's `refactor/lez-v0.4.x` branch (`c90ca0bc`, pins LEZ `v0.4.0-rc3`), the same generator `lez-programs@cad71fc6`'s `tools/idl-gen` uses for `token`, `nft`, and `twap_oracle` (its `ata` and `amm` IDLs are still version `0.1.0` on that commit). Move to the tagged SPEL v0.4 release when it is cut.
- **Reason:** As of 2026-11-20 the latest SPEL release (`v0.7.0`) pins LEZ `v0.2.4` (SPEL `main` pins `v0.2.5-rc2`), so a released SPEL cannot describe a v0.4 actor program yet, while the v0.4 branch already can.

## D-10 (2026-11-20): Cancel never refunds claimed tokens (clock-lag clamp)

- **Decision:** `split_on_cancel` computes `vested_at_cancel = max(vested(clock_now), claimed_amount)`.
- **Reason:** On `v0.4.0-rc3` the clock ticks at the end of each block, so `Cancel` (live `clock_actor()`) sees the previous block's time while `ClaimExact`'s `timestamp_window` is checked against the current block; the clock program also does not enforce monotonic time. Without the clamp, a claim and a cancel in the same block could leave `vested_at_cancel < claimed_amount` and over-refund from a shared batch escrow, taking other recipients' tokens. Found by a fresh-context AI security review on 2026-11-20; covered by `math::tests::split_on_cancel_clamps_to_claimed_under_clock_lag` and `c1_same_block_clock_lag_cancel_protects_shared_batch_escrow`.

## D-11 (2026-11-20): Threats checked and ruled out or accepted

- **Ruled out: a third party pre-initializing an escrow or fee-vault PDA.** On `v0.4.0-rc3` a PDA seed admits and authorizes only `for_public_pda(issuer, seed)`, where `issuer` is the *sending actor's program* (`lee/state_machine/core/src/execution_state.rs:353-357` `issuer()`, `:1196-1201` `admit`, `:1446-1451` `authorize`). Every Escapement escrow and fee vault is `for_public_pda(VESTING, seed)`, so only a message sent by an Escapement actor can admit or authorize it, and Escapement only ever sends `InitializeHolding` there with the schedule's own `token_definition`. Another program attaching the same seed derives a different account. A root (user) transaction has no issuer and cannot authorize a PDA at all. So no outsider can stamp a foreign token state on a future escrow or fee vault.
- **Accepted (low): a broker holding of the wrong token.** If a creator names a `broker.holding` that holds a different token, the broker credit fails late in creation and the whole transaction reverts at full gas. No funds move; the creator chose the broker. The SDK will check the broker holding before submitting (M3).
- **Accepted (info): `WithdrawFees` above the vault balance** reverts at full gas. Only `fee_treasury` can reach it; the SDK will read the vault balance first (M3).
- **Accepted (info): `lez-authority` refusals are panics by design** (`lez-authority` `guard`), so a non-admin `Configure` costs the sender the full budget. Escapement's own refusals all exit with metered codes.
