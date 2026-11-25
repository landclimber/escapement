# Escapement — CROPS Architecture Review

Evaluated against Censorship Resistance, Open Source and Free (as in Freedom), Privacy, and Security (following `ethskills.com/crops`).

> **Status (2026-11-24).** Built and tested in this repository: the program (native and token schedules), its guest with a reproducible build, `escapement-sdk`, `escapement-cli`, the SPEL IDL, an end-to-end suite on a standalone LEZ v0.4.0-rc3 sequencer (immutable deployment, public and private claims, refusals on chain), and SHA-pinned CI. The Logos Core module, the Basecamp mini-app and the testnet 0.4 deployment are not built yet.

## Chosen Default

- **Single immutable LEZ v0.4 actor program**, deployed with `program_loader` `immutable: true` (loader-enforced, no upgrade key); deployment and header read-back shown on a standalone sequencer, testnet 0.4 deployment pending.
- **Zero protocol fee at launch (`0 bps`)** with a bounded, creation-only fee switch (`<= 100 bps`) gated by `lez-admin-authority` v0.2.0 (`Nominate` -> `Accept`, permanently renounceable), and **zero admin access, pause, or rescue power** over any schedule or escrow.
- **Pull-only per-schedule claims** settling in 1 transaction either publicly (`ClaimPublic`) or into a shielded private account via fresh per-claim blinded aliases (`ClaimExact`).
- **Local-first client stack**: Rust SDK and CLI (built); Logos Core module **(M2)** and Basecamp QML+C++ mini-app **(M3)**, with user-configurable sequencer/indexer endpoints and zero hosted backend or telemetry.

## Pillar-by-Pillar Assessment

### 1. Censorship Resistance
- **Risk:** A hosted frontend, single RPC/indexer, or privileged admin pause/blacklist could block beneficiaries from claiming earned tokens.
- **Mitigation:** Zero pause, freeze, blacklist, upgrade, or sweep instructions exist on schedules or escrows (true of the program today). Sequencer and indexer URLs are user-configurable in the CLI (`LEZ_RPC`) and will be in the Basecamp UI **(M3)**. No proprietary backend or relayer is required.
- **User escape:** Any beneficiary can invoke `ClaimPublic` or `ClaimExact` directly via `escapement-cli` (built), `lez_core`, or any self-hosted Basecamp build against any LEZ sequencer.

### 2. Open (Visibility)
- **Risk:** Unreproducible guest binaries, opaque build flags, or private offchain indexers prevent independent inspection or self-hosting.
- **Mitigation:** Fully open repository: the program, guest, SDK, CLI, SPEL-generated IDL, tests, end-to-end suite and CI today; the Logos Core module **(M2)** and Basecamp QML UI with Nix flakes **(M3)** later. The guest build is reproducible and CI checks its image id against `image-ids.tsv` (built). Immutable GitHub releases in an organisation-hosted catalog, signed with `lgx sign`, each with a Release Integrity Manifest including `rootHash` **(M3, `logos-co/rfp` PR 255)**.
- **User escape:** Anyone can rebuild the guest binary and every `.lgx-portable` module from a pinned commit and verify the onchain ImageID directly from the program header.

### 3. Free, as in Freedom (License)
- **Risk:** Source-available licenses (BUSL/SSPL), proprietary plugins, or future relicensing trap users and integrators.
- **Mitigation:** Dual **MIT + Apache-2.0** across every crate, script, IDL, and UI asset; no proprietary SDKs or hosted APIs; no relicensing plan.
- **User escape:** Third parties can legally fork, modify, self-host, and deploy independent instances without permission.

### 4. Privacy
- **Risk:** Schedule terms, claim amounts, beneficiary public addresses, PPTX fee reserves, and network/RPC IP metadata are observable; reusing a plaintext destination address across claims would link a user's private treasury.
- **Mitigation:**
  - Every private claim routes to a fresh single-use blinded alias `dest_priv.blinded(fresh_factor)` promoted atomically inside 1 PPTX (`20/20` pairwise-distinct aliases, nullifiers, commitments, and ephemeral keys in `adversarial_20_claim_no_leak_and_distinct_values_suite`; no real private ID, nullifier key, or viewing key in any public transaction byte, event, or post-state).
  - `Claimed` events omit destination addresses and aliases; private `token::increase_balance` emits zero `Transferred` events (`M::EMITS_EVENTS == false`).
  - The SDK validates that a private target is a private account of the wallet (built from its key material) and rejects anything else before a transaction is built (`Pr3`, built and tested).
  - Basecamp UI will enforce a blocking pre-claim privacy disclosure before every private claim (`U5`/`Pr2`), run with network denied in the QML sandbox, and ship zero third-party analytics/telemetry **(M3)**.
- **User escape:** Recipients choose public vs private independently on every claim and can route through self-hosted sequencer/indexer nodes.

### 5. Security & Walkaway Test
- **Risk:** Precision overflow, reentrancy across multi-actor hops, unsolicited escrow donations, delegated authority abuse, admin key compromise, or team disappearance.
- **Mitigation:**
  - Full 256-bit `mul_div` math (`proptest`-verified across 28,672 cases) with floor rounding on intermediate claims and exact dust-free terminal completion.
  - Transient `PendingOp` state locks reject reentrant messages during synchronous `ReadState` / `clock` hops.
  - Creation verifies exact escrow balance delta (`post - pre == total_amount`); schedule math never depends on `escrow_account.balance` (donation-proof).
  - `refund_holding` is validated and frozen immutably at creation; delegated `cancel_authority` and `milestone_authority` are strictly exclusive.
  - `split_on_cancel` clamps `vested_at_cancel` to at least `claimed_amount` and the largest vested amount an earlier claim proved (`vested_high_water`), so a cancel read against a lagging or regressed clock can never refund tokens already claimed or already proven vested by a claim (and cannot draw on other recipients' share of a batch escrow).
  - Protocol fees go to a per-token fee vault PDA, so enabling fees cannot block schedule creation for any token, including after `Renounce`.
  - `token_program_id` is write-once and cannot be set to the program itself, its config PDA, or the clock; protocol fee cap (`100 bps`) is compile-time immutable; `Admin` uses two-step `Nominate` -> `Accept` and can be permanently renounced.
- **User escape (Walkaway Test):** If our team, catalog, and every hosted indexer disappear permanently, the immutable onchain program continues operating unchanged: every beneficiary can still claim 100% of vested tokens (publicly or privately), every cancel authority can still cancel cancelable schedules to pinned refund holdings, and every milestone authority can still unlock tranches.

## Accepted Compromises (Explicit & Bounded)

1. **Public schedule & beneficiary linkability at creation:** Schedule parameters and beneficiary public address are public onchain state by RFP-017 design; privacy protects the destination private account and all post-claim movements (full beneficiary anonymity requires commitment-based registration under LP-0003, out of scope for RFP-017).
2. **Residual post-claim timing/amount correlation:** Immediately deshielding or trading the exact claimed amount after a claim can correlate the movement offchain; disclosed explicitly in the pre-claim UI privacy notice (`U5`/`Pr2`).
3. **Private-claim native LEZ gas requirement:** a private claim pays its fee inside the proof from a private account of the beneficiary (for native claims the destination itself, out of the claimed credit; for token claims the receiving private account, out of its native balance; both as `escapement-cli` does on the sequencer suite, refusing before proving when the balance does not cover the reserve); the UI will verify native balance sufficiency pre-claim and surface an actionable error (`U4`, M4), and the SDK will use fixed fee-reserve tiers to avoid leaking small balances (M3).
4. **Producer-chosen block timestamps:** LEZ v0.4 block timestamps are chosen by the block producer and the clock program does not enforce monotonic time; acceptable for vesting horizons of days to years, and the cancel clamp above keeps a backwards step from moving claimed or claim-proven vested tokens.
