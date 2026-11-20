# Escapement — CROPS Architecture Review

Evaluated against Censorship Resistance, Open Source and Free (as in Freedom), Privacy, and Security (following `ethskills.com/crops`).

## Chosen Default

- **Single immutable LEZ v0.4 actor program** deployed with `program-loader --immutable` (loader-enforced, no upgrade key, mirrored into the commitment tree).
- **Zero protocol fee at launch (`0 bps`)** with a bounded, creation-only fee switch (`<= 100 bps`) gated by `lez-admin-authority` v0.2.0 (`Nominate` -> `Accept`, permanently renounceable), and **zero admin access, pause, or rescue power** over any schedule or escrow.
- **Pull-only per-schedule claims** settling in 1 transaction either publicly (`ClaimPublic`) or into a shielded private account via fresh per-claim blinded aliases (`ClaimExact`).
- **Local-first client stack** (Rust SDK, CLI, Logos Core module, Basecamp QML+C++ mini-app) with user-configurable sequencer/indexer endpoints and zero hosted backend or telemetry.

## Pillar-by-Pillar Assessment

### 1. Censorship Resistance
- **Risk:** A hosted frontend, single RPC/indexer, or privileged admin pause/blacklist could block beneficiaries from claiming earned tokens.
- **Mitigation:** Zero pause, freeze, blacklist, upgrade, or sweep instructions exist on schedules or escrows. Sequencer and indexer URLs are user-configurable in both CLI and Basecamp UI. No proprietary backend or relayer is required.
- **User escape:** Any beneficiary can invoke `ClaimPublic` or `ClaimExact` directly via `escapement-cli`, `lez_core`, or any self-hosted Basecamp build against any LEZ sequencer.

### 2. Open (Visibility)
- **Risk:** Unreproducible guest binaries, opaque build flags, or private offchain indexers prevent independent inspection or self-hosting.
- **Mitigation:** 100% open repository covering `escapement-core`, `escapement-program`, `escapement-methods`, SDK, CLI, Logos Core module, Basecamp QML UI, Nix flakes, actor IDL v2, and CI. Deterministic Docker guest builds verify byte-for-byte ImageID match in CI. Persistent (immutable) GitHub releases with `lgx sign` signatures and per-milestone release-integrity manifests (aligned with `logos-co/rfp` PR 255).
- **User escape:** Anyone can rebuild every guest binary and `.lgx-portable` module from a pinned commit and verify the onchain ImageID directly from the program header.

### 3. Free, as in Freedom (License)
- **Risk:** Source-available licenses (BUSL/SSPL), proprietary plugins, or future relicensing trap users and integrators.
- **Mitigation:** Dual **MIT + Apache-2.0** across every crate, script, IDL, and UI asset; no proprietary SDKs or hosted APIs; no relicensing plan.
- **User escape:** Third parties can legally fork, modify, self-host, and deploy independent instances without permission.

### 4. Privacy
- **Risk:** Schedule terms, claim amounts, beneficiary public addresses, PPTX fee reserves, and network/RPC IP metadata are observable; reusing a plaintext destination address across claims would link a user's private treasury.
- **Mitigation:**
  - Every private claim routes to a fresh single-use blinded alias `dest_priv.blinded(fresh_factor)` promoted atomically inside 1 PPTX (`20/20` pairwise-distinct aliases verified in `adversarial_20_claim_privacy_linkability_suite`; `0` real private IDs in public bytes/events).
  - `Claimed` events omit destination addresses; private `token::increase_balance` emits zero `Transferred` events (`M::EMITS_EVENTS == false`).
  - SDK validates that private targets belong to the shielded key tree and rejects public addresses before tx construction (`Pr3`).
  - Basecamp UI enforces a blocking pre-claim privacy disclosure before every private claim (`U5`/`Pr2`), runs with network denied in the QML sandbox, and ships zero third-party analytics/telemetry.
- **User escape:** Recipients choose public vs private independently on every claim and can route through self-hosted sequencer/indexer nodes.

### 5. Security & Walkaway Test
- **Risk:** Precision overflow, reentrancy across multi-actor hops, unsolicited escrow donations, delegated authority abuse, admin key compromise, or team disappearance.
- **Mitigation:**
  - Full 256-bit `mul_div` math (`proptest`-verified across 12,288 cases) with floor rounding on intermediate claims and exact dust-free terminal completion.
  - Transient `PendingOp` state locks reject reentrant messages during synchronous `ReadState` / `clock` hops.
  - Creation verifies exact escrow balance delta (`post - pre == total_amount`); schedule math never depends on `escrow_account.balance` (donation-proof).
  - `refund_holding` is validated and frozen immutably at creation; delegated `cancel_authority` and `milestone_authority` are strictly exclusive.
  - `token_program_id` is write-once; protocol fee cap (`100 bps`) is compile-time immutable; `Admin` uses two-step `Nominate` -> `Accept` and can be permanently renounced.
- **User escape (Walkaway Test):** If our team, catalog, and every hosted indexer disappear permanently, the immutable onchain program continues operating unchanged: every beneficiary can still claim 100% of vested tokens (publicly or privately), every cancel authority can still cancel cancelable schedules to pinned refund holdings, and every milestone authority can still unlock tranches.

## Accepted Compromises (Explicit & Bounded)

1. **Public schedule & beneficiary linkability at creation:** Schedule parameters and beneficiary public address are public onchain state by RFP-017 design; privacy protects the destination private account and all post-claim movements (full beneficiary anonymity requires commitment-based registration under LP-0003, out of scope for RFP-017).
2. **Residual post-claim timing/amount correlation:** Immediately deshielding or trading the exact claimed amount after a claim can correlate the movement offchain; disclosed explicitly in the pre-claim UI privacy notice (`U5`/`Pr2`).
3. **Private-claim native LEZ gas requirement:** LEZ v0.4 requires a PPTX fee to be paid from a witnessed private account; the UI verifies native balance sufficiency pre-claim and surfaces an actionable error (`U4`), and the SDK uses fixed fee-reserve tiers to avoid leaking small balances.
4. **Producer-chosen block timestamps:** LEZ v0.4 block timestamps are chosen by the block producer (~10 s granularity); acceptable for vesting horizons of days to years.
