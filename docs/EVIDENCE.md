# Evidence

What runs today, how it was run, and the command that re-runs it. Recorded 24 Nov 2026 on commit
`rfp017-final` (see `git log`); nothing here is audited.

**Where things ran.** "In-process" = LEZ `v0.4.0-rc3`'s own state machine (`lee::V03State`, transaction
validation and fee settlement) running the real compiled guests, inside the test process.
"Sequencer" = an unmodified standalone LEZ `v0.4.0-rc3` sequencer (`sequencer_service --features
standalone`, mock Bedrock, commit `bafd07be` asserted), on loopback, driven over JSON-RPC by
`escapement-cli`. "Dev mode" (`RISC0_DEV_MODE=1`) executes the guests and enforces every rule but
skips STARK sealing; "real proof" means a full RISC Zero proof, verified by the sequencer. LEZ testnet
0.4 has not launched (latest LEZ tag `v0.4.0-rc3`), so nothing here ran on it.

**Machine.** A Linux x86-64 cloud container (gVisor), 32 vCPUs visible with a 2-core CPU request
(bursting), 64 GiB RAM, CPU only.

## Build identity

| Item | Value |
|---|---|
| Program guest (`image-ids.tsv`) | image id `edb9fbe81a4c4046f60b33111dcc0c60e9ae6d9445ad329a259690d76707a865`, SHA-256 `f6758d82e60e7bef5506cefc23055a6d1af52ab3dd7c38afa5cb36f80afe6300`, 495,452 bytes |
| Toolchains | host Rust 1.98.1; RISC Zero 3.0.5 (`r0vm`), guest Rust 1.91.1, C++ 2024.1.5 |
| LEZ | `logos-execution-zone` tag `v0.4.0-rc3` (`bafd07be`) |
| Token program | `lez-programs` `3f04cc37ec5f` (branch `refactor/lez-v0.4.x`) |
| Admin authority | `mmlado/lez-admin-authority` `v0.2.0` |
| IDL generator | `logos-co/spel` `c90ca0bc` (branch `refactor/lez-v0.4.x`) |

## Rows

| Row | What ran | Result | Where | Re-run |
|---|---|---|---|---|
| **E-01** | Vesting and fee math (`escapement-core`) | 13/13; 7 property suites × 4,096 cases (28,672): `mul_div` identity at full 256-bit width, linear and cliff curves monotone, bounded and exact at the end, exact next-unlock millisecond, fee ceiling against an independent reference, cancel split conserves and never refunds claimed tokens, claimable never above `total − claimed` | native | `cargo test -p escapement-core --locked` |
| **E-02** | Kani bounded proofs (`crates/escapement-core/src/kani_proofs.rs`, Kani 0.68.0) | 3 harnesses **verified**: the fee is the exact ceiling of `amount × bps / 10,000` and any rate above its cap is refused, for every `u16` rate and cap (8-bit amounts, 12 s); cancellation conserves `vested + refund == total` and never refunds claimed tokens, whatever the clock (8-bit values, 7 s); `mul_div_rem_u128` satisfies `q·d + r == a·b`, `r < d` (8-bit operands, 131 s). Not proven by Kani: curve monotonicity (harnesses timed out at 150 s; covered by E-01's property tests) and the full-width division path (E-01) | native (Kani) | `cd crates/escapement-core && cargo kani` |
| **E-03** | Reproducible guest | identical image id, SHA-256 and size built at the tree's path and at a copy elsewhere; CI repeats it on its own runner path | native | `scripts/build-guest.sh --check` |
| **E-04** | Signer relay and PDA calls (`sec_relay_eoa_refused`, `sec_pda_cpi_succeeds_and_inherited_seed_relay_refused`) | all eight user operations relayed by another program refused with code 35 at 12,115–16,650 cycles, state unchanged; a program acting as its own PDA (`AsPda`) creates, signals, claims, cancels and makes non-cancelable; an inherited seed grant, a plain relay and a wrong seed are refused (35) | in-process, dev mode | `RISC0_DEV_MODE=1 cargo test -p escapement-tests --test escapement_e2e sec_ -- --nocapture` |
| **E-05** | Token lifecycle, authorities, fees, refusals (`full_lifecycle_*`, `s2_*`, `s3_*`, `negative_guards_*`, `comprehensive_error_codes_*`) | all three kinds; exclusive cancel and milestone authorities; one-way non-cancelable; immutable transferability; per-token fee vaults working after `Renounce`; 34 of 35 exit codes reached by a test (29 only by a misbehaving token program) | in-process, dev mode | `RISC0_DEV_MODE=1 cargo test -p escapement-tests --test escapement_e2e -- --nocapture` |
| **E-06** | Native schedules (`native_asset_lifecycle_fees_batch_private_claim_and_ceilings`) | create, partial and full claims, overclaim refused (27), cancel with refund and the vested share claimable after, 50 bps fee into the native vault and its withdrawal (non-treasury refused, 13), batch of 8 with per-recipient amounts, one-transaction private claim into a fresh account | in-process, dev mode | as E-05 |
| **E-07** | Privacy (`s1_private_claim_*`, `adversarial_20_claim_privacy_linkability_suite`) | one-transaction private token claims to fresh blinded aliases: no private account id, nullifier key or viewing key in the transaction bytes, events or state; 20/20 distinct aliases, nullifiers, commitments and keys; atomic rollback of a stale proven claim (nonce check) | in-process, dev mode | as E-05 |
| **E-08** | Conservation and clock lag (`stateful_handler_conservation_invariant_suite`, `c1_*`) | randomized multi-actor operations with refusals interleaved; per-escrow and global supply conserved after every step; same-block claim and cancel never touch other recipients of a shared escrow | in-process, dev mode | as E-05 |
| **E-09** | Costs and batch ceilings | see `docs/gas-and-batch.md`: e.g. token claim 107,625 cycles, native claim 79,367; `N_max` 206 / 178 / 148 (token), 226 / 194 / 166 (native); `N_max + 1` refused (`OutOfGas`) | in-process, dev mode | as E-05 |
| **E-10** | SPEL IDL (`crates/escapement-idl`) | `idl/escapement.idl.json` equals what SPEL generates now; every message and event present with the program's selectors; every message decodes through SPEL's IDL-driven decoder | native | `cargo test -p escapement-idl --locked` |
| **E-11** | SDK (`crates/escapement-sdk`) | 20/20: public target refused on the private path (+Privacy 3), next unlock on "nothing claimable" (U7), under-funded private fee payer refused with the shortfall (U4), disclosure bound to its confirmation token (U5), builders for both assets, chunked batches, messages for codes 1..=35 | native | `cargo test -p escapement-sdk --locked` |
| **E-12** | Sequencer suite, dev mode (`e2e/run_e2e.sh`) | **43/43**: immutable deployment (5 segments + header), header read back with the image id of `image-ids.tsv`, admin init by the header key; linear schedule: partial public claim, one-transaction private claim, cancel (unvested refunded, vested frozen), vested remainder claimed, escrow empty; milestone schedule with a delegated authority; transferable schedule; one-way non-cancelable; seven refusals sent on chain (overclaim, creator signal, double signal, old beneficiary claim, cancel after non-cancelable, beneficiary cancel) included as reverted with state unchanged | sequencer, dev mode | `e2e/sequencer.sh build && E2E_DEV_MODE=1 e2e/run_e2e.sh` |
| **E-13** | Sequencer suite, real proofs | **43/43**, the same checks as E-12 with real RISC Zero proofs verified by the sequencer (the sequencer runs without dev mode); suite wall time 5 min 24 s, peak RSS 9.7 GB | sequencer, real proof | `E2E_DEV_MODE=0 e2e/run_e2e.sh` |

### The private claim with a real proof (E-13)

A native private claim of 50,000,000 to a fresh private account, under a one-time alias, the fee paid
inside the proof by that account out of the claimed credit; 7 padded private actions, 512-byte
ciphertexts (LEZ rc3 wallet defaults); proven locally by `escapement-cli`, submitted, verified and
applied by the sequencer:

| Measure | Value |
|---|---|
| Proving time (local, CPU) | 227.9 s |
| Proof | 237,142 bytes |
| Transaction | 251,302 bytes |
| Public part (Escapement's `ClaimExact`, run publicly) | 48,344 cycles |
| Fee reserve credited in the proof (base fees 8 / 8) | 5,457,368 native units |
| Escrow debited / `claimed` after | exactly 50,000,000 / 150,000,000 |
| Private account id in the transaction's bytes | absent |
| Private account's new commitment on the sequencer (`getProofsAndRoot`) | found |
| Earlier pass (same build) | 237.8 s, same sizes |

Not re-run on this build: the in-process real-proof test `s1_real_proof_dev_mode_0` (token claim,
no fee witness). It passed on 20 Nov on an earlier build; it is `#[ignore]`d by default and reachable
with `RISC0_DEV_MODE=0 cargo test -p escapement-tests --test escapement_e2e s1_real_proof_dev_mode_0
-- --ignored --nocapture` or CI's manual job.

## Review history

- **20 Nov:** two rounds of fresh-context AI review (security, tests/CI, fact-check, RFP grading);
  fixes: the same-block cancel over-refund on shared escrows (cancel clamp), single-account fee
  routing (per-asset vaults), panics made metered exits, validated `ClaimExact` timestamps, escrow
  self-lock destinations, stronger rollback and privacy checks. Not a third-party audit.
- **24 Nov:** the signer-relay gap (D-12) found by comparing LEZ rc3's authorization source with the
  program, and fixed with tests; the 20 Nov figures were found not to reproduce on the committed code
  (the guest embedded build paths), so the guest build was made reproducible (E-03) and every figure
  here was re-measured on it.
