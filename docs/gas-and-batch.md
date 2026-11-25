# Costs and batch ceilings (P2, F5)

LEZ v0.4 meters execution 1:1 in RISC Zero user cycles; one transaction may use at most
`MAX_GAS_EXEC = 10,000,000`. Every figure below was measured on 24 Nov 2026 by the test
`batch_create_concurrent_claims_and_exact_ceiling_benchmark` (token) and
`native_asset_lifecycle_fees_batch_private_claim_and_ceilings` (native) in `crates/escapement-tests`,
through `lee::simulate_public_transaction` / `simulate_privacy_preserving_transaction` on LEZ
`v0.4.0-rc3`'s own state machine, with:

- the reproducible guest of `image-ids.tsv`: `escapement` image id
  `adc8b81f8b3f939f36cea61e23516acd1916e3b4e1b5e30a5ff91931d934df4c`, 495,452 bytes, built with
  RISC Zero's guest Rust 1.91.1 (`scripts/build-guest.sh --check`);
- `lez-programs` token program at `3f04cc37ec5f`, LEZ clock at `v0.4.0-rc3`;
- `fee_bps = 0`, no broker.

Not re-measured after the 25 Nov cancel-clamp fix (D-10), which adds one `vested_at` evaluation to
`ClaimPublic` and `ClaimExact` and changes the guest's image id (`image-ids.tsv`).

Re-run: `RISC0_DEV_MODE=1 cargo test --workspace --locked -- --nocapture` (the tables are printed
to stderr). The testnet 0.4 measurement is part of the testnet milestone (P2 asks for it).

## Per operation (cycles)

| Operation | Token | Native | Notes |
|---|---:|---:|---|
| `CreateSchedule` | 264,775 | 141,318 | config read, refund/escrow checks, exact funding delta |
| `ClaimPublic` | 107,625 | 79,367 | live clock read + escrow debit + `Claimed` |
| `ClaimExact` (private claim, public part) | 61,579 | 48,175 | `timestamp_window(effective_ts..)`, no clock hop |
| `Cancel` | 105,644 | 77,347 | live clock + clamped split + refund |
| `MakeNonCancelable` | 44,056 | | asset-independent |
| `SignalMilestone` | 76,279 | | asset-independent |
| `TransferBeneficiary` | 45,818 | | asset-independent |
| `BatchCreate(1)`, linear | 296,096 | | |
| `BatchCreate(8)`, linear | 614,978 | | |
| Refusal, e.g. pre-cliff claim (exit code 26) | 16,150 | | metered exit; a panic would be charged the full gas limit |
| Call relayed by another program (exit code 35) | 12,115–16,650 | | `sec_relay_eoa_refused` |

A private claim adds LEZ's flat privacy costs to its public part: `PRIVATE_VERIFY_GAS` of execution
gas and `PRIVATE_GAS_STOR` of storage gas (`fee_core`), paid inside the proof by the private
account (see `crates/escapement-sdk/src/fees.rs`). Proving time is in `docs/EVIDENCE.md`.

## Batch ceiling (one transaction)

Binary search for the largest batch that fits the 10M-cycle cap; `N_max + 1` is refused with
`OutOfGas`. Gas binds long before the transaction size does.

| Shape (per recipient) | Token `N_max` | Native `N_max` | Bytes at `N_max` (token / native) |
|---|---:|---:|---|
| Linear | 206 | 226 | 28,186 / 30,750 |
| Cliff + linear, with a cancel authority | 178 | 194 | 34,430 / 37,358 |
| 4-tranche milestone, with both authorities | 148 | 166 | 38,824 / 43,354 |

Each recipient has its own amount, schedule and flags; all share one escrow funded by one transfer.
The SDK's `batch_create_chunked` splits larger launches at `SAFE_BATCH_CEILING = 128` recipients
per transaction.
