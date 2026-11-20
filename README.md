# Escapement — Privacy-Preserving Token Vesting for LEZ v0.4

**Escapement** is an immutable, actor-native token vesting program for the Logos Execution Zone (**LEZ v0.4**, pinned to `v0.4.0-rc3`), built for [Logos RFP-017](https://github.com/logos-co/rfp/blob/master/RFPs/RFP-017-token-vesting.md).

Licensed under dual **MIT OR Apache-2.0**.

> **Status (2026-11-20):** Working LEZ `v0.4.0-rc3` prototype (`2,360` LOC core + guest program, `2,096` LOC real-ELF test suite) running the real compiled RISC Zero guest ELFs (`ESCAPEMENT_ELF` `472,612` B, `TOKEN_ELF`, `CLOCK_ELF`) through LEZ's `V03State`, `simulate_public_transaction`, and `execute_and_prove` — including a verified **`RISC0_DEV_MODE=0` real STARK proof** of a 1-transaction blinded-alias private claim (`145.69 s` CPU wall time, `58,375` public cycles). **Nothing here is audited**; Kani formal proofs, standalone sequencer CI, actor IDL v2, SDK, CLI, Logos Core module, Basecamp QML mini-app, signed `.lgx` catalog release, live LEZ testnet 0.4 deployment, and audit remediation are the remaining grant scope (M1–M6).

## What Already Runs & Reproduces

Every figure below is recorded with exact commands and environment labels in [docs/EVIDENCE.md](docs/EVIDENCE.md) and reproduced from a clean clone via:

```bash
# Unit tests, 12,288 proptest math fuzz cases, real-ELF E2E, 42/42 stateful conservation invariants,
# 20-claim privacy linkability test, and exact v0.4 cycle & batch-ceiling measurements:
RISC0_DEV_MODE=1 cargo test --workspace --locked -- --nocapture

# Real RISC Zero 3.0.5 STARK proof (no dev mode) of a 1-tx blinded-alias private token claim:
RISC0_DEV_MODE=0 cargo test -p escapement-tests --test escapement_e2e s1_real_proof_dev_mode_0 -- --ignored --nocapture
```

### Verified Prototype Summary (2026-11-20)

| Check | Result | Mode & Where It Ran | Evidence Row |
|---|---|---|---|
| **1-tx blinded-alias private claim (real proof)** | **PASS:** `145.69 s` CPU proof (`166.74 s` one-time holding init), `58,375` public cycles (`0.58%`), `0` mailbox publications, `0` leaked private IDs | Real STARK proof (`RISC0_DEV_MODE=0`), in-process `V03State` | [E-02](docs/EVIDENCE.md) |
| **Core 256-bit vesting & fee math fuzzing** | **5/5 passed** (`12,288` `proptest` cases across full `u128`/`u64` domains) | Native Rust (host) | [E-01](docs/EVIDENCE.md) |
| **M0 Spikes S-1, S-2, S-3 + full lifecycle** | **PASS:** blinded-alias atomic rollback/retry, `timestamp_window` vs live `clock_actor()` cancel, `lez-admin-authority` v0.2.0 (`<= 100 bps`), exclusive Soft-1/Soft-2 authorities, `16,003`-cycle metered refusal | Real-ELF dev mode (`RISC0_DEV_MODE=1`), in-process `V03State` | [E-03..E-06](docs/EVIDENCE.md) |
| **Stateful conservation invariants** | **42/42 ops passed (0% revert rate)**; strict escrow conservation held on every step incl. donations & shared batch escrow | Real-ELF dev mode (`RISC0_DEV_MODE=1`), in-process `V03State` | [E-07](docs/EVIDENCE.md) |
| **Adversarial privacy linkability** | **20/20 private claims** across 5 wallets: `0` real private IDs in public bytes/events, `20/20` pairwise-distinct blinded aliases | Real-ELF dev mode (`RISC0_DEV_MODE=1`), in-process `V03State` | [E-08](docs/EVIDENCE.md) |
| **Exact single-tx `BatchCreate` ceiling** | **`N_max = 204`** (`9,896,440` cycles = `98.96%`, `27,919` B); `BatchCreate(205)` refused (`OutOfGas`) | Real-ELF dev mode (`RISC0_DEV_MODE=1`), `simulate_*` on `V03State` | [E-09](docs/EVIDENCE.md) |

### Measured LEZ `v0.4.0-rc3` Compute Costs (`MAX_GAS_EXEC = 10,000,000`)

Measured through `lee::simulate_public_transaction` and `lee::simulate_privacy_preserving_transaction` against compiled `ESCAPEMENT_ELF` (`472,612` B, `ImageID = [4189057316, 3864282846, 443295723, 876926637, 967256315, 8553097, 2136585568, 3581203566]`), `TOKEN_ELF` (`lez-programs@cad71fc6`), and `CLOCK_ELF` (`v0.4.0-rc3`):

| Operation | Measured User Cycles | % of 10M Cap | Notes |
|---|---:|---:|---|
| `CreateSchedule` | 259,048 | 2.59% | Config read, refund-holding check, escrow init, pre/post balance-delta verification |
| `ClaimPublic` | 104,812 | 1.05% | Live `clock_actor()` (`granularity = 1`) + PDA escrow transfer + `Claimed` event |
| `ClaimExact` (1-tx private) | 58,464 *(58,375 in E-02)* | 0.58% | `Response::timestamp_window(effective_ts..)` (no `clock` hop) + blinded-alias promoted credit |
| `Cancel` | 102,638 | 1.03% | Live `clock_actor()` + exact refund to pinned `refund_holding` |
| `MakeNonCancelable` | 41,585 | 0.42% | One-way irreversible conversion |
| `SignalMilestone` | 73,785 | 0.74% | Live `clock_actor()` + idempotent tranche unlock |
| `TransferBeneficiary` | 42,965 | 0.43% | Immutable `transferable` flag enforced |
| `BatchCreate(1)` | 289,731 | 2.90% | Single shared `batch_escrow_pda` + write-once `batch_coord_pda` |
| `BatchCreate(8)` | 607,833 | 6.08% | Concurrent public/private claims & cancellation verified |
| `BatchCreate(N_max = 204)` | 9,896,440 | 98.96% | `27,919` serialized tx bytes (`BatchCreate(205)` refused: `OutOfGas`) |
| Pre-cliff refusal (`env::exit(26)`) | 16,003 | 0.16% | Cycle-metered non-zero exit (vs `10,000,000` full-budget panic charge) |

## State-Transition Caller & Incentive Table

No keepers, crons, or operator-only liveness paths exist:

| Transition | Caller | Why They Pay Gas | If Nobody Calls |
|---|---|---|---|
| `CreateSchedule` / `BatchCreate` | Creator | Escrows allocation to credibly lock tokens | Tokens stay in creator's wallet |
| `ClaimPublic` / `ClaimExact` | Beneficiary | Receives vested tokens (publicly or into a shielded account) | Vested tokens stay escrowed and claimable indefinitely |
| `Cancel` | `cancel_authority` if set, else `creator` (exclusive) | Reclaims unvested tokens on early termination | Schedule continues vesting as configured |
| `MakeNonCancelable` | `cancel_authority` if set, else `creator` (exclusive) | Credible irrevocable commitment signal | Schedule remains cancelable |
| `SignalMilestone` | `milestone_authority` if set, else `creator` (exclusive) | Unlocks earned milestone tranche for beneficiary | Tranche stays locked |
| `TransferBeneficiary` | Beneficiary (iff `transferable == true`) | Assigns rights / settles secondary transfer | Current beneficiary keeps claim rights |
| `Configure` / `AdminOp` | `Admin` (`lez-admin-authority` v0.2.0) | Bounded creation-fee governance (`<= 100 bps`, future schedules only) | Protocol fee stays `0 bps`; all schedules unaffected |

## Workspace Layout

- `crates/escapement-core` — `no_std`-compatible single source of truth (`1,147` LOC): state layouts, Borsh messages, zero-dep 256-bit `mul_div` math + `proptest` fuzzers, `ProgramEvent` schemas + deterministic 8-byte selectors, typed `VestingError` with cycle-metered exit codes `1..=30`.
- `crates/escapement-program` — LEZ v0.4 actor handler (`1,213` LOC, `actor_entrypoint!(raw handle_message)`) integrating `lez-admin-authority` v0.2.0, `clock_core`, and `token_core`.
- `crates/escapement-methods` — RISC Zero guest build (`ESCAPEMENT_ELF`, `ESCAPEMENT_ID`).
- `crates/escapement-tests` — Real-ELF integration, blinded-alias private claim, real-proof (`RISC0_DEV_MODE=0`), batch ceiling, stateful conservation invariant, and 20-claim privacy linkability tests (`2,096` LOC).
- `docs/` — [EVIDENCE.md](docs/EVIDENCE.md), [DECISIONS.md](docs/DECISIONS.md), [CROPS.md](docs/CROPS.md), [traceability.md](docs/traceability.md).

## Specified but Not Built Yet (Remaining Grant Scope: M1–M6)

- Kani bounded formal verification proofs over `escapement-core`, reproducible path-remapped guest builds, and standalone LEZ v0.4 sequencer CI harness (M1)
- Actor IDL v2 generation (`idl-gen`, CI drift-checked), PDA multisig delegated-authority E2E, mutation testing, and standalone-sequencer real-proof suite (M2)
- `escapement-sdk` (`Pr3` shielded-target validator, private holding pre-flight init, auto-chunked batches), `escapement_core_module` (Logos Core module with resumable async proving jobs), and `escapement-cli` (M3)
- `escapement_ui` Basecamp QML+C++ mini-app, signed `.lgx` / `.lgx-portable` bundles (`lgx sign`), and `logos-repo.json` catalog (M4)
- Live immutable deployment & real-proof desktop benchmarks on LEZ testnet 0.4 + signed line-by-line review + audit-ready bundle (M5)
- Independent third-party security audit support & remediation (M6)
