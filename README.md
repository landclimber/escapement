# Escapement — Privacy-Preserving Token Vesting for LEZ v0.4

**Escapement** is an immutable, actor-native token vesting program for the Logos Execution Zone (**LEZ v0.4**, pinned to `v0.4.0-rc3`), built for [Logos RFP-017](https://github.com/logos-co/rfp/blob/master/RFPs/RFP-017-token-vesting.md).

Licensed under dual **MIT OR Apache-2.0**.

> **Status (2026-11-20):** Working LEZ `v0.4.0-rc3` prototype (`2,460` lines of program and core code, `4,822`-line real-ELF test suite) running the real compiled RISC Zero guest ELFs (`ESCAPEMENT_ELF` `482,284` B, `TOKEN_ELF`, `CLOCK_ELF`) through LEZ's `V03State`, `simulate_public_transaction`, and `execute_and_prove`, including a **`RISC0_DEV_MODE=0` real STARK proof** of a 1-transaction blinded-alias private claim (`151.89 s` CPU wall time, `59,878` public cycles). **Nothing here is audited.** Kani proofs, standalone sequencer CI, SPEL IDL, SDK, CLI, Logos Core module, Basecamp mini-app, signed `.lgx` catalog releases, live LEZ testnet 0.4 deployment, and audit remediation are the remaining grant scope (M1–M6).

## What Already Runs & Reproduces

Every figure below is recorded with exact commands and environment labels in [docs/EVIDENCE.md](docs/EVIDENCE.md) and reproduced from a clean clone via:

```bash
# Unit + property tests (28,672 proptest cases), real-ELF E2E, conservation invariants,
# 20-claim privacy suite, 33 of 34 guest exit codes, and exact v0.4 cycle & batch-ceiling measurements:
RISC0_DEV_MODE=1 cargo test --workspace --locked -- --nocapture

# Real RISC Zero 3.0.5 STARK proof (no dev mode) of a 1-tx blinded-alias private token claim:
RISC0_DEV_MODE=0 cargo test -p escapement-tests --test escapement_e2e s1_real_proof_dev_mode_0 -- --ignored --nocapture
```

### Verified Prototype Summary (2026-11-20)

| Check | Result | Mode & Where It Ran | Evidence Row |
|---|---|---|---|
| **1-tx blinded-alias private claim (real proof)** | **PASS:** `151.89 s` CPU proof (`159.51 s` one-time holding init), `59,878` public cycles; `Succinct` receipts; zero mailbox publications, `Transferred` events, or private IDs/keys in public bytes | Real STARK proof (`RISC0_DEV_MODE=0`), in-process `V03State` | [E-02](docs/EVIDENCE.md) |
| **Core math & selectors** | **13/13 passed** (`28,672` `proptest` cases incl. exact next-unlock time, cancel conservation, and an independent fee-ceiling reference) | Native Rust (host) | [E-01](docs/EVIDENCE.md) |
| **Private claims, rollbacks, time, fees, lifecycle** | **PASS:** on-chain atomic rollbacks incl. a raced proven claim; `timestamp_window` vs live-clock cancel; per-token fee vaults working after `Renounce`; exclusive Soft-1/Soft-2; `15,836`-cycle metered refusal | Real-ELF dev mode (`RISC0_DEV_MODE=1`), in-process `V03State` | [E-03..E-06](docs/EVIDENCE.md) |
| **Stateful conservation invariants** | **38/38 ops passed** plus **20 negative probes** in 5 refusal classes, each leaving state unchanged (incl. transfers, make-non-cancelable, donations, fee vault); per-escrow and global supply conservation after every step | Real-ELF dev mode (`RISC0_DEV_MODE=1`), in-process `V03State` | [E-07](docs/EVIDENCE.md) |
| **Adversarial privacy** | **20/20 private claims** across 5 wallets: no private IDs/keys in full tx bytes, events, or state; 20/20 distinct aliases, nullifiers, commitments, ephemeral keys | Real-ELF dev mode (`RISC0_DEV_MODE=1`), in-process `V03State` | [E-08](docs/EVIDENCE.md) |
| **Single-tx `BatchCreate` ceilings** | **`N_max` = 208** (`Linear`), **179** (`CliffLinear` + cancel authority), **149** (4-tranche `Milestone` + both authorities); `N_max + 1` refused (`OutOfGas`) | Real-ELF dev mode (`RISC0_DEV_MODE=1`), `simulate_*` on `V03State` | [E-09](docs/EVIDENCE.md) |
| **Shared-escrow clock-lag regression & error codes** | **PASS:** same-block claim + cancel never touches other recipients' tokens; 33 of 34 guest exit codes hit by tests | Real-ELF dev mode (`RISC0_DEV_MODE=1`), in-process `V03State` | [E-10, E-11, E-12](docs/EVIDENCE.md) |

### Measured LEZ `v0.4.0-rc3` Compute Costs (`MAX_GAS_EXEC = 10,000,000`)

Measured through `lee::simulate_public_transaction` and `lee::simulate_privacy_preserving_transaction` against compiled `ESCAPEMENT_ELF` (`482,284` B, `ImageID = [3452927831, 3319013898, 3929598451, 2170369841, 1426083620, 3898447055, 2985290972, 2590888107]`), `TOKEN_ELF` (`lez-programs@cad71fc6`), and `CLOCK_ELF` (`v0.4.0-rc3`), with `fee_bps = 0`:

| Operation | Measured User Cycles | % of 10M Cap | Notes |
|---|---:|---:|---|
| `CreateSchedule` | 257,737 | 2.58% | Config read, refund-holding check, escrow init, pre/post balance-delta verification |
| `ClaimPublic` | 106,145 | 1.06% | Live `clock_actor()` (`granularity = 1`) + PDA escrow transfer + `Claimed` event |
| `ClaimExact` (1-tx private) | 59,967 | 0.60% | `Response::timestamp_window(effective_ts..)` (no `clock` hop) + blinded-alias promoted credit |
| `Cancel` | 103,647 | 1.04% | Live `clock_actor()` + clamped refund to pinned `refund_holding` |
| `MakeNonCancelable` | 42,689 | 0.43% | One-way irreversible conversion |
| `SignalMilestone` | 74,929 | 0.75% | Live `clock_actor()` + idempotent tranche unlock |
| `TransferBeneficiary` | 44,387 | 0.44% | Immutable `transferable` flag enforced |
| `BatchCreate(1)`, `Linear` | 288,875 | 2.89% | Single shared `batch_escrow_pda` + write-once `batch_coord_pda` |
| `BatchCreate(8)`, `Linear` | 605,485 | 6.05% | Concurrent public/private claims & cancellation verified |
| `BatchCreate(208)`, `Linear` | 9,992,839 | 99.93% | `28,451` serialized tx bytes |
| `BatchCreate(179)`, `CliffLinear` + cancel authority | 9,982,470 | 99.82% | `34,618` serialized tx bytes |
| `BatchCreate(149)`, 4-tranche `Milestone` + both authorities | 9,994,753 | 99.95% | `39,080` serialized tx bytes |
| Pre-cliff refusal (`env::exit(26)`) | 15,836 | 0.16% | Metered non-zero exit (vs `10,000,000` billed for a panic) |

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

- `crates/escapement-core` — guest-compatible single source of truth (`1,661` lines incl. `547` lines of inline unit/property tests): state layouts, Borsh messages, zero-dependency 256-bit `mul_div` math + `proptest` fuzzers, `ProgramEvent` schemas + constant 8-byte selectors (unit-tested against SHA-256), typed `VestingError` with cycle-metered exit codes `1..=34`.
- `crates/escapement-program` — LEZ v0.4 actor handler (`1,346` LOC, `actor_entrypoint!(raw handle_message)`) integrating `lez-admin-authority` v0.2.0, `clock_core`, and `token_core`.
- `crates/escapement-methods` — RISC Zero guest build (`ESCAPEMENT_ELF`, `ESCAPEMENT_ID`).
- `crates/escapement-tests` — Real-ELF integration, blinded-alias private claim, real-proof (`RISC0_DEV_MODE=0`), same-block clock-lag cancel regression, error-code and security-hardening suite (33 of 34 guest exit codes; code 29 is only reachable through a misbehaving token program), multi-token fee vaults, batch ceiling, stateful conservation invariant, and 20-claim privacy linkability tests (`4,822` lines).
- `docs/` — [EVIDENCE.md](docs/EVIDENCE.md), [DECISIONS.md](docs/DECISIONS.md), [CROPS.md](docs/CROPS.md), [SECURITY.md](docs/SECURITY.md), [traceability.md](docs/traceability.md).

## Specified but Not Built Yet (Remaining Grant Scope: M1–M6)

- Kani bounded formal verification proofs over `escapement-core`, reproducible path-remapped guest builds, and standalone LEZ v0.4 sequencer CI harness (M1)
- Actor IDL v2 generation (`idl-gen`, CI drift-checked), PDA multisig delegated-authority E2E, mutation testing, and standalone-sequencer real-proof suite (M2)
- `escapement-sdk` (`Pr3` shielded-target validator, private holding pre-flight init, auto-chunked batches), `escapement_core_module` (Logos Core module with resumable async proving jobs), and `escapement-cli` (M3)
- `escapement_ui` Basecamp QML+C++ mini-app, signed `.lgx` / `.lgx-portable` bundles (`lgx sign`), and `logos-repo.json` catalog (M4)
- Live immutable deployment & real-proof desktop benchmarks on LEZ testnet 0.4 + signed line-by-line review + audit-ready bundle (M5)
- Independent third-party security audit support & remediation (M6)
