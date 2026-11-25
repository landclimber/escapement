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

**Machine.** A Linux x86-64 cloud container (gVisor), CPU only, 32 vCPUs visible, 64 GiB RAM; the
container requests 2 cores and bursts (the real-proof sequencer suite below used 37,764 s of CPU time
in 26 min of wall time, about 24 cores busy on average). Proving times on a desktop are part of the
testnet milestone.

## Build identity

| Item | Value |
|---|---|
| Program guest (`image-ids.tsv`) | image id `adc8b81f8b3f939f36cea61e23516acd1916e3b4e1b5e30a5ff91931d934df4c`, SHA-256 `03d8e8d9737790902390024555f27609d1e153582b3108cc86769387b69386e3`, 495,452 bytes |
| Toolchains | host Rust 1.98.1; RISC Zero 3.0.5 (`r0vm`), guest Rust 1.91.1, C++ 2024.1.5 |
| LEZ | `logos-execution-zone` tag `v0.4.0-rc3` (`bafd07be`) |
| Token program | `lez-programs` `3f04cc37ec5f` (branch `refactor/lez-v0.4.x`) |
| Admin authority | `mmlado/lez-admin-authority` `v0.2.0` |
| IDL generator | `logos-co/spel` `c90ca0bc` (branch `refactor/lez-v0.4.x`) |

## Rows

| Row | What ran | Result | Where | Re-run |
|---|---|---|---|---|
| **E-01** | Vesting and fee math (`escapement-core`) | 13/13; 7 property suites × 4,096 cases (28,672): `mul_div` identity at full 256-bit width, linear and cliff curves monotone, bounded and exact at the end, exact next-unlock millisecond, fee ceiling against an independent reference, cancel split conserves and never refunds claimed tokens, claimable never above `total − claimed` | native | `cargo test -p escapement-core --locked` |
| **E-02** | Kani bounded proofs (`crates/escapement-core/src/kani_proofs.rs`, Kani 0.68.0) | 3 harnesses **verified**: the fee is the exact ceiling of `amount × bps / 10,000` and any rate above its cap is refused, for every `u16` rate and cap (8-bit amounts, 12 s); cancelling a **linear** schedule conserves `vested + refund == total` and never refunds claimed tokens, whatever the clock (8-bit values, 7 s; cliff and milestone cancels are covered by E-01's property tests only); `mul_div_rem_u128` satisfies `q·d + r == a·b`, `r < d` (8-bit operands, 131 s). Not proven by Kani: curve monotonicity (harnesses timed out at 150 s; covered by E-01's property tests) and the full-width division path (E-01) | native (Kani) | `cd crates/escapement-core && cargo kani` |
| **E-03** | Reproducible guest | identical image id, SHA-256 and size built at the tree's path and at a copy elsewhere, and in CI on GitHub's runner (its own path, `HOME` and toolchain install); the check builds the guest from source every time (a guest build directory restored from a cache is not the same input, see "CI" below) | native, CI | `scripts/build-guest.sh --check` |
| **E-04** | Signer authority (`sec_relay_eoa_refused`, `sec_pda_cpi_succeeds_and_inherited_seed_relay_refused`, `sec_signer_authority_review_gaps`) | all nine user operations relayed by another program refused with code 35 at 12,115–16,650 cycles, state unchanged; a program acting as its own PDA (`AsPda`) creates, batch-creates, signals, claims (`ClaimPublic`, `ClaimExact`), transfers the beneficiary, cancels, makes non-cancelable and withdraws fees as the treasury; for each of the nine operations, `AsPda` from the PDA's own program without a grant on the delivery, through a grant inherited by another program, or with a seed that does not derive the PDA is refused (35), state unchanged; admin `Configure` and `Renounce` relayed by another program are refused even when the admin signs (lez-authority E120), state unchanged; forged `Internal`, `StateReply` and clock-reply messages sent to a schedule by another program are refused (32), state unchanged; a user operation or `AsPda` that arrives as an asynchronous message from another program (LEZ's mailbox path) is refused (35), state unchanged, even when the right account signs | in-process, dev mode | `RISC0_DEV_MODE=1 cargo test -p escapement-tests --test escapement_e2e sec_ -- --nocapture` |
| **E-05** | Token lifecycle, authorities, fees, refusals (`full_lifecycle_*`, `s2_*`, `s3_*`, `negative_guards_*`, `comprehensive_error_codes_*`) | all three kinds; exclusive cancel and milestone authorities; one-way non-cancelable; immutable transferability; per-token fee vaults working after `Renounce`; 34 of 35 exit codes reached by a test (29 only by a misbehaving token program) | in-process, dev mode | `RISC0_DEV_MODE=1 cargo test -p escapement-tests --test escapement_e2e -- --nocapture` |
| **E-06** | Native schedules (`native_asset_lifecycle_fees_batch_private_claim_and_ceilings`) | create, partial and full claims, overclaim refused (27), cancel with refund and the vested share claimable after, 50 bps fee into the native vault and its withdrawal (non-treasury refused, 13), batch of 8 with per-recipient amounts, one-transaction private claim into a fresh account | in-process, dev mode | as E-05 |
| **E-07** | Privacy (`s1_private_claim_*`, `adversarial_20_claim_no_leak_and_distinct_values_suite`) | one-transaction private token claims to fresh blinded aliases: no private account id, nullifier key or viewing key in the transaction bytes, events or state; 20/20 pairwise-distinct aliases, nullifiers, commitments and ephemeral keys (the claims themselves stay linkable through their public beneficiary, schedule, amount and time); atomic rollback of a stale proven claim (nonce check) | in-process, dev mode | as E-05 |
| **E-08** | Conservation and clock lag (`stateful_handler_conservation_invariant_suite`, `c1_*`) | randomized multi-actor operations with refusals interleaved; per-escrow and global supply conserved after every step; same-block claim and cancel never touch other recipients of a shared escrow | in-process, dev mode | as E-05 |
| **E-09** | Costs and batch ceilings | see `docs/gas-and-batch.md`: e.g. token claim 107,625 cycles, native claim 79,367; `N_max` 206 / 178 / 148 (token), 226 / 194 / 166 (native); `N_max + 1` refused (`OutOfGas`) | in-process, dev mode | as E-05 |
| **E-10** | SPEL IDL (`crates/escapement-idl`) | `idl/escapement.idl.json` equals what SPEL generates now; every message and event present with the program's selectors; every message decodes through SPEL's IDL-driven decoder | native | `cargo test -p escapement-idl --locked` |
| **E-11** | SDK (`crates/escapement-sdk`) | 20/20: public target refused on the private path (+Privacy 3), next unlock on "nothing claimable" (U7), under-funded private fee payer refused with the shortfall (U4), disclosure bound to its confirmation token (U5), builders for both assets, chunked batches, messages for codes 1..=35 | native | `cargo test -p escapement-sdk --locked` |
| **E-12** | Sequencer suite, dev mode (`e2e/run_e2e.sh`) | **91/91 checks, each an assertion** (75 until 25 Nov; then 16 for `batch`: a dry run that shows each recipient's terms and sends nothing, a duplicate and an absolute cliff refused, native and token batches whose escrows hold their sums, per-recipient cliffs, a claim from a batch, a zero total refused on chain and creating nothing): the CLI refuses a mistyped flag and `--dry-run` sends nothing; immutable deployment (5 segments + header), header read back with the image id of `image-ids.tsv`, admin init by the header key; linear schedule: partial public claim, then two private claims into the beneficiary's own private account (key file written with mode 0600; the first claim creates the account, the second spends its recorded state), each shown with its disclosure first and sent only with that disclosure's token (a wrong token is refused before anything is proven and changes nothing), the account's balance after each equal to the claims less the fee reserves shown, its new commitment found on the sequencer, its id absent from the transaction bytes; cancel (unvested refunded, vested frozen), vested remainder claimed, escrow empty; milestone schedule with a delegated authority; transferable schedule; one-way non-cancelable; six refusals sent on chain without client checks (overclaim, creator signal, double signal, old beneficiary claim, cancel after non-cancelable, beneficiary cancel), each included as reverted with the schedule's state compared before and after; tokens: the pinned `lez-programs` token program deployed beside Escapement, a token schedule with a public claim and a private claim into the same private account, whose fee that account pays inside the proof from its native balance (funded by a private shield; the account's private token holding initialized by one private transaction first); `getEvents` answered `-32601` (an indexer RPC on rc3, see `docs/events.md`) | sequencer, dev mode | `e2e/sequencer.sh build && E2E_DEV_MODE=1 e2e/run_e2e.sh` |
| **E-13** | Sequencer suite, real proofs | **75/75**, the same checks as E-12 with the sequencer and the CLI out of dev mode. Exactly **five** transactions carry real RISC Zero proofs verified by the sequencer: the suite's privacy-preserving ones (two native private claims, the shield, the private token holding, the token private claim, table below); every other step is a public transaction, which LEZ runs without a proof. Suite wall time 26 min 0 s, peak RSS 9.7 GB | sequencer, real proof | `E2E_DEV_MODE=0 e2e/run_e2e.sh` |
| **E-14** | CLI private account files (`crates/escapement-cli/src/keyfile.rs`) | 3/3: a key file is written with mode 0600 and never overwritten, its keys and recorded state round-trip, a file whose account id does not match its keys is refused, a prepared private claim (its one-time alias factor) is stored with mode 0600 and cleared after use | native | `cd crates/escapement-cli && cargo test --release --locked` |
| **E-15** | Public network ([PUBLIC-NETWORK.md](PUBLIC-NETWORK.md)) | the program deployed immutably on the Ferrata LEZ test network (LEZ `v0.4.0-rc3`), image id of `image-ids.tsv` read back from its header; 66 transactions, each re-read with its call decoded and checked against its recorded role (program, arguments, root and signing accounts), nine refused on chain and read back, one native private claim with a real proof (a Succinct receipt) made on the network's host and verified by its sequencer; every account's final state; 101 checks (114 with `--self-test`, whose wrong records must each fail), all reading the operator's RPC; the proving time, memory and hardware are the operator's records | public network | `scripts/verify-public.sh` |

**CI.** The first public CI run (24 Nov 2026, commit `fa65a1d`,
[run 45494927035](https://github.com/landclimber/escapement/actions/runs/45494927035)) passed:
`core-and-guest` (formatting, lints, the reproducible guest check at the runner's path, core 13,
IDL 2, SDK 20, in-process 13 + 1 manual) and `e2e-standalone-sequencer` (the rc3 sequencer built from
source, then that commit's 43-check suite). Every push re-runs both jobs; the real-proof job is manual.
The second run (commit `f825c4c`, run 45513681545) failed the guest check in `core-and-guest`: that job
restores a cargo cache (Swatinem/rust-cache), whose cleaning deletes the build wrapper's per-crate
records, so the guest relinked from it had another image id of the same size (`6ef37ac3…`); the same
commit's `e2e-standalone-sequencer` job, which builds the guest from source, matched `image-ids.tsv`.
`scripts/build-guest.sh` now removes the guest's build directory first, and the real-proof job runs
the check before proving.

### The five private transactions with real proofs (E-13)

Proven locally by `escapement-cli` (7 padded private actions, 512-byte ciphertexts: LEZ rc3 wallet
defaults), each fee paid inside the proof by the beneficiary's private account, then submitted,
verified and applied by the sequencer (base fees 8 / 8). In each, the private account's id is absent
from the transaction's bytes, its new commitment is found on the sequencer (`getProofsAndRoot`), and
the balance the CLI records from the account's own note equals the previous balance plus the credit
less the fee reserve, exactly.

| Transaction | Proving (CPU) | Proof | Transaction | Public part | Fee reserve | Account after |
|---|---|---|---|---|---|---|
| Native claim of 50,000,000 into a new private account | 205.6 s | 237,142 B | 251,302 B | 48,312 cycles | 5,457,112 | 44,542,888 native |
| Native claim of 10,000,000 into the same account (spends its recorded state) | 290.5 s | 239,010 B | 255,038 B | 48,400 cycles | 5,457,816 | 49,085,072 native |
| Shield of 30,000,000 native from the beneficiary's public account | 285.2 s | 238,842 B | 254,702 B | none (native transfer) | 5,070,616 | 74,014,456 native |
| The account's private holding of the token (`InitializeHolding`) | 330.1 s | 238,926 B | 254,726 B | 11,663 cycles | 5,163,920 | 68,850,536 native |
| Token claim of 60,000,000, fee from the account's native balance | 307.7 s | 239,107 B | 255,232 B | 61,653 cycles | 5,563,840 | 63,286,696 native, 60,000,000 tokens |

The escrows were debited exactly the claimed amounts. Earlier runs of the native new-account claim on
this binary (same sizes): 227.9 s and 199.3 s.

Also on this build, in-process (`s1_real_proof_dev_mode_0`, `RISC0_DEV_MODE=0`): a private **token**
claim into a new private account with real proofs, both receipts checked to be `Succinct` and
verified by LEZ's transaction validation before the state diff applies: private holding
initialization proven in 180.2 s, then the claim in 159.8 s, 61,464 public cycles; the test asserts the private balance, the
`Claimed` event, and that no private id, nullifier key or viewing key appears in the transaction
bytes, events or state. (This test runs without a fee witness; the sequencer rows above carry the
in-proof fee.) Re-run: `RISC0_DEV_MODE=0 cargo test -p escapement-tests --test escapement_e2e
s1_real_proof_dev_mode_0 -- --ignored --nocapture`, or CI's manual job.

## Review history

- **20 Nov:** two rounds of fresh-context AI review (security, tests/CI, fact-check, RFP grading);
  fixes: the same-block cancel over-refund on shared escrows (cancel clamp), single-account fee
  routing (per-asset vaults), panics made metered exits, validated `ClaimExact` timestamps, escrow
  self-lock destinations, stronger rollback and privacy checks. Not a third-party audit.
- **24 Nov:** the signer-relay gap (D-12) found by comparing LEZ rc3's authorization source with the
  program, and fixed with tests; the 20 Nov figures were found not to reproduce on the committed code
  (the guest embedded build paths), so the guest build was made reproducible (E-03) and every figure
  here was re-measured on it.
- **24–25 Nov:** a fresh-context review of the bid before filing; fixes: the CLI's private claim (it
  proved into a random account whose keys it never kept; now only into a private account whose keys
  the user holds, through the SDK's checks), every on-chain refusal compared with the state before
  and after, a token private claim with an in-proof fee on the sequencer, the signer-authority test
  gaps (E-04), and test names and wording that say exactly what the privacy tests show. Nothing
  compiled into the guest changed.
