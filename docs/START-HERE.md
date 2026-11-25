# Start here: a 10-minute review

Escapement is a privacy-preserving vesting program for the Logos Execution Zone (LEZ) v0.4, covering native LEZ and token assets with cliff-plus-linear, linear and milestone schedules, created singly or in batches.
It keeps schedule terms and claim amounts public while allowing a beneficiary to claim to a private account under a one-time alias; the repository also contains its RISC Zero guest, Rust SDK, CLI, SPEL IDL, and a first Basecamp mini-app.
This checkout has in-process and standalone-sequencer evidence plus 66 recorded transactions (57 applied, 9 deliberately refused) on a public LEZ v0.4.0-rc3 network, but it is not an audited or completed LEZ testnet 0.4 delivery.

Review commit: the head of `main` (its CI run in step 5). The outputs below were checked at the merge that added this page and CI's `basecamp` job, on top of `eef9b55` ([CI run 45680840213](https://github.com/landclimber/escapement/actions/runs/45680840213), green). Clone with full history (`git clone https://github.com/landclimber/escapement && cd escapement`; not --depth 1, not a ZIP) and run commands from the repository root. The first three need Python 3.11+ and git (step 2 re-reads older commits); none sends a transaction or needs a key.

## The 10-minute verification path

### 1. Re-read the public deployment and lifecycle (about 1–2 minutes)

```sh
scripts/verify-public.sh
```

This reads `https://54-156-116-24.sslip.io/rpc` and checks the committed calls, outcomes, blocks, accounts, escrows, deployment segments, and proof envelope against the live answers. Expect 66 `ok` transaction lines followed by account and consistency checks; notable lines include:

```text
ok       complete: each of the 15 accounts that signed has exactly its recorded transactions on chain (its nonce)
ok       66 blocks fetched, 59 consecutive pairs linked by their parent hashes
ok    64 10-private-claim-confirm                       escapement.ClaimExact           block  19219 applied, succinct proof 237,142 B  https://54-156-116-24.sslip.io/explorer/#/tx/05a7d6b292dec4887d10fa7b3459a0a65fe6616da1a01af3acd60a842bcbe571
ok       refusals.json: the 9 refused transactions, each schedule unchanged
all checks passed
```

An RPC or network failure is not a passing result. For exactly what is and is not checked, and the important single-operator trust limit, read [PUBLIC-NETWORK.md](PUBLIC-NETWORK.md#what-verify-publicsh-checks) and its [limits](PUBLIC-NETWORK.md#what-this-does-not-show).

### 2. Re-derive the committed run records (about 10 seconds)

```sh
python3 scripts/verify-records.py --require-history
```

Expect five passing records, then this summary:

```text
records (5):
...
claims: 79 PASS, 27 DOC, 0 FAIL
all records and claims check
```

`PASS` means re-derived from committed raw files; `DOC` means the script only confirmed a statement in the historical documentation, not an independent measurement. The self-test at the top and raw-file scan should pass, and none of the 106 individual claims should show FAIL.

### 3. Check the requirement map (a few seconds)

```sh
python3 scripts/check-reqmap.py
```

Expect exactly:

```text
check-reqmap: 45 clauses (27 shown, 16 in part, 0 not yet, 2 waits on Logos); 96 distinct named tests; OK
```

This checks the map's structure, source test names, records, and generated page. CI additionally downloads the pinned RFP text, compares compiled test listings and E2E records, and self-tests the checker; this short local command does not replace those CI steps or inspect what test bodies assert.

### 4. Reproduce the guest identity (if the pinned toolchains are already installed)

```sh
scripts/build-guest.sh --check
```

This needs host Rust 1.98.1 (rust-toolchain.toml), `r0vm` 3.0.5 on PATH, and a `RISC0_HOME` whose only Rust toolchain is 1.91.1 (see the header of scripts/build-guest.sh: export RISC0_HOME="$PWD/.risc0-guest" && rzup install rust 1.91.1 && rzup install cpp 2024.1.5). Installing toolchains is outside the 10-minute budget; on a bare machine, use the CI check below instead. On success, the last two lines are the committed `image-ids.tsv` row and the confirmation:

```text
escapement	2f59485486434472e333dd2e508d53c63ecaf44124bda0548fafaeb0c83482f8	8d0da3ee38ce2b2e6707fca63a7bdf7dfeef162a5e9d066064886a2770c7be15	496444
the image id matches image-ids.tsv
```

The immutable public deployment has the **older** image ID `adc8b81f…df4c`: it was deployed before the H-01 cancel-clamp fix and cannot be upgraded. Do not expect the public header to equal this checkout's newer ID; [PUBLIC-NETWORK.md](PUBLIC-NETWORK.md#the-program) explains the distinction.

### 5. Inspect the CI and Basecamp evidence (remaining minutes)

Open [the CI runs on `main`](https://github.com/landclimber/escapement/actions/workflows/ci.yml?query=branch%3Amain) and pick the run for the commit you checked out. It should show `completed / success`, with `core-and-guest`, `e2e-standalone-sequencer`, `requirement-map`, `records` and `basecamp` all `success`, and `real-stark-proof: skipped` (that job repeats the in-process real-proof test and runs only on manual dispatch; it has not been dispatched on this repository, and its in-process result is a DOC claim in [EVIDENCE.md](EVIDENCE.md). The recorded real-proof evidence is the standalone-sequencer run [e2e-sequencer-real-proof-2026-11-24.json](records/e2e-sequencer-real-proof-2026-11-24.json), re-checked in step 2).

The Basecamp binaries and release assets are not committed. You can still check that the package source trees named in the results are the trees at `d731205`, the commit they were built from:

```sh
git rev-parse d731205:basecamp/escapement_core_module \
  d731205:basecamp/escapement_ui d731205:basecamp/scripts
```

Expect:

```text
84a127209827888cdb94d0735f9402bfe9344e25
9eed77bce607a1a02c6796607b70703236404788
018a7318d38748b7cbe34fb7a1cc83bf01ccb5c2
```

and that since then only test code changed in them (one `vested_high_water` fixture line in each of two module test files, and CI's `basecamp/scripts/ci-workspace.py`):

```sh
git diff --stat d731205 HEAD -- basecamp/escapement_core_module basecamp/escapement_ui basecamp/scripts
```

Then read [basecamp/RESULTS.md](../basecamp/RESULTS.md): it records 25/25 module tests, 10/10 view tests, 31/31 headless Logos Core steps, signed local package verification, and a screenshot-by-screenshot Basecamp create/claim/cancel session. Its [package table](../basecamp/RESULTS.md#packages-linux-amd64) gives these signed linux-amd64 SHA-256 values:

| Package | Signed SHA-256 |
|---|---|
| `escapement_core_module-0.1.0.lgx` | `6ed37848d8c36a3f5be209c346569459aafb26bd4bffb522d5e816fbcdd20194` |
| `escapement_ui-0.1.0.lgx` | `71861615e01c0dd602a733bd4c2973e104e3f33387c2b90dd9a3c62ae62d4029` |

Those are recorded hashes, not hashes you can recompute without the uncommitted package files. Packages were signed with an explicitly named **test key**. CI's `basecamp` job runs the module's 25 calls tests (against a stand-in sequencer, without Nix), the view's amount helpers and its Qt Quick tests; building the packages and the headless Logos Core and Basecamp steps are not in CI. CI's calls tests build against escapement-core and escapement-sdk as at the checked-out commit (with the H-01 fix), not the `2ddc57c` copy the packages embed.
The packages embed crates staged from 2ddc57c and were exercised against the earlier adc8b81f guest, not the H-01-fixed one.

## Where every RFP-017 requirement is shown

Start with the summary in [REQUIREMENTS.md](REQUIREMENTS.md#summary). Each clause below links to its quoted text, status, named tests (where any), records, and (where partial) what remains.

| Area | Clauses |
|---|---|
| Functionality | [F1](REQUIREMENTS.md#f1), [F1a](REQUIREMENTS.md#f1a), [F1b](REQUIREMENTS.md#f1b), [F1c](REQUIREMENTS.md#f1c), [F2a](REQUIREMENTS.md#f2a), [F2b](REQUIREMENTS.md#f2b), [F2c](REQUIREMENTS.md#f2c), [F3a](REQUIREMENTS.md#f3a), [F3b](REQUIREMENTS.md#f3b), [F3c](REQUIREMENTS.md#f3c), [F3d](REQUIREMENTS.md#f3d), [F4](REQUIREMENTS.md#f4), [F5](REQUIREMENTS.md#f5), [F6](REQUIREMENTS.md#f6) |
| Usability | [U1](REQUIREMENTS.md#u1), [U2a](REQUIREMENTS.md#u2a), [U2b](REQUIREMENTS.md#u2b), [U2c](REQUIREMENTS.md#u2c), [U3](REQUIREMENTS.md#u3), [U4a](REQUIREMENTS.md#u4a), [U4b](REQUIREMENTS.md#u4b), [U5](REQUIREMENTS.md#u5), [U6](REQUIREMENTS.md#u6), [U7](REQUIREMENTS.md#u7) |
| Reliability | [R1](REQUIREMENTS.md#r1), [R2](REQUIREMENTS.md#r2), [R3](REQUIREMENTS.md#r3), [R4](REQUIREMENTS.md#r4) |
| Performance | [P1](REQUIREMENTS.md#p1), [P2](REQUIREMENTS.md#p2) |
| Supportability | [S1](REQUIREMENTS.md#s1), [S2](REQUIREMENTS.md#s2), [S3](REQUIREMENTS.md#s3), [S4](REQUIREMENTS.md#s4) |
| Privacy | [Pr1](REQUIREMENTS.md#pr1), [Pr2](REQUIREMENTS.md#pr2), [Pr3](REQUIREMENTS.md#pr3) |
| Soft requirements | [SR1](REQUIREMENTS.md#sr1), [SR2](REQUIREMENTS.md#sr2) |
| Fees | [FS1](REQUIREMENTS.md#fs1), [FS2](REQUIREMENTS.md#fs2), [FS3](REQUIREMENTS.md#fs3), [FS4](REQUIREMENTS.md#fs4) |
| Batch bound and licence | [D1](REQUIREMENTS.md#d1), [L1](REQUIREMENTS.md#l1) |

In particular, do not read `shown` as “all requirements complete”: 16 clauses are partial, P2 and S1 wait on Logos, and F3c, U2a, U2b, U2c, and P1 explicitly record where code differs from the filed proposal.

## Honest limits

### Not built or not delivered yet

- **LEZ testnet 0.4:** no deployment or CU measurements there; testnet 0.4 has not launched. The public evidence is from the separate, single-sequencer Ferrata network on v0.4.0-rc3 (P2, S1).
- **Mini-app releases:** no downloadable release `.lgx` assets or installation from a git repository, no macOS build, and no demonstrated byte-reproducible packages. Only local linux-amd64 packages signed by a test key were exercised.
- **Mini-app lifecycle:** no private claim or privacy disclosure screen, no milestone signal, and no beneficiary transfer. Creation is limited to native-LEZ linear/cliff schedules and lacks transferability, delegated authorities, tokens, and milestone terms; the module's calls tests and the view's tests run in CI's `basecamp` job (without Nix, against a stand-in sequencer), but building the packages and running them in Logos Core or Basecamp is outside CI (U1, U2a–U2c, U4b, U5, Pr1, Pr2).
- **One-transaction private token claim:** a fresh private token account needs holding initialization before its claim; on the public host a full token-private path would also need a native-fee shield. Public Ferrata ran a native private claim, not a token private claim (P1).
- **Event consumption:** events are emitted and their schemas tested, but they have not been read back through an indexer; on v0.4.0-rc3 getEvents is the indexer's RPC, so this waits on testnet 0.4 (F6).
- **Remote-wallet UX:** the CLI currently targets a local sequencer with file-held keys; testnet remote endpoints and wallet-held keys remain future work (U3).

### Known risks and evidence boundaries

- **Not audited.** No independent security audit has happened; the external audit remains M5. Some admin/malformed-message refusals can panic and consume the whole gas limit rather than return a metered vesting error. See [SECURITY.md](SECURITY.md).
- **Pinned platform advisory:** LEZ v0.4.0-rc3 uses RISC Zero `<3.1.0`, affected by critical advisory GHSA-g6qg-9j8p-7j87. Escapement pins the platform and plans to follow the LEZ release that bumps it ([D-15](DECISIONS.md)).
- **Operator trust:** public verification reads one bidder-operated RPC. It does not compare independent nodes, verify Logos Blockchain anchoring, or run a RISC Zero verifier for the private receipt; it checks the receipt kind/size and relies on sequencer verification. The public deployment's admin/test keys also reside on that host.
- **The deployed program is the earlier build:** the public deployment keeps the immutable pre-H-01 guest (image id `adc8b81f…`, from `2ddc57c`), while this checkout builds the fixed guest with a new image id. The fixed guest has not been deployed there yet.
- **Privacy is scoped:** schedule, beneficiary, claim amount, time, and one-time alias are public; the receiving private account and subsequent movements are not. Claims remain linkable through public schedule information by design.
- **Proof cost is substantial:** the recorded public-host native private proof took 48.7 minutes and peaked at 9.17 GiB on a shared 4-vCPU host; a 32-vCPU standalone run took 205.6 seconds. Neither is a portable benchmark.
- **Traceability is not proof of assertion quality:** the requirement checker validates names, CI wiring, records, and generated documentation, but does not reason about test bodies. Historical `DOC` claims and screenshots are evidence records, not fresh execution.
