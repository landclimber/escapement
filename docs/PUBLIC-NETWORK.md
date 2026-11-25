# Escapement on a public LEZ network

Recorded 25 Nov 2026. Escapement is deployed, immutably, on the **Ferrata LEZ test network**: a public network
running LEZ `v0.4.0-rc3` (one sequencer, anchored to its own Logos Blockchain node), with a public JSON-RPC at
`https://54-156-116-24.sslip.io/rpc`, an explorer at `https://54-156-116-24.sslip.io/explorer/` and a network page at
`https://54-156-116-24.sslip.io/network`. It is not LEZ testnet 0.4, which has not launched. The records are in
[`public-network/`](public-network/), and one read-only script checks them against the chain:

```sh
scripts/verify-public.sh          # python3 only; RPC=<url> for another endpoint serving the same chain
```

It prints each transaction's and account's explorer page (`…/explorer/#/tx/<hash>`, `…/explorer/#/account/<id>`);
the explorer names the program from its image id. **Every read goes through the operator's own RPC** (see "What this
does not show").

## The program

| | |
|---|---|
| Program account | `Be6eH1Ps2cr7zSmuV2XfwZDkF14naGcEG6h71ViszSXW` |
| Image id | `adc8b81f8b3f939f36cea61e23516acd1916e3b4e1b5e30a5ff91931d934df4c`, the id in `image-ids.tsv`. The guest was rebuilt from this tree with `scripts/build-guest.sh --check` (Linux x86-64; same id, SHA-256 `03d8e8d9…`, 495,452 bytes) and that binary deployed. The program header on chain carries this image id and `immutable = true`: read back by the deploy itself and by `verify-public.sh`. |
| Deployment | immutable through LEZ's program loader: five segments, written tail first and chained, and the header pointing to the first (transactions 1–6; header `0a8644e2b9931f1b66b93290b247fceb13516c4ac1086ba7d11a6d641be38374`, block 18,912), then the admin init (7) |
| Deployer | a fresh key generated on the network's host and funded by the network's faucet (transaction 0) |
| Token program | `lez-programs` at `3f04cc37` (the commit `Cargo.lock` pins), image id `62f542e9fe5d7e740cafd920ce2866bfb4b0394bc3a5427ec480c89b7e057e5a`, deployed immutably beside Escapement (8–11) at `2RAjghNzt7QjRDRmuekUhRZmyj6ctwgEDoTrSjj7JJtq`, and set as Escapement's token program (12) |
| Admin, fees | the configuration account `CAENwox2ifnJiRq8Dk4iucFAGS5d6hMhrLRmT3r3iuWy` holds that token program, a creation fee of 0 bps, no treasury, and the admin seat (`lez-admin-authority`) held by the program's header account, as in the end-to-end suite |

## What ran

66 transactions, each listed in [`public-network/transactions.tsv`](public-network/transactions.tsv) with its role,
block, index and outcome, and the call it made: the program, the account the call is rooted at, the account that
signed it, and its arguments (`expect`). The accounts are in [`public-network/accounts.tsv`](public-network/accounts.tsv).

| Kind | Count | |
|---|---:|---|
| Deployment | 11 | Escapement: 5 segments, header, admin init; the token program: 3 segments, header |
| Configuration | 1 | the token program id (write-once), fee 0 bps |
| Funding | 4 | the faucet to the deployer; three fresh accounts admitted by key evidence |
| Token program | 3 | a token definition; two public holdings |
| Schedules created | 9 | native: linear (two, one for the private claim), cliff + linear, milestone (with a separate milestone authority), linear transferable, linear made non-cancelable; token: linear, cliff + linear, milestone |
| Batches | 2 | one `BatchCreate` each, native and token, three schedules on one escrow each |
| Public claims | 17 | partial and full; cliff + linear, linear, both milestone tranches of both milestone schedules, after a transfer, after a cancel, from batches |
| Private claim | 1 | native, into the beneficiary's own private account, **real RISC Zero proof** (below) |
| Milestone signals | 4 | by the milestone authority, both tranches, native and token |
| Transfer | 1 | of a transferable schedule to a new beneficiary |
| Make non-cancelable | 2 | one-way |
| Cancels | 2 | native and token: the vested part stays claimable (claimed after), the rest refunded |
| Refused on chain | 9 | below |

### What `verify-public.sh` checks

For each transaction: it is on chain at the recorded block and index (its hash recomputed from its encoding, the
block's hash from the block's contents), and applied or reverted as recorded; its call decodes to the recorded program,
message and arguments (for example, a claim's schedule, destination and amount; a creation's beneficiary, asset, total,
kind, cliff or tranches and authorities), rooted at the recorded account and signed by the recorded one (from its
witnesses); and the step's name agrees with the call. Rows whose transactions were swapped therefore fail; the `role`
column itself is a description, not checked. The deployments' segments must chain to their headers, and fetched
consecutive blocks must link by their parent hashes. For the private claim, the proof must be a real RISC Zero receipt
(`InnerReceipt` Composite, Succinct or Groth16, not the Fake one dev mode makes) of the recorded variant and size, and
its actors must include the schedule.

For the accounts: both program headers (image id, immutable), the configuration, every schedule's full state (creator,
beneficiary, asset, kind, total, claimed, flags, authorities, cancellation), and every native escrow's balance against
what its schedules are still owed. The host's records below are cross-checked against the transactions they describe.
101 checks in all; `--self-test` adds 13 wrong records (an amount, a destination, the root or signing account, the
operation, a batch recipient's total, an authority, the fee, a refusal's outcome and gas, a dev-mode receipt, two rows'
operations swapped), each of which must fail.

### Refusals read back

Nine actions were sent without the CLI's own checks (`--no-precheck`), so that the program itself had to refuse them:
an overclaim; a claim from a milestone tranche before its signal; after a transfer, a claim signed by the old
beneficiary (addressed, as the CLI addresses claims, to the schedule's beneficiary seat, now the new beneficiary's); a
milestone signal by the creator, who is not the milestone authority; a second signal of the same tranche; a cancel of a
non-cancelable schedule; a cancel by the beneficiary; a transfer of a non-transferable schedule; and make-non-cancelable
by the beneficiary. Each is in its block's reverted indices (its effects undone, its fee charged). The chain records
that a transaction reverted, not why; each was sent with a 1,000,000 gas limit (checked), about ten times what the
applied equivalents used, so none ran out of gas. The schedule was read before and after each (`escapement show`,
clock-dependent fields aside) and was identical: [`public-network/refusals.json`](public-network/refusals.json).

## The private claim with a real proof

**Checked on chain by `verify-public.sh`:** the transaction, its call (`ClaimExact` of 50,000,000 from the schedule to
the alias), that its receipt is a Succinct one of 237,142 bytes (a real proof, not dev mode), and the schedule and its
escrow afterwards. **Reported by the operator, not checked by the script:** the proving time, CPU, memory, hardware,
fee reserve, the private balance and the CLI's privacy checks, from the host's records in
[`public-network/private-claim.json`](public-network/private-claim.json) (the CLI's output and systemd's accounting).

| | |
|---|---|
| Transaction | `05a7d6b292dec4887d10fa7b3459a0a65fe6616da1a01af3acd60a842bcbe571`, block 19,219: privacy-preserving, 251,302 bytes, applied |
| What it did | `ClaimExact` of 50,000,000 native from schedule `79nFmLroryv5N6kjmPozRB7nk4VvajcGxXMahhn7WkFD` (linear, 200,000,000) into the beneficiary's own private account, under the one-time alias `8dVohtazioQf4e7Mr4Cch1gM899n2LMm97AcvHTi95of`; the schedule's escrow now holds exactly 150,000,000 |
| Proof | a full RISC Zero proof, a Succinct receipt of 237,142 bytes (not dev mode), made by `escapement-cli` through `r0vm` 3.0.5 and verified by the network's sequencer, which included and applied the transaction; 48,308 public cycles |
| Fee | 5,457,080, reserved and paid inside the proof out of the claimed credit; the account's balance afterwards, decrypted by the CLI from its own note, is 44,542,920 = 50,000,000 − 5,457,080 |
| Privacy checks | by the CLI on the host: the account's new commitment is on chain (`getProofsAndRoot`), the account's id does not appear in the transaction's bytes, and the key file records the new state |
| Proving time | **2,922.8 s** (48.7 min) for the proof; 2,925 s for the whole command (prepare, prove, send, wait for the block) |
| CPU, memory | 5,065 s of CPU for the command (about 1.7 cores on average); **peak memory 9.17 GiB** (9,849,651,200 bytes, the command's control group, page cache included) under a 10 GiB cap |
| Hardware | the network's own host, an AWS m7i.xlarge: **4 vCPUs (Intel Xeon Platinum 8488C), 15.3 GiB**, shared with the running sequencer, Logos Blockchain node, indexer and explorer, and from its 5th to its 24th minute with the CLI's other steps (blocks 18,957–19,072), which simulated the guest on the same host. The prover was held to two threads, at the lowest CPU priority. |

On a 32-vCPU container the same kind of transaction took 205.6 s, about 14 times faster (E-13 in
[EVIDENCE](EVIDENCE.md)).

## How it was run

The CLI ran on the network's own host, against its sequencer on `127.0.0.1:3040` (it talks only to a sequencer on
loopback), as a dedicated system user: built from `2ddc57c` for every step up to the token cancel (step 38) and the
private claim, and from `351d235` (this branch's `batch` command added, nothing else changed) from the first batch
(step 39) on. Every key (the deployer's, the program's header key, three public accounts, the private account) was
generated there and never left it. The step names in `transactions.tsv` follow the commands of `e2e/run_e2e.sh`;
every command's output is in [`public-network/run-records.json`](public-network/run-records.json).

## What this does not show

- **Every check reads the operator's RPC.** `verify-public.sh` checks that the answers of one endpoint (by default
  the operator's) are consistent with the records and with themselves: each block against its own header, consecutive
  fetched blocks against each other. It does not show that other nodes serve the same chain, nor check its anchoring
  on the Logos Blockchain, and the network has no second sequencer to compare with; the explorer reads the same RPC.
  The proof's validity rests on the sequencer's verification: the script reads its variant and size but does not run a
  RISC Zero verifier (that needs LEZ's privacy circuit id).
- It is not LEZ testnet 0.4, and the network is one sequencer that the bidder's team operates.
- Not audited.
- The program is immutable, but its admin seat (`lez-admin-authority`: the creation fee, at most 100 bps, and its
  treasury) is the deployment's header key, held on the network's host with the test accounts' keys.
- The cancel clamp's binding case (a claim and a cancel in the same block, the clock lagging one block) was not
  reproduced here: in both cancels the vested amount was above the claimed one, so `max(vested, claimed)` chose the
  vested amount. That case is covered by tests (D-10 in [DECISIONS](DECISIONS.md)).
- A private **token** claim was not run on this network (on this host it needs three proven transactions: a private
  shield for its fee, the private token holding, and the claim); it ran with real proofs on a standalone sequencer
  (E-13 in [EVIDENCE](EVIDENCE.md)).
- Events were not read back through an indexer (on `v0.4.0-rc3`, `getEvents` is the indexer's RPC).
- The proof time is from a 4-vCPU host shared with the running network, on two threads: not a benchmark.
- What a private claim makes public is as designed: the schedule, its beneficiary, the amount and time; not the
  private account that received it.
