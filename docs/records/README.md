# Run records

Machine-checkable records of the runs behind the figures in `docs/EVIDENCE.md` and the RFP-017
proposal. Each figure is re-derived from the files the run itself wrote.

```
python3 scripts/verify-records.py                    # PASS/FAIL per record and per claim
python3 scripts/verify-records.py --require-history  # as CI runs it (needs full git history)
python3 scripts/verify-records.py --derive ID        # what the parsers read from record ID's raw files
```

## What is here

| File | Run | Raw files |
|---|---|---|
| `e2e-sequencer-real-proof-2026-11-24.json` | E-13: `e2e/run_e2e.sh` with real proofs, 75/75, five proven transactions | `out-r2-real/e2e.jsonl`, `r2-real.time`, `r2-t4.log` |
| `e2e-sequencer-dev-2026-11-24-dev3.json` | E-12: the same suite with dev-mode receipts, 75/75 | `out-r2-dev3/e2e.jsonl`, `r2-t4.log` |
| `e2e-sequencer-dev-2026-11-24-dev2.json` | E-12: an earlier dev-mode run that day, 75/75 (records file only) | `out-r2-dev2/e2e.jsonl` |
| `suite-log-2026-11-24-r2.json` | the round's driver log: guest check, signer-authority tests with their cycles, SDK tests | `r2-t4.log` |
| `guest-adc8b81f.json` | `image-ids.tsv` against the image id read back from every recorded deployment | the three `e2e.jsonl` |
| `claims.json` | every measured figure of the proposal the repository can back, and its source | |

The raw files in `raw/2026-11-24-r2/` are the original files the runs wrote under the ignored
`e2e/.run/` on the machine that ran them, with only one change: every local absolute path is
replaced by a placeholder (`<workdir>` for the checkout's root, `<risc0-home>` for the RISC Zero
toolchain home). Nothing else differs. Each record gives the original's relative path, SHA-256 and
size beside those of the committed copy, and the verifier fails if a raw file holds an absolute
home path. The devnet key files the suite writes are not included.

## A record

- `artifacts`: each raw file with its SHA-256 and size.
- `measured`: everything the verifier's parser for the record's `kind` reads from those files:
  check counts; every transaction id with its block, size and outcome; each check's answer (the
  CLI's JSON answer per line, hashed); the deployed image id; the proven transactions' proving
  times, proof and transaction sizes, public cycles, fee reserves and balances; GNU `time -v`
  wall, user and system time, peak RSS and exit status; the log's exit markers and timestamps.
  The verifier re-derives it and requires it to be equal.
- `source_tree`, `environment`, `hardware`, `notes`: what the raw files do not say (which commit,
  which machine), with how it is known. Each factual one has a `provenance` check: the quoted text
  is in the doc at that commit, or the run's paths are unchanged between the commits named.

## Limits

- The runs used a loopback sequencer that no longer exists, so their transactions cannot be
  re-queried; the records bind the figures to the files the runs wrote, and git history binds the
  files from the commit that added them on.
- The suite logs each CLI command's answer, not the JSON-RPC requests it sent.
- The machine is described in `docs/EVIDENCE.md`; the runs' own files do not record it.
- `claims.json` entries marked `DOC` by the verifier (Kani times, the in-process cost table and
  batch ceilings, the in-process real-proof run) are stated in the docs with no raw log behind
  them in the repository.
