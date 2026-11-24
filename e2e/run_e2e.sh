#!/usr/bin/env bash
# End-to-end suite against a local standalone LEZ v0.4.0-rc3 sequencer (S2), driven by the
# Escapement CLI (crates/escapement-cli). One JSON line per step in $E2E_OUT/e2e.jsonl.
#
#   e2e/run_e2e.sh            dev-mode receipts (E2E_DEV_MODE=1, the default; what CI runs)
#   E2E_DEV_MODE=0 e2e/run_e2e.sh   real RISC Zero proofs, verified by the sequencer
#
# Needs: e2e/sequencer.sh build (sequencer + CLI), the guest built (scripts/build-guest.sh), jq.
# Talks only to 127.0.0.1. Uses LEZ's published local test key (local.json genesis) as creator.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
export E2E_DEV_MODE="${E2E_DEV_MODE:-1}"
export E2E_HOME="${E2E_HOME:-$HERE/.run}"
export E2E_OUT="${E2E_OUT:-$E2E_HOME/out}"
S="$HERE/sequencer.sh"
ELF="${ESCAPEMENT_ELF:-$ROOT/target/riscv-guest/escapement-methods/escapement-guest/riscv32im-risc0-zkvm-elf/release/escapement.bin}"
OUT="$E2E_OUT/e2e.jsonl"
mkdir -p "$E2E_OUT"; : > "$OUT"
[ -f "$ELF" ] || { echo "guest binary missing: $ELF (run scripts/build-guest.sh)"; exit 1; }
export ESCAPEMENT_ELF="$ELF"

cli() { "$S" cli "$@"; }
record() { # NAME OK JSON
  echo "{\"step\":\"$1\",\"ok\":$2,\"out\":${3:-null}}" >> "$OUT"
  if [ "$2" = true ]; then echo "PASS $1" >&2; else echo "FAIL $1: ${3:-}" >&2; fi
}
step() { # NAME CMD...   (passes if the command succeeds)
  local name="$1"; shift
  local out
  if out="$("$@" 2>>"$E2E_OUT/stderr.log")"; then record "$name" true "$out"; echo "$out"; else record "$name" false "\"command failed\""; echo "{}"; fi
}
expect() { # NAME JQ_FILTER JSON   (passes if the filter is true)
  if [ "$(echo "$3" | jq -r "$2" 2>/dev/null)" = true ]; then record "$1" true "$3"; else record "$1" false "$3"; fi
}
clock() { cli probe 2>/dev/null | jq -r .result.clock_ms; }
claimed() { cli show --schedule "$1" 2>/dev/null | jq -r .result.claimed; }
wait_clock_past() { # MS
  for _ in $(seq 1 120); do [ "$(clock)" -gt "$1" ] && return 0; sleep 1; done; return 1
}

"$S" start
trap '"$S" stop >/dev/null 2>&1 || true' EXIT

P="$(step probe cli probe)"
D="$(step deploy-immutable-and-init-admin cli deploy "$ELF" --init-admin --keys-out "$E2E_HOME/deploy.json")"
expect header-immutable-and-image-id '.result.immutable == true and (.result.image_id | length) == 64' "$D"
export ESCAPEMENT_PROGRAM="$(jq -r .program "$E2E_HOME/deploy.json")"
ADMIN_KEY="$(jq -r .header_key "$E2E_HOME/deploy.json")"

# Beneficiary and a second account, funded for fees (fresh keys: admitted by key evidence).
B="$(cli keygen)"; BK="$(echo "$B" | jq -r .key)"; BA="$(echo "$B" | jq -r .account)"
C="$(cli keygen)"; CK="$(echo "$C" | jq -r .key)"; CA="$(echo "$C" | jq -r .account)"
step fund-beneficiary cli fund --to-key "$BK" --amount 100000000000 >/dev/null
step fund-second cli fund --to-key "$CK" --amount 100000000000 >/dev/null
as_b() { ESCAPEMENT_KEY="$BK" cli "$@"; }
as_c() { ESCAPEMENT_KEY="$CK" cli "$@"; }

# 1. Linear schedule: create, partial public claim, on-chain overclaim refusal, private claim,
#    cancel (unvested back), vested remainder claimable after cancel.
NOW="$(clock)"
# Long enough that a real proof (minutes on CPU) lands before everything has vested.
LINEAR_MS="${E2E_LINEAR_MS:-$([ "$E2E_DEV_MODE" = 1 ] && echo 90000 || echo 3600000)}"
L="$(step create-linear cli create --beneficiary "$BA" --total 1000000000 --linear "$NOW,$((NOW + LINEAR_MS))")"
LS="$(echo "$L" | jq -r .result.schedule)"
expect escrow-holds-total '.result.escrow_balance == "1000000000"' "$L"
wait_clock_past $((NOW + 20000))
R="$(step claim-public-partial as_b claim --schedule "$LS" --amount 100000000 --to "$BA")"
expect claim-public-applied '.result.tx.reverted == false and .result.escrow_debited == "100000000" and .result.claimed_total == "100000000"' "$R"
BEFORE="$(claimed "$LS")"
R="$(step refusal-overclaim-sent-on-chain as_b claim --schedule "$LS" --amount 999000000 --to "$BA" --no-precheck)"
expect refusal-overclaim-reverted-state-unchanged ".result.tx.reverted == true and \"$(claimed "$LS")\" == \"$BEFORE\"" "$R"
R="$(step claim-private-one-tx as_b claim --schedule "$LS" --amount 50000000 --private --accept-privacy-disclosure)"
expect claim-private-applied '.result.tx.reverted == false and .result.private_commitment_found == true and .result.private_account_id_in_tx_bytes == false and .result.escrow_debited == "50000000"' "$R"
R="$(step cancel-by-creator cli cancel --schedule "$LS")"
expect cancel-applied '.result.tx.reverted == false' "$R"
SH="$(cli show --schedule "$LS")"
expect cancel-froze-vesting '.result.cancelled != null and (.result.cancelled.vested | tonumber) >= 150000000 and (.result.cancelled.refunded | tonumber) > 0' "$SH"
R="$(step claim-vested-after-cancel as_b claim --schedule "$LS" --to "$BA")"
expect vested-remainder-claimed '.result.tx.reverted == false' "$R"
SH="$(cli show --schedule "$LS")"
expect escrow-empty-after-cancel-and-claim '.result.escrow_balance == "0"' "$SH"

# 2. Milestone schedule with a delegated milestone authority: creator refused on chain, the
#    authority signals, a second signal is refused on chain, the beneficiary claims the tranche.
M="$(step create-milestone cli create --beneficiary "$BA" --total 300000000 --milestones 100000000,200000000 --milestone-authority "$CA")"
MS="$(echo "$M" | jq -r .result.schedule)"
R="$(step refusal-creator-signal-sent-on-chain cli signal --schedule "$MS" --index 0 --no-precheck)"
expect refusal-creator-signal-reverted '.result.tx.reverted == true' "$R"
R="$(step signal-by-authority as_c signal --schedule "$MS" --index 0)"
expect signal-applied '.result.tx.reverted == false' "$R"
R="$(step refusal-double-signal-sent-on-chain as_c signal --schedule "$MS" --index 0 --no-precheck)"
expect refusal-double-signal-reverted '.result.tx.reverted == true' "$R"
R="$(step claim-milestone-tranche as_b claim --schedule "$MS" --to "$BA")"
expect milestone-tranche-received '.result.escrow_debited == "100000000" and .result.claimed_total == "100000000"' "$R"

# 3. Transferable schedule: transfer, the old beneficiary is refused on chain, the new one claims.
NOW="$(clock)"
T="$(step create-transferable cli create --beneficiary "$BA" --total 10000000 --linear "$((NOW - 1000)),$((NOW + 1000))" --transferable)"
TS="$(echo "$T" | jq -r .result.schedule)"
R="$(step transfer-beneficiary as_b transfer-beneficiary --schedule "$TS" --to "$CA")"
expect transfer-applied '.result.tx.reverted == false' "$R"
wait_clock_past $((NOW + 2000))
R="$(step refusal-old-beneficiary-sent-on-chain as_b claim --schedule "$TS" --to "$BA" --no-precheck)"
expect refusal-old-beneficiary-reverted '.result.tx.reverted == true' "$R"
R="$(step claim-by-new-beneficiary as_c claim --schedule "$TS" --to "$CA")"
expect new-beneficiary-received '.result.escrow_debited == "10000000"' "$R"

# 4. Non-cancelable conversion is one-way: cancel afterwards is refused on chain.
NOW="$(clock)"
N="$(step create-for-noncancelable cli create --beneficiary "$BA" --total 5000000 --linear "$NOW,$((NOW + 600000))")"
NS="$(echo "$N" | jq -r .result.schedule)"
R="$(step make-non-cancelable cli make-non-cancelable --schedule "$NS")"
expect non-cancelable-applied '.result.tx.reverted == false' "$R"
R="$(step refusal-cancel-after-noncancelable-sent-on-chain cli cancel --schedule "$NS" --no-precheck)"
expect refusal-cancel-after-noncancelable-reverted '.result.tx.reverted == true' "$R"
R="$(step refusal-beneficiary-cancels-sent-on-chain as_b cancel --schedule "$NS" --no-precheck)"
expect refusal-beneficiary-cancel-reverted '.result.tx.reverted == true' "$R"

# 5. Events: LEZ v0.4.0-rc3 serves `getEvents` from the indexer, not the sequencer; recorded as
#    observed (see docs/events.md).
EV="$("$S" rpc getEvents '[{"from_block":1,"to_block":1000}]' 2>&1 || true)"
echo "{\"step\":\"getEvents-observation\",\"ok\":true,\"out\":$(printf '%s' "$EV" | jq -Rs .)}" >> "$OUT"

"$S" stop; trap - EXIT
PASSED="$(grep -c '"ok":true' "$OUT" || true)"; FAILED="$(grep -c '"ok":false' "$OUT" || true)"
echo "e2e: $PASSED passed, $FAILED failed (dev mode: $E2E_DEV_MODE); records in $OUT"
[ "$FAILED" = 0 ]
