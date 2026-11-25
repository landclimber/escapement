#!/usr/bin/env bash
# End-to-end suite against a local standalone LEZ v0.4.0-rc3 sequencer (S2), driven by the
# Escapement CLI (crates/escapement-cli). One JSON line per check in $E2E_OUT/e2e.jsonl; every
# record is an assertion (a step whose command must succeed, or a jq condition on its output).
#
#   e2e/run_e2e.sh                  dev-mode receipts (E2E_DEV_MODE=1, the default; what CI runs)
#   E2E_DEV_MODE=0 e2e/run_e2e.sh   real RISC Zero proofs, verified by the sequencer: the five
#                                   privacy-preserving transactions below carry real proofs; every
#                                   other step is a public transaction, which LEZ runs without one
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
KEYS="$E2E_OUT/keys"   # this run's key files (local devnet only)
mkdir -p "$E2E_OUT"; : > "$OUT"; rm -rf "$KEYS"; mkdir -p "$KEYS"; chmod 700 "$KEYS"
[ -f "$ELF" ] || { echo "guest binary missing: $ELF (run scripts/build-guest.sh)"; exit 1; }
export ESCAPEMENT_ELF="$ELF"
# The token program (lez-programs, pinned in Cargo.lock), built by its methods crate.
token_elf() { ls "$ROOT"/target/riscv-guest/token-methods/*/riscv32im-risc0-zkvm-elf/release/*.bin 2>/dev/null | head -1; }
if [ -z "$(token_elf)" ]; then (cd "$ROOT" && cargo build -q -p token-methods --locked); fi
TOKEN_ELF="${ESCAPEMENT_TOKEN_ELF:-$(token_elf)}"
[ -f "$TOKEN_ELF" ] || { echo "token program binary missing"; exit 1; }

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
expect_fail() { # NAME CMD...   (passes if the command is refused)
  local name="$1"; shift
  local out
  if out="$("$@" 2>>"$E2E_OUT/stderr.log")"; then record "$name" false "$out"; else record "$name" true "\"refused as expected\""; fi
}
clock() { cli probe 2>/dev/null | jq -r .result.clock_ms; }
# A schedule's on-chain state without the fields that move with the clock.
state_of() { cli show --schedule "$1" 2>/dev/null | jq -c '.result | del(.clock_ms, .claimable_now, .next_unlock_ms, .next_unlock_utc, .reason)'; }
refusal() { # NAME SCHEDULE CMD...   sent on chain without client checks: must be reverted, state unchanged
  local name="$1" sched="$2"; shift 2
  local before after r same
  before="$(state_of "$sched")"
  r="$(step "$name-sent-on-chain" "$@" --no-precheck)"
  after="$(state_of "$sched")"
  if [ -n "$before" ] && [ "$before" = "$after" ]; then same=true; else same=false; fi
  expect "$name-reverted-state-unchanged" "(.result.tx.reverted == true) and $same" "$r"
}
wait_clock_past() { # MS
  for _ in $(seq 1 120); do [ "$(clock)" -gt "$1" ] && return 0; sleep 1; done; return 1
}
private_claim() { # NAME KEYFILE SCHEDULE AMOUNT [as]: prepare (disclosure + token), then confirm
  local name="$1" file="$2" sched="$3" amount="$4" who="${5:-as_b}"
  local p tok
  p="$(step "$name-prepare" "$who" claim --schedule "$sched" --amount "$amount" --to-private "$file")"
  tok="$(echo "$p" | jq -r '.result.disclosure_token // empty')"
  expect "$name-disclosure-shown-and-nothing-sent" '.result.needs_confirmation == true and (.result.tx == null)' "$p"
  step "$name-confirm" "$who" claim --schedule "$sched" --to-private "$file" --confirm "$tok"
}

"$S" start
trap '"$S" stop >/dev/null 2>&1 || true' EXIT

step probe cli probe >/dev/null
D="$(step deploy-immutable-and-init-admin cli deploy "$ELF" --init-admin --keys-out "$KEYS/deploy.json")"
expect header-immutable-and-image-id '.result.immutable == true and (.result.image_id | length) == 64' "$D"
export ESCAPEMENT_PROGRAM="$(jq -r .program "$KEYS/deploy.json")"
ADMIN_KEY="$(jq -r .header_key "$KEYS/deploy.json")"

# Beneficiary and a second account, funded for fees (fresh keys: admitted by key evidence).
B="$(cli keygen)"; BK="$(echo "$B" | jq -r .key)"; BA="$(echo "$B" | jq -r .account)"
C="$(cli keygen)"; CK="$(echo "$C" | jq -r .key)"; CA="$(echo "$C" | jq -r .account)"
step fund-beneficiary cli fund --to-key "$BK" --amount 100000000000 >/dev/null
step fund-second cli fund --to-key "$CK" --amount 100000000000 >/dev/null
as_b() { ESCAPEMENT_KEY="$BK" cli "$@"; }
as_c() { ESCAPEMENT_KEY="$CK" cli "$@"; }

# The CLI refuses a mistyped flag instead of sending something else, and --dry-run sends nothing.
NOW="$(clock)"
expect_fail unknown-flag-refused cli create --beneficiary "$BA" --total 1000 --linear "$NOW,$((NOW + 1000))" --dryrun
DRY="$(step dry-run-create cli create --beneficiary "$BA" --total 1000 --linear "$NOW,$((NOW + 1000))" --dry-run)"
expect_fail dry-run-created-nothing cli show --schedule "$(echo "$DRY" | jq -r .result.schedule)"

# 1. Linear schedule: partial public claim; overclaim refused on chain; two private claims into the
#    beneficiary's own private account (a new account, then the same account again), each shown with
#    its disclosure and sent only with that disclosure's token; cancel; vested remainder claimed.
# Long enough that the cancel below lands before everything has vested, even on a slow CI runner
# (dev mode) or after real proofs (minutes on CPU); the total scales with it so that 160,000,000
# has vested about 15 s after the start.
LINEAR_MS="${E2E_LINEAR_MS:-$([ "$E2E_DEV_MODE" = 1 ] && echo 300000 || echo 3600000)}"
TOTAL=$((1000000000 * LINEAR_MS / 90000))
NOW="$(clock)"
L="$(step create-linear cli create --beneficiary "$BA" --total "$TOTAL" --linear "$NOW,$((NOW + LINEAR_MS))")"
LS="$(echo "$L" | jq -r .result.schedule)"
expect escrow-holds-total ".result.escrow_balance == \"$TOTAL\"" "$L"
wait_clock_past $((NOW + 20000))
R="$(step claim-public-partial as_b claim --schedule "$LS" --amount 100000000 --to "$BA")"
expect claim-public-applied '.result.tx.reverted == false and .result.escrow_debited == "100000000" and .result.claimed_total == "100000000"' "$R"
refusal refusal-overclaim "$LS" as_b claim --schedule "$LS" --amount 999000000 --to "$BA"

BF="$KEYS/beneficiary.private.json"
R="$(step private-account-new as_b private-account new --out "$BF")"
expect key-file-written-0600 "(.result.account | length) > 30 and \"$(stat -c %a "$BF")\" == \"600\"" "$R"
R="$(private_claim claim-private-new-account "$BF" "$LS" 50000000)"
expect claim-private-new-account-applied '.result.tx.reverted == false and .result.escrow_debited == "50000000" and .result.private_commitment_found == true and .result.private_account_id_in_tx_bytes == false and .result.account_state_saved == true and ((.result.account_native_balance_after | tonumber) == 50000000 - (.result.fee_reserve | tonumber))' "$R"
BAL1="$(echo "$R" | jq -r .result.account_native_balance_after)"
# A confirmation token that is not the disclosure's is refused before anything is proven.
P="$(step claim-private-prepare-again as_b claim --schedule "$LS" --amount 10000000 --to-private "$BF")"
BEFORE="$(state_of "$LS")"
expect_fail claim-private-wrong-token-refused as_b claim --schedule "$LS" --to-private "$BF" --confirm 0000000000000000000000000000000000000000000000000000000000000000
if [ "$(state_of "$LS")" = "$BEFORE" ]; then SAME=true; else SAME=false; fi
expect claim-private-wrong-token-changed-nothing "$SAME" '{}'
TOK="$(echo "$P" | jq -r .result.disclosure_token)"
R="$(step claim-private-same-account-confirm as_b claim --schedule "$LS" --to-private "$BF" --confirm "$TOK")"
BAL2="$(echo "$R" | jq -r .result.account_native_balance_after)"
expect claim-private-same-account-applied ".result.tx.reverted == false and .result.escrow_debited == \"10000000\" and .result.private_commitment_found == true and .result.private_account_id_in_tx_bytes == false and ((.result.account_native_balance_after | tonumber) == $BAL1 + 10000000 - (.result.fee_reserve | tonumber))" "$R"
R="$(step private-account-show as_b private-account show --file "$BF")"
expect private-account-state-on-chain ".result.state_committed_on_chain == true and .result.native_balance == \"$BAL2\"" "$R"

R="$(step cancel-by-creator cli cancel --schedule "$LS")"
expect cancel-applied '.result.tx.reverted == false' "$R"
SH="$(cli show --schedule "$LS")"
expect cancel-froze-vesting '.result.cancelled != null and (.result.cancelled.vested | tonumber) >= 160000000 and (.result.cancelled.refunded | tonumber) > 0' "$SH"
R="$(step claim-vested-after-cancel as_b claim --schedule "$LS" --to "$BA")"
expect vested-remainder-claimed '.result.tx.reverted == false' "$R"
SH="$(cli show --schedule "$LS")"
expect escrow-empty-after-cancel-and-claim '.result.escrow_balance == "0"' "$SH"

# 2. Milestone schedule with a delegated milestone authority.
M="$(step create-milestone cli create --beneficiary "$BA" --total 300000000 --milestones 100000000,200000000 --milestone-authority "$CA")"
MS="$(echo "$M" | jq -r .result.schedule)"
refusal refusal-creator-signal "$MS" cli signal --schedule "$MS" --index 0
R="$(step signal-by-authority as_c signal --schedule "$MS" --index 0)"
expect signal-applied '.result.tx.reverted == false' "$R"
refusal refusal-double-signal "$MS" as_c signal --schedule "$MS" --index 0
R="$(step claim-milestone-tranche as_b claim --schedule "$MS" --to "$BA")"
expect milestone-tranche-received '.result.escrow_debited == "100000000" and .result.claimed_total == "100000000"' "$R"

# 3. Transferable schedule: transfer, the old beneficiary is refused on chain, the new one claims.
NOW="$(clock)"
T="$(step create-transferable cli create --beneficiary "$BA" --total 10000000 --linear "$((NOW - 1000)),$((NOW + 1000))" --transferable)"
TS="$(echo "$T" | jq -r .result.schedule)"
R="$(step transfer-beneficiary as_b transfer-beneficiary --schedule "$TS" --to "$CA")"
expect transfer-applied '.result.tx.reverted == false' "$R"
wait_clock_past $((NOW + 2000))
refusal refusal-old-beneficiary "$TS" as_b claim --schedule "$TS" --to "$BA"
R="$(step claim-by-new-beneficiary as_c claim --schedule "$TS" --to "$CA")"
expect new-beneficiary-received '.result.escrow_debited == "10000000"' "$R"

# 4. Non-cancelable conversion is one-way: cancel afterwards is refused on chain.
NOW="$(clock)"
N="$(step create-for-noncancelable cli create --beneficiary "$BA" --total 5000000 --linear "$NOW,$((NOW + 600000))")"
NS="$(echo "$N" | jq -r .result.schedule)"
R="$(step make-non-cancelable cli make-non-cancelable --schedule "$NS")"
expect non-cancelable-applied '.result.tx.reverted == false' "$R"
refusal refusal-cancel-after-noncancelable "$NS" cli cancel --schedule "$NS"
refusal refusal-beneficiary-cancels "$NS" as_b cancel --schedule "$NS"

# 5. Tokens: the lez-programs token program deployed beside Escapement; a token schedule with a
#    public claim and a private claim into the beneficiary's private account, whose fee that same
#    account pays inside the proof from its native balance (funded by a private shield).
TP="$(step deploy-token-program cli deploy "$TOKEN_ELF")"
export ESCAPEMENT_TOKEN_PROGRAM="$(echo "$TP" | jq -r .result.program_address)" ESCAPEMENT_TOKEN_ELF="$TOKEN_ELF"
R="$(step configure-token-program cli configure --admin-key "$ADMIN_KEY" --fee-bps 0 --token-program "$ESCAPEMENT_TOKEN_PROGRAM")"
expect token-program-configured '.result.tx.reverted == false' "$R"
TD="$(step token-definition cli token new --supply 1000000000000)"
DEF="$(echo "$TD" | jq -r .result.definition)"
expect token-supply-at-creator '.result.holder_balance == "1000000000000"' "$TD"
step beneficiary-public-token-holding as_b token init-holding --definition "$DEF" >/dev/null
NOW="$(clock)"
K="$(step create-token-linear cli create --token "$DEF" --beneficiary "$BA" --total "$TOTAL" --linear "$NOW,$((NOW + LINEAR_MS))")"
KS="$(echo "$K" | jq -r .result.schedule)"
expect token-escrow-holds-total ".result.escrow_balance == \"$TOTAL\"" "$K"
wait_clock_past $((NOW + 20000))
R="$(step claim-token-public as_b claim --schedule "$KS" --amount 40000000 --to "$BA")"
expect claim-token-public-applied '.result.tx.reverted == false and .result.escrow_debited == "40000000" and .result.destination_delta == "40000000"' "$R"
R="$(step shield-native-for-fees as_b private-account shield --file "$BF" --amount 30000000)"
expect shield-applied '.result.tx.reverted == false and .result.private_commitment_found == true and .result.private_account_id_in_tx_bytes == false' "$R"
NATIVE_BEFORE_HOLDING="$(echo "$R" | jq -r .result.account_native_balance_after)"
R="$(step private-token-holding as_b private-account init-holding --file "$BF" --definition "$DEF")"
expect private-token-holding-applied ".result.tx.reverted == false and .result.private_commitment_found == true and ([.result.token_holdings_after[] | select(.definition == \"$DEF\")] | length) == 1 and ((.result.account_native_balance_after | tonumber) == $NATIVE_BEFORE_HOLDING - (.result.fee_reserve | tonumber))" "$R"
NATIVE_BEFORE_CLAIM="$(echo "$R" | jq -r .result.account_native_balance_after)"
R="$(private_claim claim-private-token "$BF" "$KS" 60000000)"
expect claim-private-token-applied ".result.tx.reverted == false and .result.escrow_debited == \"60000000\" and .result.private_commitment_found == true and .result.private_account_id_in_tx_bytes == false and ([.result.token_holdings_after[] | select(.definition == \"$DEF\") | .balance] == [\"60000000\"]) and ((.result.account_native_balance_after | tonumber) == $NATIVE_BEFORE_CLAIM - (.result.fee_reserve | tonumber))" "$R"

# 6. Batches: one BatchCreate for several recipients on one escrow. A dry run shows each recipient's terms and sends
#    nothing; a cliff batch gives each recipient its own cliff amount (an absolute cliff for all is refused); a
#    duplicated recipient is refused before anything is built; a token batch; a zero total, sent without the
#    client's checks, is refused on chain and creates no schedule.
NOW="$(clock)"
CLIFF_SHAPE="$((NOW - 1000)),$NOW,$((NOW + 600000))"
DB="$(step batch-dry-run cli batch --recipients "$BA:60000000:20000000,$CA:40000000:10000000" --cliff "$CLIFF_SHAPE" --dry-run)"
expect batch-dry-run-shows-each-recipients-terms ".result.dry_run == true and (.result.items | length) == 2 and .result.items[0].beneficiary == \"$BA\" and .result.items[0].cliff_amount == \"20000000\" and .result.items[1].beneficiary == \"$CA\" and .result.items[1].cliff_amount == \"10000000\"" "$DB"
expect_fail batch-dry-run-created-nothing cli show --schedule "$(echo "$DB" | jq -r '.result.schedules[0]')"
expect_fail batch-duplicate-recipient-refused cli batch --recipients "$BA:1,$BA:2" --linear "$NOW,$((NOW + 1000))"
expect_fail batch-absolute-cliff-refused cli batch --recipients "$BA:60000000,$CA:40000000" --cliff "$CLIFF_SHAPE,10000000"
NB="$(step batch-create-native-cliff cli batch --recipients "$BA:60000000:20000000,$CA:40000000:10000000" --cliff "$CLIFF_SHAPE")"
expect batch-native-escrow-holds-the-sum '.result.tx.reverted == false and .result.escrow_balance == "100000000"' "$NB"
S0="$(cli show --schedule "$(echo "$NB" | jq -r '.result.schedules[0]')")"
expect batch-native-recipient-0-terms ".result.beneficiary == \"$BA\" and .result.total == \"60000000\"" "$S0"
S1="$(cli show --schedule "$(echo "$NB" | jq -r '.result.schedules[1]')")"
expect batch-native-recipient-1-terms ".result.beneficiary == \"$CA\" and .result.total == \"40000000\"" "$S1"
R="$(step claim-from-batch as_c claim --schedule "$(echo "$NB" | jq -r '.result.schedules[1]')" --to "$CA")"
expect claim-from-batch-at-least-its-cliff '.result.tx.reverted == false and (.result.escrow_debited | tonumber) >= 10000000' "$R"
TB="$(step batch-create-token cli batch --token "$DEF" --recipients "$BA:30000000,$CA:20000000" --linear "$NOW,$((NOW + 600000))")"
expect batch-token-escrow-holds-the-sum '.result.tx.reverted == false and .result.escrow_balance == "50000000"' "$TB"
ZB="$(step batch-zero-total-sent-without-checks cli batch --recipients "$BA:0" --linear "$NOW,$((NOW + 600000))" --no-precheck)"
expect batch-zero-total-reverted '.result.tx.reverted == true' "$ZB"
expect_fail batch-zero-total-created-nothing cli show --schedule "$(echo "$ZB" | jq -r '.result.schedules[0]')"

# 7. Events: on LEZ v0.4.0-rc3 `getEvents` is the indexer's RPC, not the sequencer's.
EV="$("$S" rpc getEvents '[{"from_block":1,"to_block":1000}]' 2>&1 || true)"
expect getEvents-is-not-a-sequencer-rpc-on-rc3 '.error.code == -32601' "$EV"

"$S" stop; trap - EXIT
PASSED="$(grep -c '"ok":true' "$OUT" || true)"; FAILED="$(grep -c '"ok":false' "$OUT" || true)"
echo "e2e: $PASSED passed, $FAILED failed (dev mode: $E2E_DEV_MODE); records in $OUT"
[ "$FAILED" = 0 ]
