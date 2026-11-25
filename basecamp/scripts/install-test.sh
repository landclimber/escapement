#!/usr/bin/env bash
# The packages in a headless Logos Core (logosctl, logos-logoscore-cli 66d098d portable), as a user installs them:
# signature_policy require, the test key's DID the only trusted signer. First the refusals (an unsigned package, a
# package with one bit flipped), then both signed packages installed, the core module loaded and its version called.
# With a running LEZ v0.4.0-rc3 sequencer (FLOW_RPC, FLOW_PROGRAM, FLOW_KEYS: a directory with creator.json and
# beneficiary.json, `escapement keygen` files of funded accounts), the module's flow through Logos Core: configure,
# create a schedule (prepare, approve), the beneficiary's positions, a public claim (prepare, approve), cancel.
#
#   basecamp/scripts/install-test.sh SIGNED UNSIGNED WORK
#
# SIGNED: sign-test.sh's OUT. UNSIGNED: build-lgx.sh's OUT/linux-amd64. WORK: a new directory; the record goes to
# WORK/record (steps.tsv: name, expected, exit code, ms, pass, output; out/<step>.txt). LOGOSCTL: a logosctl (default:
# built with Nix). Needs lgx, jq, python3.
set -uo pipefail
[ $# = 3 ] || { sed -n '2,13p' "$0" >&2; exit 2; }
signed=$(cd "$1" && pwd) && unsigned=$(cd "$2" && pwd) || exit 2
mkdir -p "$3" && work=$(cd "$3" && pwd)
[ -z "$(ls -A "$work")" ] || { echo "install-test.sh: $work is not empty" >&2; exit 2; }
CLI=github:logos-co/logos-logoscore-cli/66d098d3af1367cf831b69c13a5aa8345edeb682
rec=$work/record
mkdir -p "$rec/out" "$rec/req" "$work/home"
sock=${LOGOS_TMPDIR:-/var/tmp/esc-s$$}
mkdir -p "$sock"
export TMPDIR=$sock LOGOS_TMPDIR=$sock
if [ -z "${LOGOSCTL:-}" ]; then
  if [ "$(ulimit -s)" = unlimited ]; then ulimit -s 1048576; fi
  nix build "$CLI#ctl-bundle-dir" -o "$work/logos-portable" > "$work/logosctl-build.log" 2>&1 || { tail -n 20 "$work/logosctl-build.log" >&2; exit 1; }
  LOGOSCTL=$work/logos-portable/bin/logosctl
fi
did=$(cat "$signed/keys/escapement-test.did")
ses=$work/session
ctl() { HOME="$work/home" ESCAPEMENT_MODULE_HOME="$work/module-home" "$LOGOSCTL" --config-dir "$ses" "$@"; }
step() {
  local name=$1 expect=$2 s e rc pass; shift 2
  s=$(date +%s%3N)
  "$@" > "$rec/out/$name.txt" 2>&1; rc=$?
  e=$(date +%s%3N)
  case "$expect" in
    ok) [ $rc = 0 ] && pass=1 || pass=0 ;;
    "refused: "*) [ $rc != 0 ] && grep -q -F -- "${expect#refused: }" "$rec/out/$name.txt" && pass=1 || pass=0 ;;
    "refused-any: "*) [ $rc != 0 ] && grep -q -i -E -- "${expect#refused-any: }" "$rec/out/$name.txt" && pass=1 || pass=0 ;;
    "reply: "*) [ $rc = 0 ] && python3 -I - "$rec/out/$name.txt" "${expect#reply: }" <<'PY' && pass=1 || pass=0
import json, sys
t = open(sys.argv[1]).read().strip()
v = t
for _ in range(4):
    if isinstance(v, str):
        try: v = json.loads(v)
        except Exception: break
    elif isinstance(v, dict) and "result" in v and "ok" not in v: v = v["result"]
    else: break
want = sys.argv[2]
ok = isinstance(v, dict) and eval(want, {}, {"r": v})
json.dump(v, open(sys.argv[1] + ".json", "w"))
sys.exit(0 if ok else 1)
PY
    ;;
  esac
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$expect" "$rc" "$(( e - s ))" "$pass" "$(tr '\n\t' '  ' < "$rec/out/$name.txt" | cut -c1-500)" >> "$rec/steps.tsv"
  echo "$([ $pass = 1 ] && echo PASS || echo FAIL) $name (exit $rc, $(( e - s )) ms)"
}
field() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$rec/out/$1.txt.json" "$2"; }
req() { printf '%s' "$2" > "$rec/req/$1.json"; echo "@$rec/req/$1.json"; }
call() { local name=$1 expect=$2 method=$3 body=$4; step "$name" "$expect" ctl call escapement_core_module "$method" "$(req "$name" "$body")" --json --timeout 60000; }
: > "$rec/steps.tsv"
printf 'signature_policy: require\n' > "$rec/node.yaml"
step config-set ok ctl daemon config set "$rec/node.yaml"
step daemon-start ok ctl daemon start --detach
step key-add ok ctl key add escapement-test --did "$did" --display-name "Escapement test build (not a release)"
python3 -I - "$signed/linux-amd64/escapement_core_module-0.1.0.lgx" "$work/tampered.lgx" <<'PY'
import io, sys, tarfile
src, dst = sys.argv[1], sys.argv[2]
done = False
with tarfile.open(src, "r:gz") as tin, tarfile.open(dst, "w:gz", format=tin.format) as tout:
    for m in tin.getmembers():
        data = tin.extractfile(m).read() if m.isfile() else None
        if data is not None and not done and m.name.endswith(".so"):
            b = bytearray(data); b[4096] ^= 1; data = bytes(b); done = True
        tout.addfile(m, io.BytesIO(data) if data is not None else None)
if not done:
    sys.exit("no plugin in the package")
PY
# Review R1 L5: the view's package unsigned, one signed by another key under the test signer's name, and one with its
# manifest edited after signing.
lgx keygen --name other --output-dir "$work/other-key" > /dev/null
cp "$unsigned/escapement_core_module-0.1.0.lgx" "$work/other-signed.lgx" && chmod u+w "$work/other-signed.lgx"
lgx sign "$work/other-signed.lgx" --key "$work/other-key/other.jwk" --name "Escapement test build (not a release)" > /dev/null
python3 -I - "$signed/linux-amd64/escapement_core_module-0.1.0.lgx" "$work/tampered-manifest.lgx" <<'PY'
import io, json, sys, tarfile
src, dst = sys.argv[1], sys.argv[2]
done = False
with tarfile.open(src, "r:gz") as tin, tarfile.open(dst, "w:gz", format=tin.format) as tout:
    for m in tin.getmembers():
        data = tin.extractfile(m).read() if m.isfile() else None
        if data is not None and not done and m.name.split("/")[-1] == "manifest.json":
            j = json.loads(data)
            j["description"] = "Escapement (tampered after signing)"
            data = json.dumps(j).encode(); m.size = len(data); done = True
        tout.addfile(m, io.BytesIO(data) if data is not None else None)
if not done:
    sys.exit("no manifest.json in the package")
PY
step refuse-unsigned "refused: unsigned" ctl package install "$unsigned/escapement_core_module-0.1.0.lgx" -y
step refuse-unsigned-ui "refused: unsigned" ctl package install "$unsigned/escapement_ui-0.1.0.lgx" -y
step refuse-tampered "refused: mismatch" ctl package install "$work/tampered.lgx" -y
step refuse-tampered-manifest "refused-any: mismatch|signature|invalid|verif" ctl package install "$work/tampered-manifest.lgx" -y
step refuse-other-signer "refused: untrusted" ctl package install "$work/other-signed.lgx" -y
step install-core ok ctl package install "$signed/linux-amd64/escapement_core_module-0.1.0.lgx" -y
step install-ui ok ctl package install "$signed/linux-amd64/escapement_ui-0.1.0.lgx" -y
step package-ls ok ctl package ls
step load-core ok ctl module load escapement_core_module
step version 'reply: r["ok"] and r["module"] == "escapement_core_module"' ctl call escapement_core_module version --json --timeout 60000
if [ -n "${FLOW_RPC:-}" ]; then
  K=$FLOW_KEYS; BA=$(jq -r .account "$K/beneficiary.json"); CA=$(jq -r .account "$K/creator.json")
  now=$(curl -s -m 10 -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"getLastBlockId","params":[]}' "$FLOW_RPC" > /dev/null; date +%s%3N)
  call configure-units-fixed 'reply: (not r["ok"]) and "fixed" in r["error"]' configure "{\"rpc_url\":\"$FLOW_RPC\",\"program\":\"$FLOW_PROGRAM\",\"decimals\":12}"
  call configure 'reply: r["ok"] and r["program_configured"]' configure "{\"rpc_url\":\"$FLOW_RPC\",\"program\":\"$FLOW_PROGRAM\"}"
  call key-creator "reply: r['ok'] and r['account'] == '$CA'" key "{\"action\":\"import\",\"path\":\"$K/creator.json\"}"
  call prepare-create 'reply: r["ok"] and r["op"] == "create" and r["signed"] is False' prepare_create \
    "{\"beneficiary\":\"$BA\",\"total\":\"25000000000\",\"kind\":\"linear\",\"start_ms\":$((now - 60000)),\"end_ms\":$((now + 1800000))}"
  call approve-create 'reply: r["ok"] and r["outcome"]["applied"] and r["approved_by"] == "host"' approve "{\"pending_id\":\"$(field prepare-create pending_id)\"}"
  sched=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["outcome"]["schedule"])' "$rec/out/approve-create.txt.json")
  call creator-list "reply: r['ok'] and any(p['schedule'] == '$sched' for p in r['created'])" schedules '{}'
  call key-beneficiary "reply: r['ok'] and r['account'] == '$BA'" key "{\"action\":\"import\",\"path\":\"$K/beneficiary.json\"}"
  call positions "reply: r['ok'] and r['positions'][0]['schedule'] == '$sched' and int(r['positions'][0]['claimable_now']['base_units']) > 0" schedules '{}'
  call prepare-claim 'reply: r["ok"] and r["op"] == "claim"' prepare_claim "{\"schedule\":\"$sched\"}"
  call reject-claim 'reply: r["ok"] and r["signed"] is False' reject "{\"pending_id\":\"$(field prepare-claim pending_id)\"}"
  call approve-rejected 'reply: not r["ok"]' approve "{\"pending_id\":\"$(field prepare-claim pending_id)\"}"
  call prepare-claim2 'reply: r["ok"] and r["op"] == "claim"' prepare_claim "{\"schedule\":\"$sched\",\"amount\":\"100000000\"}"
  call approve-claim 'reply: r["ok"] and r["outcome"]["applied"] and r["approved_by"] == "host"' approve "{\"pending_id\":\"$(field prepare-claim2 pending_id)\"}"
  call positions-after "reply: r['ok'] and r['positions'][0]['claimed']['base_units'] == '100000000'" schedules '{}'
  call key-creator2 "reply: r['ok'] and r['account'] == '$CA'" key "{\"action\":\"import\",\"path\":\"$K/creator.json\"}"
  call prepare-cancel 'reply: r["ok"] and r["op"] == "cancel"' prepare_cancel "{\"schedule\":\"$sched\"}"
  call approve-cancel 'reply: r["ok"] and r["outcome"]["applied"] and r["approved_by"] == "host"' approve "{\"pending_id\":\"$(field prepare-cancel pending_id)\"}"
  echo "$sched" > "$rec/schedule.txt"
fi
step daemon-stop ok ctl daemon stop
total=$(wc -l < "$rec/steps.tsv")
passed=$(awk -F'\t' '$5 == 1' "$rec/steps.tsv" | wc -l)
echo "install-test.sh: $passed of $total steps as expected; record in $rec"
[ "$passed" = "$total" ]
