#!/usr/bin/env bash
# keyscan.py finds a key in any of its forms and passes a clean tree:   basecamp/scripts/tests/test-keyscan.sh WORK
set -u
here=$(cd "$(dirname "$0")" && pwd)
[ $# = 1 ] || { echo "usage: $0 WORK (a new directory)" >&2; exit 2; }
mkdir -p "$1" && w=$(cd "$1" && pwd)
[ -z "$(ls -A "$w")" ] || { echo "test-keyscan.sh: $w is not empty" >&2; exit 2; }
mkdir -p "$w/keys" "$w/clean" "$w/dirty"
# Placeholders, not keys: the number 7 as 64 hex digits, and a "d" that is base64url of "seed-seed-…" (review R2 nit).
k=$(printf '%064x' 7)
printf '{"key":"%s","account":"x"}' "$k" > "$w/keys/a.json"
printf '{"kty":"OKP","crv":"Ed25519","x":"AAAA","d":"%s"}' "$(printf 'seed-seed-seed-seed-seed-seed-32' | base64 | tr '+/' '-_' | tr -d '=')" > "$w/keys/b.jwk"
echo "nothing here" > "$w/clean/f.txt"
echo "${k^^}" > "$w/dirty/upper.txt"
printf 'seed-seed-seed-seed-seed-seed-32' | base64 > "$w/dirty/b64.txt"
fails=0
python3 -I "$here/../keyscan.py" "$w/clean" --keyfile "$w/keys/a.json" --jwk "$w/keys/b.jwk" > "$w/clean.out"; rc=$?
[ $rc = 0 ] && grep -q "0 with key material (2 secrets)" "$w/clean.out" && echo "PASS clean tree" || { echo "FAIL clean tree: $(cat "$w/clean.out")"; fails=1; }
python3 -I "$here/../keyscan.py" "$w/dirty" --keyfile "$w/keys/a.json" --jwk "$w/keys/b.jwk" > "$w/dirty.out"; rc=$?
[ $rc = 1 ] && grep -q "2 with key material" "$w/dirty.out" && ! grep -q -i "$k" "$w/dirty.out" && echo "PASS dirty tree (both forms found, no secret printed)" || { echo "FAIL dirty tree: $(cat "$w/dirty.out")"; fails=1; }
[ $fails = 0 ]
