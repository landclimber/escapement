#!/usr/bin/env bash
# Sign the packages with Escapement's TEST key (not a release key), on the machine that holds it:
#
#   basecamp/scripts/sign-test.sh KEYDIR IN OUT
#
# KEYDIR: the test key's directory; a new Ed25519 key is made there with `lgx keygen` if it has none (never
# overwritten, mode 0700). IN: build-lgx.sh's OUT/linux-amd64 (unsigned). OUT: a new directory: linux-amd64/*.lgx
# signed under the name "Escapement test build (not a release)", keys/escapement-test.did (the public half as lgx's
# did:jwk), SHA256SUMS, verify.txt (lgx verify with a keyring holding only that DID). The private key is never copied,
# printed or written outside KEYDIR, and OUT must not overlap it.
set -euo pipefail
[ $# = 3 ] || { sed -n '2,11p' "$0" >&2; exit 2; }
kd=$1 in=$(cd "$2" && pwd) out=$3
NAME="Escapement test build (not a release)"
SIGNER=escapement-test
command -v lgx > /dev/null || { echo "sign-test.sh: lgx (logos-package) is not on PATH" >&2; exit 2; }
mkdir -p "$kd" && chmod 700 "$kd" && kd=$(cd "$kd" && pwd)
[ ! -e "$out" ] || { echo "sign-test.sh: $out exists" >&2; exit 2; }
mkdir -p "$out" && out=$(cd "$out" && pwd)
case "$out/" in "$kd/"*) echo "sign-test.sh: OUT is inside KEYDIR" >&2; exit 2 ;; esac
case "$kd/" in "$out/"*) echo "sign-test.sh: KEYDIR is inside OUT" >&2; exit 2 ;; esac
if [ ! -e "$kd/$SIGNER.jwk" ]; then
  (umask 077 && lgx keygen --name "$SIGNER" --output-dir "$kd" > "$kd/keygen.log" 2>&1)
  echo "sign-test.sh: a new test key in $kd"
fi
chmod 600 "$kd"/*.jwk 2> /dev/null || true
# The public half only: did:jwk of {"crv","kty","x"} (keys sorted, no spaces, unpadded base64url), as lgx names signers.
did=$(python3 -I - "$kd/$SIGNER.jwk" <<'PY'
import base64, json, sys
j = json.load(open(sys.argv[1]))
assert j.get("kty") == "OKP" and j.get("crv") == "Ed25519" and isinstance(j.get("x"), str)
pub = {"crv": j["crv"], "kty": j["kty"], "x": j["x"]}
print("did:jwk:" + base64.urlsafe_b64encode(json.dumps(pub, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode())
PY
)
mkdir -p "$out/linux-amd64" "$out/keys"
printf '%s\n' "$did" > "$out/keys/$SIGNER.did"
kr=$(mktemp -d)
trap 'rm -rf "$kr"' EXIT
lgx keyring add "$SIGNER" "$did" --dir "$kr" > /dev/null
: > "$out/verify.txt"
for f in "$in"/*.lgx; do
  b=$(basename "$f")
  cp "$f" "$out/linux-amd64/$b" && chmod u+w "$out/linux-amd64/$b"
  lgx sign "$out/linux-amd64/$b" --key "$kd/$SIGNER.jwk" --name "$NAME" > /dev/null
  v=$(lgx verify "$out/linux-amd64/$b" --keyring-dir "$kr" 2>&1)
  printf '== %s\n%s\n' "$b" "$v" >> "$out/verify.txt"
  grep -q -x "Signature is valid" <<< "$v" || { echo "sign-test.sh: $b: the signature does not verify" >&2; exit 1; }
  # The exact line: "Signer DID is NOT in trusted keyring" also contains "trusted" (review R1 L1).
  grep -q -x "Signer is trusted: $SIGNER" <<< "$v" || { echo "sign-test.sh: $b: lgx does not name $SIGNER as the trusted signer" >&2; exit 1; }
  chmod 644 "$out/linux-amd64/$b"
done
(cd "$out/linux-amd64" && sha256sum ./*.lgx | sed 's| \./| |') > "$out/SHA256SUMS"
cat "$out/SHA256SUMS"
echo "sign-test.sh: signed by $did"
