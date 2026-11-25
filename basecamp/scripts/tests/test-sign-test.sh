#!/usr/bin/env bash
# sign-test.sh against a stand-in `lgx` (no Logos tools needed):   basecamp/scripts/tests/test-sign-test.sh WORK
#   lgx verify names the test signer trusted                      -> signed
#   lgx verify says "Signer DID is NOT in trusted keyring"        -> refused (review R1 L1: it contains "trusted")
#   lgx verify names another signer trusted                       -> refused
# WORK: a new directory (the stand-in, keys and outputs go there; TMPDIR too).
set -u
here=$(cd "$(dirname "$0")" && pwd)
[ $# = 1 ] || { sed -n '2,7p' "$0" >&2; exit 2; }
mkdir -p "$1" && w=$(cd "$1" && pwd)
[ -z "$(ls -A "$w")" ] || { echo "test-sign-test.sh: $w is not empty" >&2; exit 2; }
mkdir -p "$w/bin" "$w/in" "$w/tmp"
cat > "$w/bin/lgx" <<'LGX'
#!/usr/bin/env bash
# A stand-in for logos-package's lgx: keygen, keyring add, sign, verify (its answer set by FAKE_VERIFY).
case "$1" in
  # A placeholder JWK made at run time (random bytes; nothing key-shaped is committed): review R2.
  keygen) shift; while [ $# -gt 0 ]; do case "$1" in --name) n=$2; shift 2 ;; --output-dir) d=$2; shift 2 ;; *) shift ;; esac; done
          r() { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'; }
          printf '{"crv":"Ed25519","d":"%s","kty":"OKP","x":"%s"}' "$(r)" "$(r)" > "$d/$n.jwk" ;;
  keyring) exit 0 ;;
  sign) printf 'signed\n' >> "$2" ;;
  verify)
    echo "Package structure is valid: $2"; echo "Signature is valid"; echo "Signer DID: did:jwk:stand-in"
    case "${FAKE_VERIFY:-trusted}" in
      trusted) echo "Signer name (self-asserted): Escapement test build (not a release)"; echo "Signer is trusted: escapement-test" ;;
      untrusted) echo "Signer DID is NOT in trusted keyring" ;;
      other) echo "Signer is trusted: someone-else" ;;
    esac ;;
  *) echo "lgx stand-in: $*" >&2; exit 2 ;;
esac
LGX
chmod +x "$w/bin/lgx"
printf 'package' > "$w/in/escapement_core_module-0.1.0.lgx"
fails=0
run() { # NAME FAKE_VERIFY EXPECT(0|nonzero)
  PATH="$w/bin:$PATH" TMPDIR="$w/tmp" FAKE_VERIFY=$2 bash "$here/../sign-test.sh" "$w/key-$1" "$w/in" "$w/out-$1" > "$w/$1.log" 2>&1; rc=$?
  if { [ "$3" = 0 ] && [ $rc = 0 ]; } || { [ "$3" = nonzero ] && [ $rc != 0 ]; }; then echo "PASS $1 (exit $rc)"; else echo "FAIL $1 (exit $rc, expected $3): $(tail -n 2 "$w/$1.log" | tr '\n' ' ')"; fails=$((fails + 1)); fi
}
run trusted trusted 0
run not-in-keyring untrusted nonzero
run other-signer other nonzero
[ -z "$(ls -A "$w/tmp")" ] && echo "PASS keyring-cleaned (no directory left in TMPDIR)" || { echo "FAIL keyring-cleaned: $(ls "$w/tmp")"; fails=$((fails + 1)); }
echo "test-sign-test.sh: $fails failure(s)"
[ $fails = 0 ]
