#!/usr/bin/env python3
"""Scan what leaves a machine for private keys before it leaves: every file under DIR is searched for each secret, as
raw bytes, lower- and upper-case hex, base64 and base64url (padded or not). Run on the machine that holds the keys.

    python3 -I basecamp/scripts/keyscan.py DIR [--jwk KEY.jwk]... [--keyfile KEY.json]...

--jwk: an Ed25519 JWK as `lgx keygen` writes it (its "d"). --keyfile: a LEZ key as `escapement keygen` writes it (its
"key", 64 hex digits) or the bare 64 hex digits. Prints one line, "keyscan: N files, M with key material (K secrets)",
then the files that hold one; exits 1 if any does. The secrets themselves are never printed.
"""
import base64
import json
import os
import sys


def forms(raw: bytes) -> list[bytes]:
    b64 = base64.b64encode(raw)
    b64u = base64.urlsafe_b64encode(raw)
    return [raw, raw.hex().encode(), raw.hex().upper().encode(), b64, b64.rstrip(b"="), b64u, b64u.rstrip(b"=")]


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0].startswith("-"):
        print(__doc__, file=sys.stderr)
        return 2
    root, secrets = args[0], []
    it = iter(args[1:])
    for a in it:
        path = next(it, None)
        if path is None:
            print(f"keyscan: {a} needs a file", file=sys.stderr)
            return 2
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
        if a == "--jwk":
            d = json.loads(text)["d"]
            secrets.append(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4)))
        elif a == "--keyfile":
            h = json.loads(text)["key"] if text.startswith("{") else text
            secrets.append(bytes.fromhex(h.removeprefix("0x")))
        else:
            print(f"keyscan: unknown option {a}", file=sys.stderr)
            return 2
    needles = [n for s in secrets for n in forms(s)]
    files, hits = 0, []
    for d, _, names in os.walk(root):
        for name in sorted(names):
            p = os.path.join(d, name)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            files += 1
            with open(p, "rb") as f:
                data = f.read()
            if any(n in data for n in needles):
                hits.append(os.path.relpath(p, root))
    print(f"keyscan: {files} files, {len(hits)} with key material ({len(secrets)} secrets)")
    for h in hits:
        print(f"  {h}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
