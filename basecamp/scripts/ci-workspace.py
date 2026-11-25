#!/usr/bin/env python3
"""Make basecamp/ci/ a workspace cargo can test without Nix: the module's calls crate and the staged
escapement-core and escapement-sdk, locked exactly as the module is built.

    python3 -I basecamp/scripts/ci-workspace.py

1. stage.py stages escapement-core and escapement-sdk into rust-lib/staged/ (basecamp/ci/staged links there).
2. rust-lib/Cargo.lock is copied to basecamp/ci/Cargo.lock and cargo drops the entries of the module's scaffold
   (`escapement_core_module`, `logos-rust-sdk`), which this workspace does not have.
3. Every package left in that lock must be in rust-lib/Cargo.lock with the same version, source and checksum:
   the tests then build what the module is built from, and `cargo test --locked` refuses any other resolution.
"""
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASECAMP = HERE.parent
MODULE_LOCK = BASECAMP / "escapement_core_module" / "rust-lib" / "Cargo.lock"
CI = BASECAMP / "ci"


def packages(lock: Path) -> dict[tuple, tuple]:
    data = tomllib.loads(lock.read_text())
    return {(p["name"], p["version"], p.get("source")): (p.get("checksum"), tuple(p.get("dependencies", [])))
            for p in data["package"]}


def main() -> int:
    subprocess.run([sys.executable, "-I", str(HERE / "stage.py")], check=True)
    shutil.copyfile(MODULE_LOCK, CI / "Cargo.lock")
    # Resolve against the copied lock: cargo keeps every locked version and drops what no member uses.
    subprocess.run(["cargo", "metadata", "--format-version", "1", "--manifest-path", str(CI / "Cargo.toml")],
                   check=True, stdout=subprocess.DEVNULL)
    module, ours = packages(MODULE_LOCK), packages(CI / "Cargo.lock")
    bad = []
    for key, (checksum, _deps) in sorted(ours.items(), key=str):
        if key not in module:
            bad.append(f"{key[0]} {key[1]} ({key[2] or 'path'}) is not in rust-lib/Cargo.lock")
        elif module[key][0] != checksum:
            bad.append(f"{key[0]} {key[1]}: checksum differs from rust-lib/Cargo.lock")
    for name in ("escapement-module-calls", "escapement-core", "escapement-sdk"):
        if not any(k[0] == name for k in ours):
            bad.append(f"{name} is not in the workspace's lock")
    for b in bad:
        print(f"ci-workspace.py: {b}", file=sys.stderr)
    if bad:
        return 1
    dropped = sorted({k[0] for k in module} - {k[0] for k in ours})
    print(f"ci-workspace.py: basecamp/ci/Cargo.lock = rust-lib/Cargo.lock less {', '.join(dropped) or 'nothing'}"
          f" ({len(ours)} of {len(module)} packages, every one with its locked version, source and checksum)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
