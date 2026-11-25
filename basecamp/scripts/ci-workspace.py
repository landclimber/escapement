#!/usr/bin/env python3
"""Make basecamp/ci/ a workspace cargo can test without Nix: the module's calls crate and the staged
escapement-core and escapement-sdk, locked exactly as the module is built.

    python3 -I basecamp/scripts/ci-workspace.py

1. stage.py stages escapement-core and escapement-sdk into rust-lib/staged/ (basecamp/ci/staged links there).
2. rust-lib/Cargo.lock is copied to basecamp/ci/Cargo.lock and cargo drops the entries of the module's scaffold
   (`escapement_core_module`, `logos-rust-sdk`), which this workspace does not have.
3. That lock must be exactly what the three crates need in rust-lib/Cargo.lock (their closure there), every
   package with the same version, source, checksum and dependencies:
   the tests then build what the module is built from, and `cargo test --locked` refuses any other resolution.
"""
import argparse
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASECAMP = HERE.parent
MODULE_LOCK = BASECAMP / "escapement_core_module" / "rust-lib" / "Cargo.lock"
CI = BASECAMP / "ci"


ROOTS = ("escapement-module-calls", "escapement-core", "escapement-sdk")


def packages(lock: Path) -> dict[tuple, tuple]:
    """(name, version, source) -> (checksum, the full keys of its dependencies). A lock names a dependency by name
    alone, or with its version, or with version and source, as needed to be unique in that lock: resolve each one."""
    pk = tomllib.loads(lock.read_text())["package"]
    keys = [(p["name"], p["version"], p.get("source")) for p in pk]

    def full(dep: str) -> tuple:
        name, *rest = dep.split(" ", 2)
        hit = [k for k in keys if k[0] == name and (not rest or k[1] == rest[0])
               and (len(rest) < 2 or k[2] == rest[1][1:-1])]
        if len(hit) != 1:
            raise SystemExit(f"ci-workspace.py: {lock}: cannot resolve dependency {dep!r}")
        return hit[0]
    return {k: (p.get("checksum"), frozenset(map(full, p.get("dependencies", [])))) for k, p in zip(keys, pk)}


def main() -> int:
    argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter).parse_args()
    subprocess.run([sys.executable, "-I", str(HERE / "stage.py")], check=True)
    shutil.copyfile(MODULE_LOCK, CI / "Cargo.lock")
    # Resolve against the copied lock: cargo keeps every locked version and drops what no member uses.
    subprocess.run(["cargo", "metadata", "--format-version", "1", "--manifest-path", str(CI / "Cargo.toml")],
                   check=True, stdout=subprocess.DEVNULL)
    module, ours = packages(MODULE_LOCK), packages(CI / "Cargo.lock")
    # What the module's lock says the three crates need: their closure in rust-lib/Cargo.lock. basecamp/ci's lock
    # must be exactly that, entry for entry: a package added, dropped, re-versioned or re-pointed is an error (so a
    # staged crate that no longer matches rust-lib/Cargo.lock fails here, not later in the module's own build).
    todo = [k for k in module if k[0] in ROOTS and k[2] is None]
    need: set[tuple] = set()
    while todo:
        k = todo.pop()
        if k not in need:
            need.add(k)
            todo.extend(module[k][1])
    bad = []
    for name in ROOTS:
        if not any(k[0] == name for k in need):
            bad.append(f"{name} is not in rust-lib/Cargo.lock")
    show = lambda k: f"{k[0]} {k[1]} ({k[2] or 'path'})"
    for k in sorted(set(ours) - need, key=str):
        bad.append(f"{show(k)} is in basecamp/ci/Cargo.lock but not needed by {', '.join(ROOTS)} in rust-lib/Cargo.lock")
    for k in sorted(need - set(ours), key=str):
        bad.append(f"{show(k)} is needed in rust-lib/Cargo.lock but missing from basecamp/ci/Cargo.lock")
    for k in sorted(need & set(ours), key=str):
        if module[k][0] != ours[k][0]:
            bad.append(f"{show(k)}: checksum differs from rust-lib/Cargo.lock")
        elif module[k][1] != ours[k][1]:
            bad.append(f"{show(k)}: dependencies differ from rust-lib/Cargo.lock")
    for b in bad:
        print(f"ci-workspace.py: {b}", file=sys.stderr)
    if bad:
        return 1
    dropped = sorted({k[0] for k in module} - {k[0] for k in ours})
    print(f"ci-workspace.py: basecamp/ci/Cargo.lock = what {', '.join(ROOTS)} need in rust-lib/Cargo.lock"
          f" ({len(ours)} of {len(module)} packages; less {', '.join(dropped) or 'nothing'}), every one with its"
          " locked version, source, checksum and dependencies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
