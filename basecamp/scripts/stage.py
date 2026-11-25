#!/usr/bin/env python3
"""Stage escapement-core and escapement-sdk into the module's crate directory, where cargo and the module builder find
them (the builder copies only rust-lib/): rust-lib/staged/<crate>/, ignored by git.

Each staged manifest is written with what it inherits from the Escapement workspace resolved (package fields,
workspace dependencies; escapement-core as the sibling copy), without dev-dependencies and lints, which a module build
does not use. Git dependencies (LEZ v0.4.0-rc3, lez-authority, lez-admin-authority) stay git dependencies: the
builder fetches them by the commits in rust-lib/Cargo.lock. What was copied is recorded in staged/STAGED.json (the
commit, each crate's sources' SHA-256), which the module's version() reports.

    python3 -I basecamp/scripts/stage.py [MODULE_DIR]     default: basecamp/escapement_core_module beside this script
    ESCAPEMENT_COMMIT=<sha>                               the commit to record (default: the last commit that changed
                                                          crates/escapement-core or crates/escapement-sdk, so the
                                                          record, and the module built with it, do not change with
                                                          later commits that leave those crates alone)
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CRATES = ["escapement-core", "escapement-sdk"]
KEEP = ("package", "lib", "features", "dependencies", "build-dependencies", "target")


def toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{k} = {toml_value(x)}" for k, x in v.items()) + " }"
    raise SystemExit(f"stage.py: cannot write {v!r}")


def resolve_dep(name, spec, ws, crate_names):
    if isinstance(spec, dict) and spec.get("workspace") is True:
        base = ws["workspace"]["dependencies"][name]
        out = dict(base) if isinstance(base, dict) else {"version": base}
        for k, v in spec.items():
            if k == "workspace":
                continue
            if k == "features":
                out["features"] = list(dict.fromkeys(list(out.get("features", [])) + list(v)))
            else:
                out[k] = v
        spec = out
    if isinstance(spec, dict) and "path" in spec:
        if name not in crate_names:
            raise SystemExit(f"stage.py: path dependency {name} is not staged")
        spec = dict(spec)
        spec["path"] = f"../{name}"
    return spec


def manifest(crate_dir: Path, ws: dict, crate_names) -> str:
    m = tomllib.loads((crate_dir / "Cargo.toml").read_text())
    pkg = dict(m["package"])
    for k, v in list(pkg.items()):
        if isinstance(v, dict) and v.get("workspace") is True:
            pkg[k] = ws["workspace"]["package"][k]
    out = ["# Staged by basecamp/scripts/stage.py from the Escapement workspace: inherited fields resolved,", "# no dev-dependencies or lints.", "[package]"]
    out += [f"{k} = {toml_value(v)}" for k, v in pkg.items()]
    for table in ("lib", "features"):
        if table in m:
            out += ["", f"[{table}]"] + [f"{k} = {toml_value(v)}" for k, v in m[table].items()]
    for table in ("dependencies", "build-dependencies"):
        if table in m:
            out += ["", f"[{table}]"]
            for name, spec in m[table].items():
                out.append(f"{name} = {toml_value(resolve_dep(name, spec, ws, crate_names))}")
    if "target" in m:
        raise SystemExit("stage.py: target-specific tables are not supported")
    return "\n".join(out) + "\n"


def tree_sha(d: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(x for x in d.rglob("*") if x.is_file()):
        h.update(str(p.relative_to(d)).encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def main():
    mod = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE.parent / "escapement_core_module"
    ws = tomllib.loads((REPO / "Cargo.toml").read_text())
    staged = mod / "rust-lib" / "staged"
    if staged.exists():
        shutil.rmtree(staged)
    staged.mkdir(parents=True)
    commit = os.environ.get("ESCAPEMENT_COMMIT") or subprocess.run(
        ["git", "-C", str(REPO), "log", "-1", "--format=%H", "--", *(f"crates/{c}" for c in CRATES)],
        capture_output=True, text=True).stdout.strip() or "unknown"
    record = {"escapement_commit": commit, "commit_is": "the last commit that changed the staged crates",
              "lez": "v0.4.0-rc3 (bafd07be), git dependency", "crates": {}}
    for name in CRATES:
        src = REPO / "crates" / name
        dst = staged / name
        shutil.copytree(src / "src", dst / "src")
        (dst / "Cargo.toml").write_text(manifest(src, ws, CRATES))
        record["crates"][name] = {"from": f"crates/{name}", "src_sha256": tree_sha(src / "src")}
    (staged / "STAGED.json").write_text(json.dumps(record, indent=1) + "\n")
    print(f"stage.py: {', '.join(CRATES)} staged into {staged} (commit {commit[:8]})")


if __name__ == "__main__":
    main()
