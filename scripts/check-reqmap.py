#!/usr/bin/env python3
"""Check the RFP-017 requirement map and regenerate docs/REQUIREMENTS.md from it.

    scripts/check-reqmap.py                      check the map against the source and CI (no build)
    scripts/check-reqmap.py --write              regenerate docs/REQUIREMENTS.md, then check
    scripts/check-reqmap.py --rfp FILE           also check FILE is the pinned RFP text, that every
                                                 clause is quoted verbatim from it, and that every
                                                 requirement item of the RFP is covered by clauses
    scripts/check-reqmap.py --cargo-list FILE    also check each named test is in the compiled test
                                                 binaries listed by `cargo test ... -- --list`
    scripts/check-reqmap.py --e2e-records FILE   also check each named end-to-end step was recorded
                                                 as passed in e2e/.run/out/e2e.jsonl
    scripts/check-reqmap.py --self-test          show that each kind of error below is caught

Fails (exit 1) when, among other things:
  - a named Rust test does not exist (module path from the crate's source; `#[cfg]` evaluated), or
    no `cargo test` in .github/workflows/ci.yml runs it (package, target, filters and `#[ignore]`
    all taken into account);
  - a named end-to-end step is not a check of e2e/run_e2e.sh, or no CI job runs that suite;
  - a "shown" row names no test, or only tests that CI runs on manual trigger;
  - an "in part", "not yet" or "waits on Logos" row does not say what remains;
  - a row's status differs from the filed proposal's and the row does not say why (`code_says`);
  - a record (file, anchor) does not exist;
  - S3 claims more than the map shows (a hard Functionality, Usability, Reliability or
    Performance clause that names no test);
  - docs/REQUIREMENTS.md differs from what this script generates.

Standard library only (Python 3.11+). Exit 0 and a one-line summary when everything holds.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shlex
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAP = Path("docs/requirements-map.json")
DOC = Path("docs/REQUIREMENTS.md")
WORKFLOW = Path(".github/workflows/ci.yml")
E2E_SUITE = Path("e2e/run_e2e.sh")
STATUSES = ("shown", "in part", "not yet", "waits on Logos")
DEFAULT_BRANCH = "main"


class MapError(Exception):
    pass


ENFORCED = [
    "a clause is not quoted verbatim from the RFP text at the pinned commit (CI downloads it from "
    "that commit and checks its SHA-256), or a requirement item of the RFP (Fee structure 1-4, "
    "Functionality, Usability, Reliability, Performance, Supportability, + Privacy, Soft "
    "Requirements, Open Source) has words that no clause quotes;",
    "a named Rust test does not exist: the script reads each crate's source, follows its modules "
    "and evaluates `#[cfg]`, so the name is the full libtest path in the named crate;",
    "a named Rust test is not run by any `cargo test` in `.github/workflows/ci.yml`: the package, "
    "the target, the filters and `#[ignore]` (run only with `--ignored`) are all taken into "
    "account;",
    "after the tests are built, a named Rust test is missing from the compiled test binaries "
    "(`cargo test ... -- --list`), in the job that runs it;",
    "a named end-to-end check is not one that `e2e/run_e2e.sh` records, or no CI job runs that "
    "suite; after the suite runs in CI, a named check was not recorded as passed in that run;",
    "a `shown` clause names no test, or none of its tests runs on every push to `main` (a test "
    "that only the manual job runs does not count on its own);",
    "an `in part`, `not yet` or `waits on Logos` clause does not say what remains (`not yet` must "
    "name its milestone, `waits on Logos` must name LEZ testnet 0.4);",
    "a status differs from the one the filed proposal gives and the row does not say what in the "
    "code contradicts it;",
    "a record (file, or an anchor in it such as an EVIDENCE row) does not exist;",
    "S3 is `shown` while a hard Functionality, Usability, Reliability or Performance clause names "
    "no test;",
    "this page is not exactly what the script generates from the map (stale).",
]


# ---------------------------------------------------------------------------------------------
# Rust source: test functions with their module paths
# ---------------------------------------------------------------------------------------------

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_RAW = re.compile(r'(b?r)(#*)"')
_CHAR = re.compile(r"(\\(x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'])'", re.S)
_NUM = re.compile(r"[0-9][0-9A-Za-z_.]*")


def rust_tokens(src: str) -> list[str]:
    """Identifiers, punctuation and literals (strings keep their text, quoted); comments dropped."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        prev_ident = i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_")
        if c.isspace():
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j + 1
        elif src.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif not prev_ident and (m := _RAW.match(src, i)):
            close = '"' + m.group(2)
            j = src.find(close, m.end())
            if j < 0:
                raise MapError("unterminated raw string")
            out.append('"' + src[m.end():j] + '"')
            i = j + len(close)
        elif c == '"' or (c == "b" and not prev_ident and src.startswith('b"', i)):
            i += 2 if c == "b" else 1
            start = i
            while i < n and src[i] != '"':
                i += 2 if src[i] == "\\" else 1
            out.append('"' + src[start:i] + '"')
            i += 1
        elif c == "'" or (c == "b" and not prev_ident and src.startswith("b'", i)):
            k = i + (2 if c == "b" else 1)
            m = _CHAR.match(src, k)
            if m:  # a char literal
                out.append("CHAR")
                i = m.end()
            else:  # a lifetime or label
                out.append("'")
                i = k
        elif c.isdigit():
            i = _NUM.match(src, i).end()
            out.append("NUM")
        elif m := _IDENT.match(src, i):
            out.append(m.group(0))
            i = m.end()
        else:
            out.append(c)
            i += 1
    return out


def cfg_value(expr: str):
    """Evaluate a `cfg(...)` predicate as the host `cargo test` build on Linux x86-64 sees it:
    True, False, or None when it depends on something this script does not know (features)."""

    def ev(t: str):
        if t.startswith("not(") and t.endswith(")"):
            v = ev(t[4:-1])
            return None if v is None else not v
        for op in ("all(", "any("):
            if t.startswith(op) and t.endswith(")"):
                parts, depth, cur = [], 0, ""
                for ch in t[4:-1]:
                    if ch == "," and depth == 0:
                        parts.append(cur)
                        cur = ""
                        continue
                    depth += ch == "("
                    depth -= ch == ")"
                    cur += ch
                if cur:
                    parts.append(cur)
                vals = [ev(p) for p in parts]
                if op == "all(":
                    return False if False in vals else (None if None in vals else True)
                return True if True in vals else (None if None in vals else False)
        m = re.fullmatch(r'(\w+)="(.*)"', t)
        if m:
            key, val = m.groups()
            host = {"target_os": "linux", "target_family": "unix", "target_arch": "x86_64"}
            return (val == host[key]) if key in host else None
        return {"test": True, "unix": True, "debug_assertions": True,
                "kani": False, "miri": False, "windows": False}.get(t)

    return ev(re.sub(r"\s+", "", expr))


@dataclass
class RustTest:
    package: str
    target: str          # "lib", "bin:NAME", "test:NAME"
    path: str            # libtest name, e.g. math::tests::fee_boundary_classes
    file: str            # repo-relative source file
    ignored: bool
    cfg_unknown: bool    # behind a cfg this script cannot evaluate


@dataclass
class Target:
    package: str
    kind: str            # lib | bin | test
    name: str
    root: str            # repo-relative root source file
    list_key: tuple      # ("unittests src/lib.rs" | "tests/idl.rs", binary stem)

    @property
    def id(self) -> str:
        return "lib" if self.kind == "lib" else f"{self.kind}:{self.name}"


@dataclass
class Package:
    name: str
    dir: str             # repo-relative
    workspace_root: str  # repo-relative dir of the workspace this package belongs to
    targets: list[Target] = field(default_factory=list)


def _attr_text(toks: list[str]) -> str:
    return "".join(toks)


def scan_target(target: Target) -> list[RustTest]:
    tests: list[RustTest] = []
    seen: set[str] = set()

    def walk(file: Path, modpath: list[str], mod_dir: Path, cond_unknown: bool):
        rel = str(file.relative_to(ROOT))
        if rel in seen:
            return
        seen.add(rel)
        toks = rust_tokens(file.read_text())
        stack: list[tuple[int, list[str], Path, bool]] = []  # (depth at open, path, dir, unknown)
        cur_path, cur_dir, cur_unknown, depth = list(modpath), mod_dir, cond_unknown, 0
        pending: list[str] = []
        i = 0
        while i < len(toks):
            t = toks[i]
            if t == "#" and i + 1 < len(toks) and toks[i + 1] in ("[", "!"):
                inner = toks[i + 1] == "!"
                j = i + (2 if inner else 1)
                if toks[j] != "[":
                    i += 1
                    continue
                d, k = 0, j
                while k < len(toks):
                    d += toks[k] == "["
                    d -= toks[k] == "]"
                    if d == 0:
                        break
                    k += 1
                if not inner:
                    pending.append(_attr_text(toks[j + 1:k]))
                i = k + 1
                continue
            if pending and (t in ("pub", "async", "unsafe", "const", "extern", "crate", "(", ")") or t.startswith('"')):
                # `pub`, `pub(crate)`, `async`, `extern "C"` between attributes and the item
                i += 1
                continue
            if t == "mod" and i + 2 < len(toks) and _IDENT.fullmatch(toks[i + 1]):
                name, nxt = toks[i + 1], toks[i + 2]
                cfgs = [a[4:-1] for a in pending if a.startswith("cfg(")]
                vals = [cfg_value(c) for c in cfgs]
                path_attr = next((a[6:-1] for a in pending if a.startswith('path="')), None)
                pending = []
                if False in vals:
                    if nxt == "{":  # skip the whole inline module
                        d, k = 0, i + 2
                        while k < len(toks):
                            d += toks[k] == "{"
                            d -= toks[k] == "}"
                            if d == 0:
                                break
                            k += 1
                        i = k + 1
                    else:
                        i += 3
                    continue
                unknown = cur_unknown or (None in vals)
                if nxt == ";":
                    cands = [file.parent / path_attr] if path_attr else [cur_dir / f"{name}.rs", cur_dir / name / "mod.rs"]
                    for cand in cands:
                        if cand.exists():
                            sub_dir = cand.parent if cand.name == "mod.rs" else cand.parent / name
                            walk(cand, cur_path + [name], sub_dir, unknown)
                            break
                    else:
                        raise MapError(f"{rel}: module `{name}` declared but no file found")
                    i += 3
                    continue
                if nxt == "{":
                    stack.append((depth, cur_path, cur_dir, cur_unknown))
                    cur_path, cur_dir, cur_unknown = cur_path + [name], cur_dir / name, unknown
                    depth += 1
                    i += 3
                    continue
            if t == "fn" and i + 1 < len(toks) and _IDENT.fullmatch(toks[i + 1]):
                is_test = any(a in ("test", "tokio::test") for a in pending)
                if is_test:
                    cfgs = [a[4:-1] for a in pending if a.startswith("cfg(")]
                    vals = [cfg_value(c) for c in cfgs]
                    if False not in vals:
                        tests.append(RustTest(
                            package=target.package, target=target.id,
                            path="::".join(cur_path + [toks[i + 1]]), file=rel,
                            ignored=any(a == "ignore" or a.startswith("ignore=") for a in pending),
                            cfg_unknown=cur_unknown or (None in vals)))
                pending = []
                i += 2
                continue
            pending = []
            if t == "{":
                depth += 1
            elif t == "}":
                depth -= 1
                if stack and depth == stack[-1][0]:
                    _, cur_path, cur_dir, cur_unknown = stack.pop()
            i += 1

    root = ROOT / target.root
    walk(root, [], root.parent, False)
    return tests


def discover_packages() -> list[Package]:
    """Every package of the root workspace, plus standalone packages under crates/."""
    root_manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    ws = root_manifest.get("workspace", {})
    dirs = list(ws.get("members", []))
    excluded = set(ws.get("exclude", []))
    pkgs: list[Package] = []
    for d in dirs:
        pkgs.append(_package(d, "."))
    for manifest in sorted((ROOT / "crates").glob("*/Cargo.toml")):
        d = str(manifest.parent.relative_to(ROOT))
        if d in dirs or d in excluded:
            continue
        data = tomllib.loads(manifest.read_text())
        if "package" in data and "workspace" in data:
            pkgs.append(_package(d, d))
    return pkgs


def _package(d: str, ws_root: str) -> Package:
    data = tomllib.loads((ROOT / d / "Cargo.toml").read_text())
    name = data["package"]["name"]
    pkg = Package(name=name, dir=d, workspace_root=ws_root)
    lib = data.get("lib", {})
    lib_path = lib.get("path", "src/lib.rs")
    if (ROOT / d / lib_path).exists():
        stem = lib.get("name", name).replace("-", "_")
        pkg.targets.append(Target(name, "lib", stem, f"{d}/{lib_path}", (f"unittests {lib_path}", stem)))
    bins = {b["name"]: b.get("path", f"src/bin/{b['name']}.rs") for b in data.get("bin", [])}
    if not bins:
        if (ROOT / d / "src/main.rs").exists():
            bins[name] = "src/main.rs"
    for f in sorted((ROOT / d / "src/bin").glob("*.rs")) if (ROOT / d / "src/bin").is_dir() else []:
        bins.setdefault(f.stem, f"src/bin/{f.name}")
    for bname, bpath in bins.items():
        stem = bname.replace("-", "_")
        pkg.targets.append(Target(name, "bin", bname, f"{d}/{bpath}", (f"unittests {bpath}", stem)))
    tests = {t["name"]: t.get("path", f"tests/{t['name']}.rs") for t in data.get("test", [])}
    for f in sorted((ROOT / d / "tests").glob("*.rs")) if (ROOT / d / "tests").is_dir() else []:
        tests.setdefault(f.stem, f"tests/{f.name}")
    for tname, tpath in tests.items():
        pkg.targets.append(Target(name, "test", tname, f"{d}/{tpath}", (tpath, tname.replace("-", "_"))))
    return pkg


# ---------------------------------------------------------------------------------------------
# End-to-end suite: the names of its checks
# ---------------------------------------------------------------------------------------------

def e2e_checks(text: str) -> list[str]:
    """Every record name e2e/run_e2e.sh can write: `step|expect|expect_fail NAME`, and the names
    its helper functions derive from their first argument (`refusal NAME` -> NAME-sent-on-chain,
    NAME-reverted-state-unchanged)."""
    recorders = ("step", "expect", "expect_fail")
    functions: dict[str, str] = {}
    main_lines: list[str] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{(.*)$", lines[i])
        if not m:
            main_lines.append(lines[i])
            i += 1
            continue
        rest = m.group(2).split(" #", 1)[0].rstrip()
        if rest.endswith("}"):           # one-line function
            functions[m.group(1)] = rest[:-1]
            i += 1
            continue
        body = [rest]
        i += 1
        while i < len(lines) and lines[i] != "}":
            body.append(lines[i])
            i += 1
        if i == len(lines):
            raise MapError(f"{E2E_SUITE}: function {m.group(1)} has no closing brace")
        functions[m.group(1)] = "\n".join(body)
        i += 1
    helpers: dict[str, list[str]] = {}
    for fname, body in functions.items():
        # A helper's NAME parameter is `local name="$1"`; the names it records are "$name-SUFFIX".
        if fname not in recorders and 'name="$1"' in body:
            suffixes = re.findall(r'\b(?:%s) "\$name-([A-Za-z0-9-]+)"' % "|".join(recorders), body)
            if suffixes:
                helpers[fname] = suffixes
    names: list[str] = []
    for line in main_lines:
        code = "" if line.lstrip().startswith("#") else re.split(r"\s#", line, maxsplit=1)[0]
        for m in re.finditer(r"(?:^|[\s(\"])(%s) ([A-Za-z0-9][A-Za-z0-9-]*)\b" % "|".join(recorders + tuple(helpers)), code):
            fn, name = m.group(1), m.group(2)
            if fn in helpers:
                names += [f"{name}-{s}" for s in helpers[fn]]
            else:
                names.append(name)
    return names


# ---------------------------------------------------------------------------------------------
# The CI workflow: a small YAML reader for GitHub workflow files
# ---------------------------------------------------------------------------------------------

def _scalar(v: str):
    v = v.strip()
    if not v:
        return None
    if v[0] in "&*!" or v.startswith("---"):
        raise MapError(f"workflow YAML feature not supported by this reader: {v!r}")
    if v[0] in "'\"":
        q = v[0]
        end = v.find(q, 1)
        while q == "'" and end + 1 < len(v) and v[end + 1] == "'":
            end = v.find(q, end + 2)
        return v[1:end].replace("''", "'") if q == "'" else json.loads(v[: end + 1])
    v = re.split(r"\s+#", v, maxsplit=1)[0].rstrip()
    if v.startswith("[") and v.endswith("]"):
        return [_scalar(x) for x in v[1:-1].split(",") if x.strip()]
    if v == "{}":
        return {}
    return v


def parse_yaml(text: str):
    lines = text.split("\n")

    def indent(s: str) -> int:
        return len(s) - len(s.lstrip(" "))

    def skip(i: int) -> int:
        while i < len(lines) and (not lines[i].strip() or lines[i].lstrip().startswith("#")):
            i += 1
        return i

    def block_scalar(i: int, parent: int, style: str):
        body, j = [], i
        while j < len(lines) and (not lines[j].strip() or indent(lines[j]) > parent):
            body.append(lines[j])
            j += 1
        while body and not body[-1].strip():
            body.pop()
        ind = min((indent(b) for b in body if b.strip()), default=0)
        text_ = "\n".join(b[ind:] for b in body)
        if style.startswith(">"):
            text_ = re.sub(r"(?<!\n)\n(?!\n)", " ", text_)
        return (text_ + ("\n" if not style.endswith("-") else "")), j

    def node(i: int, ind: int):
        i = skip(i)
        if i >= len(lines) or indent(lines[i]) < ind:
            return None, i
        ind = indent(lines[i])
        if lines[i].lstrip().startswith("- ") or lines[i].strip() == "-":
            return seq(i, ind)
        return mapping(i, ind)

    def value_after(rest: str, i: int, ind: int):
        rest = rest.strip()
        if rest.startswith("|") or rest.startswith(">"):
            return block_scalar(i + 1, ind, rest.split("#")[0].strip())
        if rest and not rest.startswith("#"):
            return _scalar(rest), i + 1
        j = skip(i + 1)
        if j < len(lines) and (indent(lines[j]) > ind or (indent(lines[j]) == ind and lines[j].lstrip().startswith("- "))):
            return node(j, indent(lines[j]))
        return None, i + 1

    def mapping(i: int, ind: int):
        out = {}
        while True:
            i = skip(i)
            if i >= len(lines) or indent(lines[i]) != ind or lines[i].lstrip().startswith("- "):
                return out, i
            s = lines[i].strip()
            m = re.match(r"""("[^"]*"|'[^']*'|[^:#'"][^:]*?)\s*:(\s|$)(.*)""", s)
            if not m:
                raise MapError(f"workflow line {i + 1}: cannot read {s!r}")
            key = m.group(1).strip("'\"")
            out[key], i = value_after(m.group(3), i, ind)

    def seq(i: int, ind: int):
        out = []
        while True:
            i = skip(i)
            if i >= len(lines) or indent(lines[i]) != ind or not lines[i].lstrip().startswith("-"):
                return out, i
            rest = lines[i].strip()[1:].lstrip()
            if re.match(r"""("[^"]*"|'[^']*'|[^:#'"\s][^:]*?)\s*:(\s|$)""", rest):
                lines[i] = " " * (ind + 2) + rest
                item, i = mapping(i, ind + 2)
            elif not rest:
                item, i = node(i + 1, ind + 1)
            else:
                item, i = _scalar(rest), i + 1
            out.append(item)

    value, _ = node(0, 0)
    return value


@dataclass
class CargoRun:
    job: str
    step: str
    cwd: str             # repo-relative
    argv: list[str]
    triggers: str        # "every push and pull request" | "manual"
    on_push: bool


@dataclass
class SuiteRun:
    job: str
    step: str
    triggers: str
    on_push: bool


def ci_runs(workflow_text: str) -> tuple[list[CargoRun], list[SuiteRun], list[SuiteRun]]:
    """`cargo test` commands, runs of the end-to-end suite, and runs of this script, in CI."""
    wf = parse_yaml(workflow_text)
    on = wf.get("on") or wf.get(True) or {}
    if isinstance(on, str):
        on = {on: None}
    if isinstance(on, list):
        on = {k: None for k in on}
    push = on.get("push", "absent") if isinstance(on, dict) else "absent"
    push_main = push != "absent" and (
        push is None or not push.get("branches") or DEFAULT_BRANCH in push.get("branches"))
    cargo_runs, suite_runs, reqmap_runs = [], [], []
    for job_id, job in (wf.get("jobs") or {}).items():
        cond = (job.get("if") or "").strip()
        if not cond:
            on_push, triggers = push_main, "every push and pull request" if push_main else "pull request"
        elif re.fullmatch(r"""github\.event_name\s*==\s*['"]workflow_dispatch['"]""", cond):
            on_push, triggers = False, "manual (workflow_dispatch)"
        else:
            on_push, triggers = False, f"only if `{cond}`"
        default_dir = ((job.get("defaults") or {}).get("run") or {}).get("working-directory", ".")
        for step in job.get("steps") or []:
            run = step.get("run")
            if not run:
                continue
            step_on_push, step_triggers = on_push, triggers
            scond = str(step.get("if") or "").strip()
            if scond and scond not in ("always()", "success()"):
                step_on_push, step_triggers = False, f"{triggers}, step only if `{scond}`"
            cwd = os.path.normpath(step.get("working-directory", default_dir))
            for argv, at in _commands(run, cwd):
                if argv[:2] == ["cargo", "test"]:
                    cargo_runs.append(CargoRun(job_id, step.get("name", ""), at, argv[2:], step_triggers, step_on_push))
                elif (argv[0] in ("bash", "sh") and len(argv) > 1 and os.path.normpath(os.path.join(at, argv[1])) == str(E2E_SUITE)) \
                        or os.path.normpath(os.path.join(at, argv[0])) == str(E2E_SUITE):
                    suite_runs.append(SuiteRun(job_id, step.get("name", ""), step_triggers, step_on_push))
                elif any(os.path.normpath(os.path.join(at, x)) == "scripts/check-reqmap.py" for x in argv[:2]):
                    reqmap_runs.append(SuiteRun(job_id, step.get("name", ""), step_triggers, step_on_push))
    return cargo_runs, suite_runs, reqmap_runs


def _strip_shell_comments(script: str) -> str:
    """Drop `# ...` comments (a `#` that starts a word outside quotes), keeping the newlines, so
    that an apostrophe in a comment cannot open a quote."""
    out, quote, i, n = [], None, 0, len(script)
    while i < n:
        c = script[i]
        if quote:
            out.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                out.append(script[i + 1])
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
            out.append(c)
        elif c == "\\" and i + 1 < n:
            out.append(script[i:i + 2])
            i += 2
            continue
        elif c == "#" and (i == 0 or script[i - 1] in " \t\n;|&("):
            j = script.find("\n", i)
            i = n if j < 0 else j
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _commands(script: str, cwd: str):
    """(argv, cwd) of each simple command of a `run:` script, following `cd`."""
    script = _strip_shell_comments(script.replace("\\\n", " "))
    lex = shlex.shlex(script, posix=True, punctuation_chars="();<>|&\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        toks = list(lex)
    except ValueError as e:
        raise MapError(f"workflow run script: {e}") from e
    cmd: list[str] = []
    subshells: list[str] = []
    for t in toks + [";"]:
        if t and set(t) <= set("();<>|&\n"):   # shlex groups adjacent punctuation: "\n(", ");"
            while cmd and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", cmd[0]):
                cmd = cmd[1:]
            if cmd and cmd[0] == "cd" and len(cmd) > 1:
                cwd = os.path.normpath(os.path.join(cwd, cmd[1]))
            elif cmd:
                yield cmd, cwd
            cmd = []
            for ch in t:
                if ch == "(":
                    subshells.append(cwd)
                elif ch == ")" and subshells:
                    cwd = subshells.pop()   # a `cd` inside `( ... )` ends with it
        else:
            cmd.append(t)


_CARGO_VALUE_OPTS = {"-p", "--package", "--test", "--bin", "--example", "--bench", "--features", "-F",
                     "--target", "--target-dir", "--manifest-path", "--profile", "--exclude", "-j",
                     "--jobs", "--color", "--message-format", "--config", "-Z"}
_LIBTEST_VALUE_OPTS = {"--test-threads", "--skip", "--format", "--color", "--logfile", "-Z", "--report-time"}


def cargo_selects(run: CargoRun, pkgs: list[Package], test: RustTest) -> bool:
    """Does this `cargo test` invocation run this test?"""
    args, rest = run.argv, []
    if "--" in args:
        k = args.index("--")
        args, rest = args[:k], args[k + 1:]
    opts: dict[str, list[str]] = {}
    flags: set[str] = set()
    filt: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in _CARGO_VALUE_OPTS:
            opts.setdefault(a, []).append(args[i + 1])
            i += 2
        elif "=" in a and a.split("=", 1)[0] in _CARGO_VALUE_OPTS:
            k_, v = a.split("=", 1)
            opts.setdefault(k_, []).append(v)
            i += 1
        elif a.startswith("-"):
            flags.add(a)
            i += 1
        else:
            filt.append(a)
            i += 1
    if "--no-run" in flags:
        return False
    lflags: set[str] = set()
    skips: list[str] = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in _LIBTEST_VALUE_OPTS:
            if a == "--skip":
                skips.append(rest[i + 1])
            i += 2
        elif a.startswith("-"):
            lflags.add(a)
            i += 1
        else:
            filt.append(a)
            i += 1
    if "--list" in lflags:
        return False
    # Which packages: the manifest cargo finds from the working directory.
    cwd = run.cwd
    if "--manifest-path" in opts:
        cwd = os.path.normpath(os.path.join(cwd, os.path.dirname(opts["--manifest-path"][0])))
    probe = cwd
    while not (ROOT / probe / "Cargo.toml").exists():
        if probe in (".", ""):
            return False
        probe = os.path.dirname(probe) or "."
    by_dir = {p.dir: p for p in pkgs}
    named = set(opts.get("-p", []) + opts.get("--package", []))
    if probe in by_dir and by_dir[probe].workspace_root == probe:
        # A package that is its own workspace (the CLI): only it.
        selected = {by_dir[probe].name} if not named or by_dir[probe].name in named else set()
    elif probe == "." or (probe in by_dir and by_dir[probe].workspace_root == "."):
        members = {p.name for p in pkgs if p.workspace_root == "."}
        if named:
            selected = named & members
        elif {"--workspace", "--all"} & flags or probe == ".":
            # The root manifest is virtual: with no -p, cargo tests every member.
            selected = members - set(opts.get("--exclude", []))
        else:
            selected = {by_dir[probe].name}
    else:
        return False
    if test.package not in selected:
        return False
    # Which targets.
    explicit = {"--lib", "--bins", "--tests", "--doc", "--all-targets", "--examples", "--benches"} & flags \
        or "--test" in opts or "--bin" in opts
    if explicit:
        ok = ("--all-targets" in flags
              or (test.target == "lib" and "--lib" in flags)
              or (test.target.startswith("bin:") and ("--bins" in flags or test.target[4:] in opts.get("--bin", [])))
              or (test.target.startswith("test:") and ("--tests" in flags or test.target[5:] in opts.get("--test", []))))
        if not ok:
            return False
    # Filters and #[ignore].
    exact = "--exact" in lflags
    if filt and not any((f == test.path) if exact else (f in test.path) for f in filt):
        return False
    if any(s in test.path for s in skips):
        return False
    if test.ignored:
        return bool({"--ignored", "--include-ignored"} & lflags)
    return "--ignored" not in lflags


# ---------------------------------------------------------------------------------------------
# The map
# ---------------------------------------------------------------------------------------------

def normalize_md(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = text.replace("**", "").replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def rfp_items(text: str) -> list[tuple[str, str]]:
    """(where, normalized text) of every requirement item: the numbered items of Fee structure
    and of each Hard Requirements subsection, the Soft Requirements bullets, and the Open Source
    Requirement paragraph."""
    lines = text.split("\n")
    items: list[tuple[str, str]] = []
    section, sub, cur, where = None, None, None, ""

    def flush():
        nonlocal cur
        if cur is not None:
            items.append((where, normalize_md(" ".join(cur))))
        cur = None

    for ln in lines:
        h = re.match(r"^(#{2,4}) (.*)", ln)
        if h:
            flush()
            level, title = len(h.group(1)), re.sub(r"^[^A-Za-z+]+", "", h.group(2)).strip()
            if level <= 3:
                section, sub = title, None
            else:
                sub = title
            continue
        in_scope = (section in ("Fee structure", "Hard Requirements", "Soft Requirements")
                    or section == "Open Source Requirement")
        if not in_scope:
            flush()
            continue
        if section == "Hard Requirements" and sub is None:
            continue
        top = re.match(r"^(\d+)\. (.*)", ln) or (re.match(r"^- (.*)", ln) if section == "Soft Requirements" else None)
        if top:
            flush()
            n = top.group(1) if top.lastindex == 2 else str(len([w for w, _ in items if w.startswith(section)]) + 1)
            where = f"{section}{' / ' + sub if sub else ''} {n}"
            cur = [top.group(top.lastindex)]
        elif cur is not None and ln.startswith(" ") and ln.strip():
            cur.append(re.sub(r"^\s*- ", "", ln))
        elif section == "Open Source Requirement" and ln.strip():
            if cur is None:
                where, cur = "Open Source Requirement", []
            cur.append(ln)
        elif not ln.strip():
            flush()
        else:
            flush()
    flush()
    return items


@dataclass
class Context:
    rmap: dict
    packages: list[Package]
    tests: list[RustTest]
    cargo_runs: list[CargoRun]
    suite_runs: list[SuiteRun]
    reqmap_runs: list[SuiteRun]
    e2e_names: list[str]


def load_context(rmap: dict | None = None, workflow_text: str | None = None) -> Context:
    if rmap is None:
        rmap = json.loads((ROOT / MAP).read_text())
    pkgs = discover_packages()
    tests = [t for p in pkgs for tg in p.targets for t in scan_target(tg)]
    runs = ci_runs(workflow_text if workflow_text is not None else (ROOT / WORKFLOW).read_text())
    return Context(rmap, pkgs, tests, *runs, e2e_checks((ROOT / E2E_SUITE).read_text()))


def test_key(t: dict) -> str:
    if "rust" in t:
        return f"rust {t['crate']} {t['rust']}"
    if "e2e" in t:
        return f"e2e {t['e2e']}"
    if "check" in t:
        return f"check {t['check']}"
    raise MapError(f"unknown test reference {t}")


@dataclass
class Resolved:
    ref: dict
    ok: bool
    where: str = ""                         # file or suite
    runs: list[str] = field(default_factory=list)   # "job (triggers)"
    on_push: bool = False
    rust: RustTest | None = None
    error: str = ""


def resolve_test(ctx: Context, ref: dict) -> Resolved:
    if "rust" in ref:
        cands = [t for t in ctx.tests if t.package == ref.get("crate") and t.path == ref["rust"]
                 and (ref.get("target") in (None, t.target))]
        if not cands:
            return Resolved(ref, False, error=f"no test `{ref['rust']}` in crate `{ref.get('crate')}`")
        if len(cands) > 1:
            return Resolved(ref, False, error=f"`{ref['rust']}` is in several targets of `{ref['crate']}`: name one with \"target\"")
        t = cands[0]
        if t.cfg_unknown:
            return Resolved(ref, False, where=t.file, error=f"`{t.path}` sits behind a `cfg` this check cannot evaluate")
        runs = [r for r in ctx.cargo_runs if cargo_selects(r, ctx.packages, t)]
        if not runs:
            why = " (it is #[ignore] and no CI command passes --ignored with a filter that selects it)" if t.ignored else ""
            return Resolved(ref, False, where=t.file, rust=t, error=f"no `cargo test` in {WORKFLOW} runs `{t.path}`{why}")
        return Resolved(ref, True, where=t.file, rust=t,
                        runs=sorted({f"{r.job} ({r.triggers})" for r in runs}), on_push=any(r.on_push for r in runs))
    if "e2e" in ref:
        if ref["e2e"] not in ctx.e2e_names:
            return Resolved(ref, False, where=str(E2E_SUITE), error=f"`{ref['e2e']}` is not a check of {E2E_SUITE}")
        if not ctx.suite_runs:
            return Resolved(ref, False, where=str(E2E_SUITE), error=f"no CI job runs {E2E_SUITE}")
        return Resolved(ref, True, where=str(E2E_SUITE),
                        runs=sorted({f"{r.job} ({r.triggers})" for r in ctx.suite_runs}),
                        on_push=any(r.on_push for r in ctx.suite_runs))
    if "check" in ref:
        if ref["check"] not in CHECKS:
            return Resolved(ref, False, error=f"unknown check `{ref['check']}`")
        if not ctx.reqmap_runs:
            return Resolved(ref, False, error="no CI job runs scripts/check-reqmap.py")
        return Resolved(ref, True, where="scripts/check-reqmap.py",
                        runs=sorted({f"{r.job} ({r.triggers})" for r in ctx.reqmap_runs}),
                        on_push=any(r.on_push for r in ctx.reqmap_runs))
    return Resolved(ref, False, error=f"unknown test reference {ref}")


def check_license(ctx: Context) -> list[str]:
    errs = []
    for f in ("LICENSE-MIT", "LICENSE-APACHE"):
        if not (ROOT / f).is_file():
            errs.append(f"license: {f} missing")
    for p in ctx.packages:
        data = tomllib.loads((ROOT / p.dir / "Cargo.toml").read_text())
        lic = data["package"].get("license")
        if isinstance(lic, dict) and lic.get("workspace"):
            lic = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["license"]
        if lic != "MIT OR Apache-2.0":
            errs.append(f"license: {p.dir}/Cargo.toml says {lic!r}, not 'MIT OR Apache-2.0'")
    return errs


def check_s3(ctx: Context) -> list[str]:
    """S3 may only be `shown` when every hard F/U/R/P clause names at least one test."""
    missing = s3_missing(ctx.rmap)
    s3 = next((c for c in ctx.rmap["clauses"] if c["id"] == "S3"), None)
    if s3 and s3["status"] == "shown" and missing:
        return [f"S3 is `shown` but these hard clauses name no test: {', '.join(missing)}"]
    if s3 and s3["status"] != "shown" and not missing and s3.get("status") != "waits on Logos":
        return ["S3: every hard F/U/R/P clause names a test; S3 can be `shown` (update the row)"]
    return []


def s3_missing(rmap: dict) -> list[str]:
    groups = {g["id"]: g for g in rmap["groups"]}
    return [c["id"] for c in rmap["clauses"]
            if groups[c["group"]].get("s3") and not c.get("tests")]


CHECKS = {
    "reqmap:license": ("LICENSE-MIT and LICENSE-APACHE exist and every crate's manifest says "
                       "`license = \"MIT OR Apache-2.0\"`", check_license),
    "reqmap:s3-coverage": ("every hard Functionality, Usability, Reliability and Performance clause "
                           "names a test, or S3 is not `shown`", check_s3),
}


def validate(ctx: Context, rfp_text: str | None = None, cargo_list: list[str] | None = None,
             e2e_records: list[str] | None = None) -> tuple[list[str], dict[str, Resolved]]:
    rmap, errs = ctx.rmap, []
    resolved: dict[str, Resolved] = {}
    for key in ("schema", "rfp", "proposal", "statuses", "groups", "clauses"):
        if key not in rmap:
            errs.append(f"map: missing `{key}`")
    if errs:
        return errs, resolved
    if set(rmap["statuses"]) != set(STATUSES):
        errs.append(f"map: statuses must be exactly {STATUSES}")
    group_ids = {g["id"] for g in rmap["groups"]}
    seen: set[str] = set()
    for c in rmap["clauses"]:
        cid = c.get("id", "?")
        if cid in seen:
            errs.append(f"{cid}: duplicate id")
        seen.add(cid)
        for k in ("group", "text", "short", "status", "rfp_where"):
            if not c.get(k):
                errs.append(f"{cid}: missing `{k}`")
        if "proposal" not in c:
            errs.append(f"{cid}: missing `proposal` (null when the proposal's table has no row for it)")
        if c.get("group") not in group_ids:
            errs.append(f"{cid}: unknown group {c.get('group')!r}")
        st = c.get("status")
        if st not in STATUSES:
            errs.append(f"{cid}: status {st!r} is not one of {STATUSES}")
            continue
        prop = c.get("proposal")
        if prop is not None:
            if prop.get("status") not in STATUSES:
                errs.append(f"{cid}: proposal status {prop.get('status')!r} is not one of {STATUSES}")
            elif prop["status"] != st and not c.get("code_says"):
                errs.append(f"{cid}: status `{st}` differs from the proposal's `{prop['status']}` and `code_says` does not say why")
            elif prop["status"] == st and c.get("code_says"):
                errs.append(f"{cid}: `code_says` is set but the status equals the proposal's")
        tests = c.get("tests") or []
        keys = [test_key(t) for t in tests]
        if len(keys) != len(set(keys)):
            errs.append(f"{cid}: a test is named twice")
        for t in tests:
            r = resolved.setdefault(test_key(t), resolve_test(ctx, t))
            if not r.ok:
                errs.append(f"{cid}: {r.error}")
        for rec in c.get("records") or []:
            errs += [f"{cid}: {e}" for e in check_record(rec)]
        if st == "shown":
            if not tests:
                errs.append(f"{cid}: `shown` but names no test")
            elif not any(resolved[test_key(t)].on_push for t in tests if resolved[test_key(t)].ok):
                errs.append(f"{cid}: `shown` but none of its tests runs on every push to {DEFAULT_BRANCH}")
        else:
            if not (c.get("remaining") or "").strip():
                errs.append(f"{cid}: `{st}` but `remaining` does not say what is missing")
        if st == "not yet" and not re.search(r"\bM[1-9]\b", c.get("remaining", "")):
            errs.append(f"{cid}: `not yet` but `remaining` names no milestone (M1..M9)")
        if st == "waits on Logos" and "testnet 0.4" not in c.get("remaining", ""):
            errs.append(f"{cid}: `waits on Logos` but `remaining` does not name LEZ testnet 0.4")
    for name, (_, fn) in CHECKS.items():
        if any(t.get("check") == name for c in rmap["clauses"] for t in c.get("tests") or []):
            errs += fn(ctx)
    if rfp_text is not None:
        errs += check_rfp(rmap, rfp_text)
    if cargo_list is not None:
        errs += check_cargo_list(ctx, resolved, cargo_list)
    if e2e_records is not None:
        errs += check_e2e_records(resolved, e2e_records)
    return errs, resolved


def check_record(rec: dict) -> list[str]:
    if "url" in rec:
        if not re.match(r"https://github\.com/landclimber/escapement/", rec["url"]):
            return [f"record URL {rec['url']} is not in this repository"]
        return []
    path = rec.get("file")
    if not path or not (ROOT / path).exists():
        return [f"record file {path!r} does not exist"]
    anchor = rec.get("anchor")
    if anchor and anchor not in (ROOT / path).read_text():
        return [f"record {path}: `{anchor}` not found in it"]
    return []


def check_rfp(rmap: dict, text: str) -> list[str]:
    errs = []
    digest = hashlib.sha256(text.encode()).hexdigest()
    if digest != rmap["rfp"]["sha256"]:
        errs.append(f"RFP text: SHA-256 {digest} is not the pinned {rmap['rfp']['sha256']} "
                    f"({rmap['rfp']['repo']} {rmap['rfp']['path']} at {rmap['rfp']['commit']})")
    body = normalize_md(text)
    clause_texts = []
    for c in rmap["clauses"]:
        t = normalize_md(c["text"])
        clause_texts.append(t)
        if t not in body:
            errs.append(f"{c['id']}: text is not a verbatim quote of the RFP")
    for where, item in rfp_items(text):
        rest = item
        for t in sorted(clause_texts, key=len, reverse=True):
            rest = rest.replace(t, " ")
        if re.sub(r"[\s\W]+", "", rest):
            errs.append(f"RFP {where}: not covered by any clause: {rest.strip()[:120]!r}")
    return errs


def parse_cargo_list(text: str) -> dict[tuple, set[str]]:
    out: dict[tuple, set[str]] = {}
    cur = None
    for ln in text.splitlines():
        m = re.match(r"^\s+Running (.+) \((?:.*/)?deps/([A-Za-z0-9_]+)-[0-9a-f]+(?:\.exe)?\)$", ln)
        if m:
            cur = out.setdefault((m.group(1), m.group(2)), set())
            continue
        if re.match(r"^\s+Doc-tests ", ln):
            cur = None
            continue
        m = re.match(r"^(\S+): (test|bench)$", ln)
        if m and cur is not None:
            cur.add(m.group(1))
    return out


def check_cargo_list(ctx: Context, resolved: dict[str, Resolved], files: list[str]) -> list[str]:
    listed: dict[tuple, set[str]] = {}
    for text in files:
        for k, v in parse_cargo_list(text).items():
            listed.setdefault(k, set()).update(v)
    if not listed:
        return ["cargo list: no test binaries found in the listing"]
    targets = {(p.name, t.id): t for p in ctx.packages for t in p.targets}
    errs, checked = [], 0
    for r in resolved.values():
        if not r.ok or r.rust is None:
            continue
        tg = targets[(r.rust.package, r.rust.target)]
        if tg.list_key not in listed:
            continue
        checked += 1
        if r.rust.path not in listed[tg.list_key]:
            errs.append(f"cargo list: `{r.rust.path}` is not in the compiled {tg.list_key[0]} of {r.rust.package}")
    if not checked:
        errs.append("cargo list: none of the map's tests are in the listed binaries")
    return errs


def check_e2e_records(resolved: dict[str, Resolved], files: list[str]) -> list[str]:
    ok: dict[str, bool] = {}
    for text in files:
        for ln in text.splitlines():
            if ln.strip():
                rec = json.loads(ln)
                ok[rec["step"]] = ok.get(rec["step"], True) and rec["ok"] is True
    errs = []
    for r in resolved.values():
        if "e2e" in r.ref:
            name = r.ref["e2e"]
            if name not in ok:
                errs.append(f"e2e records: `{name}` was not recorded by this run")
            elif not ok[name]:
                errs.append(f"e2e records: `{name}` failed in this run")
    return errs


# ---------------------------------------------------------------------------------------------
# docs/REQUIREMENTS.md
# ---------------------------------------------------------------------------------------------

def md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_test(ref: dict, r: Resolved) -> str:
    if "rust" in ref:
        return f"`{ref['rust']}` ({ref['crate']}, [{r.where}]({os.path.relpath(r.where, DOC.parent)}))"
    if "e2e" in ref:
        return f"E2E `{ref['e2e']}`"
    return f"check `{ref['check']}`: {CHECKS[ref['check']][0]}"


def render_record(rec: dict) -> str:
    if "url" in rec:
        return f"[{rec.get('what', rec['url'])}]({rec['url']})"
    label = f"{rec['file']}" + (f" {rec['anchor']}" if rec.get("anchor") else "")
    return f"[{label}]({os.path.relpath(rec['file'], DOC.parent)})" + (f": {rec['what']}" if rec.get("what") else "")


def render(ctx: Context, resolved: dict[str, Resolved]) -> str:
    rmap = ctx.rmap
    rfp, prop = rmap["rfp"], rmap["proposal"]
    clauses = rmap["clauses"]
    counts = {s: sum(c["status"] == s for c in clauses) for s in STATUSES}
    differ = [c for c in clauses if c.get("code_says")]
    gaps = [c for c in clauses if c.get("gap")]
    out = []
    w = out.append
    w("# RFP-017 requirement map")
    w("")
    w("<!-- Generated by scripts/check-reqmap.py --write from docs/requirements-map.json. Do not edit: CI fails when this file is stale. -->")
    w("")
    w(f"Every clause of RFP-017 ({rfp['title']}), quoted verbatim from `{rfp['repo']}` "
      f"`{rfp['path']}` at commit `{rfp['commit'][:12]}` (SHA-256 `{rfp['sha256'][:16]}…`), with its status "
      f"and, for each clause, the named tests and records that show it. Source of truth: "
      f"[`requirements-map.json`](requirements-map.json); this page is generated from it.")
    w("")
    w(f"**Status** is the one the filed proposal gives ({prop['where']}) unless a row says the code "
      f"disagrees. {' '.join(f'**{s}**: {d}' for s, d in rmap['statuses'].items())}")
    w("")
    w(f"**{len(clauses)} clauses: {counts['shown']} shown, {counts['in part']} in part, "
      f"{counts['not yet']} not yet, {counts['waits on Logos']} waits on Logos.** "
      + (f"Rows where the code contradicts the proposal: {', '.join(c['id'] for c in differ)}. " if differ
         else "No row's status is contradicted by the code. ")
      + (f"Evidence gaps noted (status kept): {', '.join(c['id'] for c in gaps)}." if gaps else ""))
    w("")
    w("## What CI enforces")
    w("")
    w("`scripts/check-reqmap.py` runs in CI (`.github/workflows/ci.yml`) and fails the build when:")
    w("")
    for line in ENFORCED:
        w(f"- {line}")
    w("")
    w("## Summary")
    w("")
    w("| Clause | Requirement (short) | Status | Tests | Records |")
    w("|---|---|---|---|---|")
    for c in clauses:
        st = c["status"] + (" (code differs from the proposal)" if c.get("code_says") else "") \
            + (" (evidence gap noted)" if c.get("gap") else "")
        w(f"| [{c['id']}](#{c['id'].lower()}) | {md_escape(c['short'])} | {st} | {len(c.get('tests') or [])} | {len(c.get('records') or [])} |")
    w("")
    groups = {g["id"]: g for g in rmap["groups"]}
    current = None
    for c in clauses:
        g = groups[c["group"]]
        if g["id"] != current:
            current = g["id"]
            w(f"## {g['title']}")
            w("")
        w(f"### {c['id']}")
        w("")
        w(f"> {c['text']}")
        w("")
        w(f"*RFP: {c['rfp_where']}.*")
        w("")
        prop_s = c.get("proposal")
        if prop_s:
            qual = f" ({prop_s['as_filed']})" if prop_s.get("as_filed") else ""
            w(f"**Status: {c['status']}.** Proposal row `{prop_s['row']}`: {prop_s['status']}{qual}.")
        else:
            w(f"**Status: {c['status']}.** Not a row of the proposal's table.")
        w("")
        if c.get("code_says"):
            w(f"**The code says otherwise:** {c['code_says']}")
            w("")
        if c.get("remaining"):
            w(f"**Remaining:** {c['remaining']}")
            w("")
        if c.get("note"):
            w(f"**Note:** {c['note']}")
            w("")
        if c.get("gap"):
            w(f"**Evidence gap:** {c['gap']}")
            w("")
        tests = c.get("tests") or []
        if tests:
            w("Tests:")
            w("")
            for t in tests:
                r = resolved[test_key(t)]
                w(f"- {render_test(t, r)}; CI: {', '.join(r.runs)}")
            w("")
        recs = c.get("records") or []
        if recs:
            w("Records:")
            w("")
            for rec in recs:
                w(f"- {render_record(rec)}")
            w("")
    w("## Not mapped")
    w("")
    for nm in rmap.get("not_mapped", []):
        w(f"- **{nm['what']}**: {nm['why']}")
    w("")
    w("## Tests not cited by any clause")
    w("")
    cited = {(r.rust.package, r.rust.path) for r in resolved.values() if r.rust}
    cited_e2e = {r.ref["e2e"] for r in resolved.values() if "e2e" in r.ref}
    uncited = sorted({(t.package, t.path) for t in ctx.tests} - cited)
    uncited_e2e = [n for n in dict.fromkeys(ctx.e2e_names) if n not in cited_e2e]
    by_key = {(t.package, t.path): t for t in ctx.tests}
    not_run = [p for k, p in uncited if not any(cargo_selects(r, ctx.packages, by_key[(k, p)]) for r in ctx.cargo_runs)]
    w(f"Listed so that nothing is hidden. Rust ({len(uncited)}"
      + (f"; not run by CI: {', '.join(not_run)}" if not_run else ", all run by CI") + "): "
      + (", ".join(f"`{p}` ({k})" for k, p in uncited) or "none") + ".")
    w("")
    w(f"End-to-end checks ({len(uncited_e2e)} of {len(set(ctx.e2e_names))}): "
      + (", ".join(f"`{n}`" for n in uncited_e2e) or "none") + ".")
    w("")
    return "\n".join(out)


# ---------------------------------------------------------------------------------------------
# Self-test: each kind of error is caught
# ---------------------------------------------------------------------------------------------

def stale_errors(doc: str) -> list[str]:
    path = ROOT / DOC
    if not path.exists() or path.read_text() != doc:
        return [f"{DOC} is stale: run scripts/check-reqmap.py --write and commit it"]
    return []


def self_test(ctx: Context) -> list[str]:
    failures = []
    base_errs, _ = validate(ctx)
    if base_errs:
        return ["self-test needs a clean map first"] + base_errs

    def expect(label: str, mutate, needle: str, workflow: str | None = None):
        m = copy.deepcopy(ctx.rmap)
        mutate(m)
        runs = ci_runs(workflow) if workflow else (ctx.cargo_runs, ctx.suite_runs, ctx.reqmap_runs)
        c2 = Context(m, ctx.packages, ctx.tests, *runs, ctx.e2e_names)
        errs, _ = validate(c2)
        if not any(needle in e for e in errs):
            failures.append(f"self-test `{label}`: expected an error containing {needle!r}, got {errs[:3]}")

    def first(m, status):
        return next(c for c in m["clauses"] if c["status"] == status and any("rust" in t for t in c.get("tests") or []))

    def rust_ref(m, status="shown"):
        return next(t for t in first(m, status)["tests"] if "rust" in t)

    expect("renamed test", lambda m: rust_ref(m).update(rust=rust_ref(m)["rust"] + "_renamed"), "no test")
    expect("wrong crate", lambda m: rust_ref(m).update(crate="escapement-idl"), "no test")
    expect("unknown e2e step", lambda m: first(m, "shown")["tests"].append({"e2e": "no-such-step"}), "is not a check of")
    expect("shown without tests", lambda m: first(m, "shown").update(tests=[]), "names no test")
    expect("in part without remaining", lambda m: first(m, "in part").update(remaining=""), "does not say what is missing")
    expect("status differs silently", lambda m: first(m, "in part").update(status="shown"), "differs from the proposal")
    expect("missing record", lambda m: first(m, "shown").setdefault("records", []).append({"file": "docs/NOPE.md"}), "does not exist")
    expect("missing anchor", lambda m: first(m, "shown").setdefault("records", []).append({"file": "docs/EVIDENCE.md", "anchor": "E-99"}), "not found")
    ignored = next((t for t in ctx.tests if t.ignored), None)
    if ignored:
        wf = (ROOT / WORKFLOW).read_text()
        no_manual = re.sub(r"-- --ignored", "--", wf)
        expect("ignored test not run", lambda m: first(m, "shown")["tests"].append(
            {"rust": ignored.path, "crate": ignored.package}), "#[ignore]", workflow=no_manual)
        expect("only manual CI", lambda m: first(m, "shown").update(
            tests=[{"rust": ignored.path, "crate": ignored.package}]), "runs on every push")
    wf = (ROOT / WORKFLOW).read_text()
    expect("crate not tested by CI", lambda m: None, "no `cargo test`",
           workflow=wf.replace("cargo test --workspace --locked -- --nocapture", "cargo test -p escapement-idl --locked -- --nocapture"))
    expect("suite not run", lambda m: None, "no CI job runs", workflow=wf.replace("bash e2e/run_e2e.sh", "true"))

    def s3_shown(m):
        next(c for c in m["clauses"] if c["id"] == "S3").update(status="shown", code_says="self-test")
    expect("S3 overclaims", s3_shown, "S3 is `shown`")
    # A map edit without regenerating the page.
    m = copy.deepcopy(ctx.rmap)
    m["clauses"][0]["note"] = (m["clauses"][0].get("note") or "") + " (edited)"
    c2 = Context(m, ctx.packages, ctx.tests, ctx.cargo_runs, ctx.suite_runs, ctx.reqmap_runs, ctx.e2e_names)
    _, resolved = validate(c2)
    if not stale_errors(render(c2, resolved)):
        failures.append("self-test `stale page`: an edited map did not make the page stale")
    # RFP text: a changed clause, an uncovered item, a different file.
    rfp_path = os.environ.get("REQMAP_SELFTEST_RFP")
    if rfp_path:
        text = Path(rfp_path).read_text()
        m = copy.deepcopy(ctx.rmap)
        m["clauses"][0]["text"] += " (paraphrased)"
        if not any("verbatim" in e for e in check_rfp(m, text)):
            failures.append("self-test `paraphrased clause`: not caught")
        m = copy.deepcopy(ctx.rmap)
        m["clauses"] = [c for c in m["clauses"] if c["id"] != "R2"]
        if not any("not covered" in e for e in check_rfp(m, text)):
            failures.append("self-test `dropped clause`: not caught")
        if not any("SHA-256" in e for e in check_rfp(ctx.rmap, text + "\n")):
            failures.append("self-test `different RFP file`: not caught")
    return failures


# ---------------------------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--write", action="store_true", help="regenerate docs/REQUIREMENTS.md")
    ap.add_argument("--rfp", help="the RFP text at the pinned commit")
    ap.add_argument("--cargo-list", action="append", default=[], help="output of `cargo test ... -- --list` (repeatable)")
    ap.add_argument("--e2e-records", action="append", default=[], help="e2e/.run/out/e2e.jsonl (repeatable)")
    ap.add_argument("--self-test", action="store_true", help="show each kind of error is caught")
    ap.add_argument("--print-rfp-url", action="store_true", help="print where CI downloads the pinned RFP text")
    a = ap.parse_args()
    if a.print_rfp_url:
        rfp = json.loads((ROOT / MAP).read_text())["rfp"]
        print(f"https://raw.githubusercontent.com/{rfp['repo']}/{rfp['commit']}/{rfp['path']}")
        return 0
    try:
        ctx = load_context()
        if a.self_test:
            if a.rfp:
                os.environ["REQMAP_SELFTEST_RFP"] = a.rfp
            fails = self_test(ctx)
            for f in fails:
                print(f"FAIL {f}", file=sys.stderr)
            print(f"check-reqmap self-test: {'FAILED' if fails else 'every injected error was caught'}")
            return 1 if fails else 0
        errs, resolved = validate(
            ctx,
            rfp_text=Path(a.rfp).read_text() if a.rfp else None,
            cargo_list=[Path(f).read_text() for f in a.cargo_list] or None,
            e2e_records=[Path(f).read_text() for f in a.e2e_records] or None)
        doc = render(ctx, resolved)
        if a.write:
            (ROOT / DOC).write_text(doc)
        errs += stale_errors(doc)
    except MapError as e:
        print(f"check-reqmap: {e}", file=sys.stderr)
        return 1
    for e in errs:
        print(f"FAIL {e}", file=sys.stderr)
    clauses = ctx.rmap["clauses"]
    counts = ", ".join(f"{sum(c['status'] == s for c in clauses)} {s}" for s in STATUSES)
    n_tests = len({k for k, r in resolved.items() if r.ok})
    extra = []
    if a.rfp:
        extra.append("checked against the RFP text")
    if a.cargo_list:
        extra.append("checked against the compiled test binaries")
    if a.e2e_records:
        extra.append("checked against the E2E records")
    print(f"check-reqmap: {len(clauses)} clauses ({counts}); {n_tests} distinct named tests"
          + (f"; {'; '.join(extra)}" if extra else "")
          + (f"; {len(errs)} error(s)" if errs else "; OK"))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
