#!/usr/bin/env python3
"""Re-check the run records in docs/records/ against the raw files they were built from.

Each record (docs/records/*.json other than claims.json) lists its raw files with their SHA-256 and
size, and holds a `measured` block. This script hashes the raw files, re-derives `measured` from
their bytes with the parser for the record's `kind`, and requires the two to be equal. It then runs
the record's provenance checks (text quoted from a doc at a given commit, paths unchanged between
two commits) and compares every figure in docs/records/claims.json with the record value it cites.

    python3 scripts/verify-records.py                    # PASS/FAIL per record and per claim
    python3 scripts/verify-records.py --require-history  # a git check that cannot run is a FAIL
    python3 scripts/verify-records.py --derive ID        # print what the parsers derive for record ID

Comparisons are type-strict (True != 1, 41 != 41.0); a self-test that edited records and claims
are caught runs first, every time. Every file under docs/records/raw/ must belong to a record and
hold no local absolute path or key material.

Exit status 1 if anything fails. Python 3 standard library only; reads files, runs `git` read-only.
"""
import argparse
import copy
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORDS = ROOT / "docs" / "records"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_artifact(art):
    return (ROOT / art["path"]).read_bytes()


def jsonl_rows(data):
    rows = []
    for n, line in enumerate(data.split(b"\n"), 1):
        if line.strip():
            rows.append((n, line, json.loads(line)))
    return rows


def result_of(row):
    out = row.get("out")
    if isinstance(out, dict) and isinstance(out.get("result"), dict):
        return out["result"]
    return None


def tx_fields(tx):
    return {k: tx[k] for k in ("block", "index", "hash", "bytes", "reverted")}


# ---------------------------------------------------------------- e2e/run_e2e.sh output (e2e.jsonl)

def derive_e2e_jsonl(data):
    rows = jsonl_rows(data)
    by_step = {r["step"]: r for _, _, r in rows}
    m = {}
    m["checks"] = {
        "total": len(rows),
        "passed": sum(1 for _, _, r in rows if r["ok"] is True),
        "failed": sum(1 for _, _, r in rows if r["ok"] is not True),
        "distinct_steps": len({r["step"] for _, _, r in rows}),
    }
    m["answers"] = [
        {
            "line": n,
            "step": r["step"],
            "ok": r["ok"],
            "command": r["out"].get("command") if isinstance(r["out"], dict) else None,
            "sha256": sha256(line),
        }
        for n, line, r in rows
    ]
    modes = sorted({res["dev_mode"] for _, _, r in rows if (res := result_of(r)) and "dev_mode" in res})
    m["dev_mode_reported"] = modes
    p = result_of(by_step["probe"])
    m["probe"] = {k: p[k] for k in ("base_fee_exec", "base_fee_stor", "head")}

    def deploy(step):
        d = result_of(by_step[step])
        out = {k: d[k] for k in ("image_id", "elf_bytes", "segments", "immutable", "program_address")}
        out["transactions"] = [tx_fields(t) for t in d["transactions"]]
        if "admin_init" in d:
            out["admin_init"] = tx_fields(d["admin_init"])
        return out

    m["deploy"] = deploy("deploy-immutable-and-init-admin")
    m["deploy_token_program"] = deploy("deploy-token-program")

    # Every distinct transaction the suite reported, first step that reported it, in file order.
    txs, seen = [], set()
    for _, _, r in rows:
        res = result_of(r)
        if not res:
            continue
        found = []
        for t in res.get("transactions", []):
            found.append(("deploy", t))
        if isinstance(res.get("admin_init"), dict):
            found.append(("admin-init", res["admin_init"]))
        if isinstance(res.get("tx"), dict):
            found.append((r["out"]["command"], res["tx"]))
        for role, t in found:
            if t["hash"] in seen:
                continue
            seen.add(t["hash"])
            txs.append(dict(step=r["step"], role=role, **tx_fields(t)))
    m["transactions"] = txs
    m["transactions_total"] = len(txs)
    m["transactions_reverted"] = sum(1 for t in txs if t["reverted"])

    refusals = []
    for _, _, r in rows:
        if r["step"].endswith("-sent-on-chain"):
            name = r["step"][: -len("-sent-on-chain")]
            check = by_step.get(name + "-reverted-state-unchanged")
            tx = result_of(r)["tx"]
            refusals.append({
                "name": name,
                "block": tx["block"],
                "hash": tx["hash"],
                "reverted": tx["reverted"],
                "state_unchanged_check_ok": bool(check and check["ok"] is True),
            })
    m["refusals"] = refusals

    # Privacy-preserving transactions: rows whose answer carries a proving time and a sent tx.
    priv, seen, balance = [], set(), 0
    for _, _, r in rows:
        res = result_of(r)
        if not res or "prove_s" not in res or not isinstance(res.get("tx"), dict):
            continue
        if res["tx"]["hash"] in seen:
            continue
        seen.add(res["tx"]["hash"])
        after = int(res["account_native_balance_after"])
        fee = int(res["fee_reserve"])
        priv.append({
            "step": r["step"],
            "command": r["out"]["command"],
            "dev_mode": res["dev_mode"],
            "prove_s": res["prove_s"],
            "proof_bytes": res["proof_bytes"],
            "tx_bytes": res["tx"]["bytes"],
            "block": res["tx"]["block"],
            "hash": res["tx"]["hash"],
            "reverted": res["tx"]["reverted"],
            "public_cycles": res["public_cycles_simulated"],
            "fee_reserve": fee,
            "amount": int(res["amount"]) if "amount" in res else None,
            "escrow_debited": int(res["escrow_debited"]) if "escrow_debited" in res else None,
            "account_native_balance_after": after,
            # what the private account's native balance gained besides paying the fee reserve
            "native_credit": after - balance + fee,
            "token_holdings_after": res.get("token_holdings_after"),
            "private_account_id_in_tx_bytes": res["private_account_id_in_tx_bytes"],
            "private_commitment_found": res["private_commitment_found"],
        })
        balance = after
    m["private_transactions"] = priv

    cycles, seen = [], set()
    for _, _, r in rows:
        res = result_of(r)
        if not res or res.get("simulated_cycles") is None or not isinstance(res.get("tx"), dict):
            continue
        if res["tx"]["hash"] in seen:
            continue
        seen.add(res["tx"]["hash"])
        cycles.append({"step": r["step"], "command": r["out"]["command"], "cycles": res["simulated_cycles"]})
    m["public_cycles"] = cycles

    ge = by_step["getEvents-is-not-a-sequencer-rpc-on-rc3"]["out"]
    m["get_events_answer"] = {"code": ge["error"]["code"], "message": ge["error"]["message"]}
    return m, [r["step"] for _, _, r in rows]


# ---------------------------------------------------------------- GNU time -v output

TIME_FIELDS = {
    "Command being timed": ("command", lambda s: s.strip('"')),
    "User time (seconds)": ("user_s", float),
    "System time (seconds)": ("system_s", float),
    "Percent of CPU this job got": ("cpu_percent", lambda s: int(s.rstrip("%"))),
    "Elapsed (wall clock) time (h:mm:ss or m:ss)": ("elapsed", str),
    "Maximum resident set size (kbytes)": ("max_rss_kib", int),
    "Exit status": ("exit_status", int),
}


def elapsed_seconds(s):
    total = Decimal(0)
    for part in s.split(":"):
        total = total * 60 + Decimal(part)
    return float(total)


def derive_time(data):
    m, passes = {}, []
    for line in data.decode().splitlines():
        if line.startswith("PASS "):
            passes.append(line[5:])
            continue
        key, _, val = line.strip().partition(": ")
        if key in TIME_FIELDS:
            name, conv = TIME_FIELDS[key]
            m[name] = conv(val)
    mode = re.search(r"(?:^|\s)E2E_DEV_MODE=(\d)(?:\s|$)", m["command"])
    m["e2e_dev_mode_in_command"] = int(mode.group(1)) if mode else None
    m["elapsed_s"] = elapsed_seconds(m["elapsed"])
    m["cpu_s"] = round(m["user_s"] + m["system_s"], 2)
    m["stdout_pass_lines"] = len(passes)
    return m, passes


# ---------------------------------------------------------------- the round's driver log

TS = r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00)"


def log_section(text, start, end):
    lines = text.splitlines()
    i = next(n for n, l in enumerate(lines) if l.startswith(start))
    j = next((n for n in range(i + 1, len(lines)) if end and lines[n].startswith(end)), len(lines))
    return lines[i:j]


def derive_log_section(data, spec):
    sec = log_section(data.decode(), spec["from"], spec.get("to"))
    m = {"header": sec[0]}
    t = re.search(TS, sec[0])
    m["header_time"] = t.group(1) if t else None
    for l in sec:
        if mm := re.match(r"^([A-Z0-9_]+_EXIT)=(\d+)(?: (\d+)s)?$", l):
            m[mm.group(1)] = int(mm.group(2))
            if mm.group(3):
                m[mm.group(1) + "_wall_s"] = int(mm.group(3))
        if mm := re.match(r"^e2e: (\d+) passed, (\d+) failed \(dev mode: (\d)\)", l):
            m["summary"] = {"passed": int(mm.group(1)), "failed": int(mm.group(2)), "dev_mode": int(mm.group(3))}
    return m


def derive_suite_log(data):
    text = data.decode()
    lines = text.splitlines()
    m = {}
    m["start"] = re.match(r"^start " + TS, lines[0]).group(1)
    done = [re.match(r"^ALL_DONE " + TS, l) for l in lines]
    m["all_done"] = next(d.group(1) for d in done if d)
    m["markers"] = [l for l in lines if re.match(r"^[A-Z0-9_]+(_OK|_DONE|_EXIT=\d+)( .*)?$", l)]
    m["sections"] = [l for l in lines if l.startswith("== ")]
    m["guest_check"] = "the image id matches image-ids.tsv" in lines
    clippy = log_section(text, "FMT_OK", "CLIPPY_DONE")
    m["clippy"] = {
        "build_script_failures": sum(1 for l in clippy if l.startswith("error: failed to run custom build command")),
        "exit_status_logged": any("CLIPPY_EXIT" in l for l in lines),
    }
    relay = [re.match(r"^\[SEC_RELAY\] (\w+) relayed by another program -> exit (\d+) \((\d+) cycles\)$", l) for l in lines]
    m["sec_relay"] = [{"op": r.group(1), "code": int(r.group(2)), "cycles": int(r.group(3))} for r in relay if r]
    neg = [re.match(r"^\[SEC_PDA_NEG\] (\w+): no grant, inherited grant, wrong seed -> (\d+), unchanged$", l) for l in lines]
    m["sec_pda_neg"] = [{"op": r.group(1), "code": int(r.group(2))} for r in neg if r]
    adm = [re.match(r"^\[SEC_ADMIN_RELAY\] (\w+) relayed by another program -> refused: .*(E\d+)", l) for l in lines]
    m["sec_admin_relay"] = [{"op": r.group(1), "error": r.group(2)} for r in adm if r]
    forged = [re.match(r"^\[SEC_FORGED\] (.+) from another program -> refused: .*code: (\d+), cycles: (\d+)", l) for l in lines]
    m["sec_forged"] = [{"message": r.group(1), "code": int(r.group(2)), "cycles": int(r.group(3))} for r in forged if r]
    asy = [re.match(r"^\[SEC_ASYNC\] (.+) -> (\d+), unchanged$", l) for l in lines]
    m["sec_async"] = [{"case": r.group(1), "code": int(r.group(2))} for r in asy if r]
    m["tests_ok"] = [mm.group(1) for l in lines if (mm := re.match(r"^test (\S+) \.\.\. ok$", l))]
    results, section = [], "start"
    for l in lines:
        if l.startswith("== "):
            section = l[3:]
        mm = re.match(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", l)
        if mm:
            results.append({"section": section, "result": mm.group(1), "passed": int(mm.group(2)),
                            "failed": int(mm.group(3)), "ignored": int(mm.group(4)),
                            "filtered_out": int(mm.group(6))})
    m["test_results"] = results
    return m


# ---------------------------------------------------------------- image-ids.tsv + deploy read-backs

def derive_guest(rec):
    # image-ids.tsv as of the commit the record names, so a later guest change does not touch it
    at = rec["tsv_at"]
    shown = git("show", f"{at}:image-ids.tsv") if have_commit(at) else None
    tsv = shown.stdout if shown is not None and shown.returncode == 0 else (ROOT / "image-ids.tsv").read_text()
    row = next(l.split("\t") for l in tsv.splitlines() if l.startswith("escapement\t"))
    m = {"tsv": {"image_id": row[1], "sha256": row[2], "bytes": int(row[3])}}
    reads = []
    for name in sorted(rec["artifacts"]):
        d, _ = derive_e2e_jsonl(read_artifact(rec["artifacts"][name]))
        dep = d["deploy"]
        reads.append({"artifact": name, "image_id": dep["image_id"], "elf_bytes": dep["elf_bytes"],
                      "segments": dep["segments"], "immutable": dep["immutable"],
                      "deploy_transactions": len(dep["transactions"])})
    m["read_backs"] = reads
    m["all_read_backs_match_tsv"] = all(
        r["image_id"] == m["tsv"]["image_id"] and r["elf_bytes"] == m["tsv"]["bytes"] and r["immutable"] for r in reads
    )
    return m


# ---------------------------------------------------------------- per-kind derivation

def derive(rec):
    kind, arts = rec["kind"], rec["artifacts"]
    if kind == "e2e-sequencer-run":
        m, steps = derive_e2e_jsonl(read_artifact(arts["jsonl"]))
        if "time" in arts:
            t, passes = derive_time(read_artifact(arts["time"]))
            t["stdout_pass_lines_match_jsonl"] = passes == steps
            m["time"] = t
        if "log" in arts:
            m["log"] = derive_log_section(read_artifact(arts["log"]), arts["log"]["section"])
        if "time" in arts and "log" in arts and m["log"].get("header_time"):
            start = dt.datetime.fromisoformat(m["log"]["header_time"])
            end = start + dt.timedelta(seconds=m["time"]["elapsed_s"])
            m["start"] = start.isoformat()
            m["end"] = end.isoformat(timespec="seconds")
        return m
    if kind == "suite-log":
        return derive_suite_log(read_artifact(arts["log"]))
    if kind == "guest-image":
        return derive_guest(rec)
    raise ValueError(f"unknown record kind {kind!r}")


# ---------------------------------------------------------------- provenance checks (git, docs)

def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)


def have_commit(c):
    return git("cat-file", "-e", c + "^{commit}").returncode == 0


def run_check(chk, require_history):
    """Returns (ok, note); ok None means skipped."""
    t = chk["type"]
    if t == "doc-contains":
        at = chk.get("at")
        if at and have_commit(at):
            r = git("show", f"{at}:{chk['file']}")
            text, where = r.stdout, f"{chk['file']} at {at[:7]}"
        else:
            if at and require_history:
                return False, f"commit {at[:7]} not in this clone"
            text, where = (ROOT / chk["file"]).read_text(), f"{chk['file']} (working tree)"
        return chk["text"] in text, f"{where} contains {chk['text']!r}"
    if t in ("git-unchanged", "git-numstat"):
        a, b = chk["from"], chk["to"]
        if not (have_commit(a) and have_commit(b)):
            msg = f"commits {a[:7]}/{b[:7]} not in this clone (fetch full history)"
            return (False if require_history else None), msg
        r = git("diff", "--numstat", a, b, "--", *chk["paths"])
        got = [l for l in r.stdout.splitlines() if l]
        want = chk.get("expect", [])
        return r.returncode == 0 and got == want, f"git diff {a[:7]} {b[:7]} -- {' '.join(chk['paths'])}: {len(got)} changed file(s)"
    return False, f"unknown check type {t!r}"


# ---------------------------------------------------------------- claims

def resolve(obj, path):
    """`a.b[0].c`, `a[*].c` (list), `a[step=x].c` (first element whose field equals x)."""
    cur = [obj]
    many = False
    for tok in re.findall(r"[^.\[\]]+|\[[^\]]*\]", path):
        nxt = []
        for c in cur:
            if tok == "[*]":
                nxt.extend(c)
                many = True
            elif tok.startswith("[") and "=" in tok:
                k, v = tok[1:-1].split("=", 1)
                nxt.append(next(e for e in c if str(e.get(k)) == v))
            elif tok.startswith("["):
                nxt.append(c[int(tok[1:-1])])
            else:
                nxt.append(c[tok])
        cur = nxt
    return cur if many else cur[0]


def claim_value(claim, records):
    src = claim["source"]
    rec = records[src["record"]]["measured"]
    v = resolve(rec, src["path"])
    red = src.get("reduce")
    if red == "min":
        v = min(v)
    elif red == "max":
        v = max(v)
    elif red == "len":
        v = len(v)
    elif red == "all":
        v = all(v)
    elif red == "set":
        v = sorted(set(v))
    if "divide_by" in src:
        v = v / resolve(rec, src["divide_by"])
    if "scale" in src:
        v = v * src["scale"]
    if "round" in src:
        q = Decimal(1).scaleb(-src["round"])
        v = Decimal(str(v)).quantize(q, rounding=ROUND_HALF_UP)
        v = int(v) if src["round"] == 0 else float(v)
    return v


def strict_eq(a, b):
    """Equality that also requires equal JSON types: True != 1, False != 0, 41 != 41.0."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(strict_eq(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(strict_eq(x, y) for x, y in zip(a, b))
    return a == b


LOCAL_PATH = re.compile(
    rb"(?:^|[\s\"'=:(])/(?:home|Users|root|tmp|mnt|var|opt|srv|workspace|data|scratch)/|\b[A-Za-z]:\\", re.M)
KEY_MATERIAL = re.compile(rb"\"(?:secret|secret_key|nsk|vsk|private_key|seed)\"\s*:|BEGIN [A-Z ]*PRIVATE KEY")


def check_raw_dir(records):
    """Every file under docs/records/raw/ belongs to a record and holds no local path or key."""
    used = {art["path"] for rec in records.values() for art in rec["artifacts"].values()}
    problems = []
    for f in sorted((RECORDS / "raw").rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(ROOT).as_posix()
        data = f.read_bytes()
        if rel not in used:
            problems.append(f"{rel}: not an artifact of any record")
        if LOCAL_PATH.search(data):
            problems.append(f"{rel}: holds a local absolute path (replace it by <workdir>)")
        if KEY_MATERIAL.search(data):
            problems.append(f"{rel}: holds what looks like key material")
    return problems


def check_record(rec, require_history):
    problems, notes = [], []
    for name, art in rec["artifacts"].items():
        path = ROOT / art["path"]
        if not path.is_file():
            problems.append(f"{name}: {art['path']} missing")
            continue
        data = path.read_bytes()
        if sha256(data) != art["sha256"] or len(data) != art["bytes"]:
            problems.append(f"{name}: {art['path']} hash/size differ")
    if not problems:
        try:
            got = derive(rec)
        except Exception as e:  # a raw file the parser cannot read is a failure, not a crash
            got, problems = None, [f"derivation failed: {e!r}"]
        want = rec["measured"]
        if got is not None and not strict_eq(got, want):
            keys = sorted(k for k in set(got) | set(want) if not strict_eq(got.get(k), want.get(k)))
            problems.append("measured differs from the raw files (value or type) in: " + ", ".join(keys))
    for chk in rec.get("provenance", {}).get("checks", []):
        ok, note = run_check(chk, require_history)
        if ok is False:
            problems.append("provenance: " + note)
        elif ok is None:
            notes.append("skipped: " + note)
    return problems, notes


def check_claim(c, records, require_history):
    src = c["source"]
    try:
        if "record" in src:
            got = claim_value(c, records)
            ok = strict_eq(got, c["value"])
            detail = f"record {src['record']} {src['path']} -> {got!r}, claim says {c['value']!r}"
        else:
            ok, detail = run_check({"type": "doc-contains", **src}, require_history)
    except Exception as e:
        ok, detail = False, f"error: {e!r}"
    return ("FAIL" if not ok else ("PASS" if "record" in src else "DOC")), detail


def set_path(obj, dotted, value):
    *head, last = dotted.split(".")
    for k in head:
        obj = obj[k]
    obj[last] = value


def self_test(records, claims):
    """Type swaps in records and claims must fail. Returns a list of problems (empty = pass)."""
    problems = []
    for a, b, want in ((True, 1, False), (False, 0, False), (41, 41.0, False), (0, None, False),
                       ("1", 1, False), (1.5, 1.5, True), ({"a": [1]}, {"a": [1]}, True),
                       ({"a": [1]}, {"a": [True]}, False), ([False], [0], False)):
        if strict_eq(a, b) is not want:
            problems.append(f"strict_eq({a!r}, {b!r}) is not {want}")
    rid = "e2e-sequencer-real-proof-2026-11-24"
    for path, bad in (("time.exit_status", False), ("checks.failed", False), ("transactions_total", 41.0),
                      ("time.user_s", 37763), ("probe.base_fee_exec", 8.0)):
        rec = copy.deepcopy(records[rid])
        set_path(rec["measured"], path, bad)
        if not check_record(rec, False)[0]:
            problems.append(f"record {rid}: measured.{path} = {bad!r} was not caught")
    by_id = {c["id"]: c for c in claims}
    for cid, bad in (("R-4", False), ("R-11", 5.0), ("G-4", 1), ("R-12", 206), ("E-5", 1)):
        c = copy.deepcopy(by_id[cid])
        c["value"] = bad
        if check_claim(c, records, False)[0] != "FAIL":
            problems.append(f"claim {cid}: value {bad!r} was not caught")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--require-history", action="store_true")
    ap.add_argument("--derive", metavar="RECORD_ID")
    args = ap.parse_args()

    failed = 0
    records = {}
    for p in sorted(p for p in RECORDS.glob("*.json") if p.name != "claims.json"):
        rec = json.loads(p.read_text())
        if rec["id"] in records:
            print(f"FAIL  duplicate record id {rec['id']} ({p.name}, {records[rec['id']]['_file']})")
            failed += 1
            continue
        rec["_file"] = p.name
        records[rec["id"]] = rec

    if args.derive:
        print(json.dumps(derive(records[args.derive]), indent=2))
        return 0

    claims_doc = json.loads((RECORDS / "claims.json").read_text())
    claims = claims_doc["claims"]
    expected = set(claims_doc["records"])
    for rid in sorted(expected ^ set(records)):
        print(f"FAIL  record {rid}: " + ("missing" if rid in expected else "not listed in claims.json `records`"))
        failed += 1

    st = self_test(records, claims)
    print(f"self-test (type swaps in records and claims are caught): {'FAIL' if st else 'PASS'}")
    for p in st:
        print(f"        - {p}")
    failed += bool(st)

    raw = check_raw_dir(records)
    print(f"raw files (all belong to a record; no local path or key material): {'FAIL' if raw else 'PASS'}")
    for p in raw:
        print(f"        - {p}")
    failed += bool(raw)

    print(f"records ({len(records)}):")
    for rid, rec in records.items():
        problems, notes = check_record(rec, args.require_history)
        failed += bool(problems)
        print(f"  {'FAIL' if problems else 'PASS'}  {rid}  ({rec['_file']})")
        for p in problems:
            print(f"        - {p}")
        for n in notes:
            print(f"        . {n}")

    print(f"claims ({len(claims)}; PASS = re-derived from a record's raw files, "
          "DOC = only stated in the docs, no raw log in the repository):")
    counts = {"PASS": 0, "DOC": 0, "FAIL": 0}
    for c in claims:
        status, detail = check_claim(c, records, args.require_history)
        counts[status] += 1
        failed += status == "FAIL"
        print(f"  {status:<4}  {c['id']}  {c['says']}")
        if status != "PASS":
            print(f"        - {detail}")
    print(f"claims: {counts['PASS']} PASS, {counts['DOC']} DOC, {counts['FAIL']} FAIL")
    print("all records and claims check" if not failed else f"{failed} failure(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
