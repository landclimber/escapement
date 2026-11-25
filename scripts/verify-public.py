#!/usr/bin/env python3
"""Re-reads, through a LEZ RPC, every transaction and account listed in docs/public-network/ (transactions.tsv,
accounts.tsv) and checks each against the chain. Read-only; Python's standard library only.

Every read goes through one RPC endpoint (by default the network operator's, docs/public-network/network.json).
What is checked is that endpoint's answers being consistent with the records and with themselves, not that other
nodes serve the same chain (docs/PUBLIC-NETWORK.md, "What this does not show").

For each transaction:
- `getTransaction` returns it and its block; its hash is recomputed (SHA-256 of its borsh encoding, as LEZ hashes
  it); the block is fetched with `getBlock`, decoded, and its hash recomputed from its contents; the transaction sits
  at the recorded index; the block's reverted list holds that index exactly when the record says "refused";
- what it did: its root call is decoded (the program called, the account it is rooted at, the message and its
  arguments) and must match the row's `call`, `root` and `expect` columns, and the accounts whose keys signed it
  (from its witnesses) must include the row's `signed_by`; the step's name must agree with the call, so rows whose
  roles were swapped fail; refused rows must carry the recorded gas limit (they did not run out of gas);
- a privacy-preserving transaction: its public call is decoded the same way, its actors must include the schedule,
  and its proof must be a real RISC Zero receipt (`InnerReceipt` Composite, Succinct or Groth16; Fake, what dev mode
  makes, fails) of the recorded variant and size. The proof's validity itself rests on the sequencer, which verified
  it before including the transaction; this script does not run a RISC Zero verifier;
- a deployment: the segments written point to each other (tail first) and the header to the first one.
Fetched blocks that are consecutive must link (each one's parent hash is the previous one's hash). The records must be
complete: network.json pins the counts of transactions, accounts and native escrows, rows are numbered in order with no
hash or account twice, and each account that signed a recorded transaction has an on-chain nonce equal to its recorded
transactions. This checks the committed evidence set, not every transaction the network ever carried.

For each account: program headers carry the recorded image id (Escapement's from image-ids.tsv) and are immutable;
the configuration holds the recorded token program, fee and admin; each schedule's state (`VestingActorState::
Schedule`, borsh) shows the recorded creator, beneficiary, asset, kind, total, claimed amount, flags, authorities and
cancellation, and each native escrow holds exactly what its schedules have not paid out. Exit status 1 on any mismatch.

    scripts/verify-public.sh                 through the RPC in docs/public-network/network.json
    RPC=<url> scripts/verify-public.sh       through another endpoint serving the same chain
    scripts/verify-public.sh --self-test     also: wrong records (an amount, a recipient, an account, the operation,
                                             a refusal, the receipt, swapped rows, a deleted transaction or account
                                             row) must each fail
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "docs", "public-network")
NETWORK = json.load(open(os.path.join(DATA, "network.json")))
RPC = os.environ.get("RPC", NETWORK["rpc"])
EXPLORER = NETWORK["explorer"]
BLOCK_HASH_PREFIX = b"/LEE/v0.3/Message/Block/".ljust(32, b"\0")
ACCOUNT_ID_PREFIX = b"/LEE/v0.3/AccountId/Public/".ljust(32, b"\0")  # a public account's id: SHA-256(prefix, key)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RECEIPTS = {0: "composite", 1: "succinct", 2: "groth16", 3: "fake"}  # risc0-zkvm InnerReceipt, as LEZ encodes it


def b58encode(b):
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


LOADER, NATIVE = b58encode(bytes([0xFE] * 32)), b58encode(bytes(32))
ESCAPEMENT, TOKEN = NETWORK["program"], NETWORK["token_program"]


def call(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    for attempt in range(8):
        req = urllib.request.Request(RPC, data=body, headers={"Content-Type": "application/json",
                                                               "User-Agent": "escapement-verify-public"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                d = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 7:  # the gateway's per-address budget: wait as it asks
                time.sleep(float(e.headers.get("Retry-After") or 5))
                continue
            raise
        if "error" in d:
            raise RuntimeError(f"{method}: {d['error']}")
        return d["result"]
    raise RuntimeError(f"{method}: rate-limited")


class Reader:
    def __init__(self, b):
        self.b, self.p = bytes(b), 0

    def take(self, n):
        if self.p + n > len(self.b):
            raise ValueError("truncated")
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), "little")

    def u32(self):
        return int.from_bytes(self.take(4), "little")

    def u64(self):
        return int.from_bytes(self.take(8), "little")

    def u128(self):
        return int.from_bytes(self.take(16), "little")

    def acct(self):
        return b58encode(self.take(32))

    def boolean(self):
        v = self.u8()
        if v > 1:
            raise ValueError(f"bool {v}")
        return v == 1

    def vec(self, f):
        return [f(self) for _ in range(self.u32())]

    def bytes_vec(self):
        return self.take(self.u32())

    def option(self, f):
        t = self.u8()
        if t > 1:
            raise ValueError(f"option tag {t}")
        return f(self) if t else None

    def end(self, what):
        if self.p != len(self.b):
            raise ValueError(f"{what}: {len(self.b) - self.p} bytes left over")


# ---- LEZ v0.4.0-rc3's transaction and block encodings (borsh), as the network's explorer decodes them ----------
def actor(r): return (r.acct(), r.acct())
def root_call(r): return (actor(r), r.bytes_vec())
def public_context(r):
    actors = r.vec(actor)
    r.vec(lambda r: r.take(32))
    r.vec(lambda r: r.u64())
    return actors
def nonces(r): r.vec(lambda r: r.take(48))
def evidence(r):
    t = r.u8()
    if t > 1:
        raise ValueError(f"evidence tag {t}")
    r.take(32 if t == 0 else 64)
def witnesses(r):
    """The accounts whose keys signed: each witness is a signature (64 B) and its public key (32 B)."""
    return [b58encode(hashlib.sha256(ACCOUNT_ID_PREFIX + w[64:]).digest()) for w in r.vec(lambda r: r.take(96))]
def fee_declaration(r):
    r.take(32)
    gas = r.u64()
    r.u64()
    r.take(16)
    return gas
def note(r): r.bytes_vec(); r.bytes_vec()
def delivery(r):
    actor(r); actor(r); r.bytes_vec()
    r.vec(lambda r: r.take(32)); r.u8(); r.vec(lambda r: r.take(32))
def boundary_step(r):
    t = r.u8()
    if t > 3:
        raise ValueError(f"boundary tag {t}")
    if t < 2:
        delivery(r)
def private_action(r): r.take(96); note(r)
def window(r): r.option(lambda r: r.u64()); r.option(lambda r: r.u64())
def image_claim(r):
    t = r.u8()
    if t > 1:
        raise ValueError(f"image claim tag {t}")
    r.take(64 if t == 0 else 32)
def proven_fee(r):
    r.option(lambda r: r.take(32))
    r.option(lambda r: (private_action(r), r.vec(boundary_step)))


def transaction(r):
    """The transaction at the reader's position: kind, hash, root call, gas limit, actors, proof."""
    tag = r.u8()
    start = r.p
    tx = {"proof": b"", "gas": None, "root": None}
    if tag == 0:
        tx["kind"] = "public"
        tx["actors"] = public_context(r)
        tx["root"] = root_call(r)
        tx["gas"] = r.option(fee_declaration)
        nonces(r); r.vec(evidence)
        tx["signers"] = witnesses(r)
    elif tag == 1:
        tx["kind"] = "private"
        tx["actors"] = public_context(r)
        r.vec(boundary_step); r.vec(lambda r: (r.take(32), note(r))); r.vec(lambda r: (r.take(32), note(r)))
        tx["root"] = r.option(root_call)
        r.vec(private_action); window(r); window(r); r.vec(image_claim); r.option(proven_fee)
        nonces(r); r.vec(evidence)
        tx["signers"] = witnesses(r)
        tx["proof"] = r.bytes_vec()
    else:
        raise ValueError(f"transaction tag {tag}")
    tx["hash"] = hashlib.sha256(r.b[start:r.p]).hexdigest()
    return tx


def block(raw):
    r = Reader(raw)
    block_id = r.u64()
    parent = r.take(32)
    header_hash = r.take(32)
    r.u64()
    body = r.p
    txs = r.vec(transaction)
    reverted = r.vec(lambda r: r.u64())
    end = r.p
    if r.u8() > 2 or r.p != len(raw):
        raise ValueError("block encoding")
    computed = hashlib.sha256(BLOCK_HASH_PREFIX + raw[0:40] + raw[72:80] + raw[body:end]).digest()
    return {"id": block_id, "parent": parent, "hash": header_hash, "hash_ok": computed == header_hash,
            "txs": txs, "reverted": reverted}


# ---- the programs' messages ------------------------------------------------------------------------------------
def asset(r):
    t = r.u8()
    if t > 1:
        raise ValueError(f"asset tag {t}")
    return "native" if t == 0 else "token:" + r.acct()


def kind(r, f):
    t = r.u8()
    if t == 0:
        r.u64(); r.u64(); r.u64()
        f["kind"], f["cliff_amount"] = "cliff+linear", str(r.u128())
    elif t == 1:
        r.u64(); r.u64()
        f["kind"] = "linear"
    elif t == 2:
        tranches = r.vec(lambda r: (r.u128(), r.boolean(), r.option(lambda r: r.u64())))
        f["kind"] = "milestone"
        f["tranches"] = "+".join(str(t[0]) for t in tranches)
    else:
        raise ValueError(f"kind tag {t}")


def opt_acct(r):
    v = r.option(lambda r: r.acct())
    return v or "none"


def no_broker(r):
    if r.u8() != 0:
        raise ValueError("a broker fee (none was set in this run)")


def escapement_message(msg):
    if msg[:1] == b"\xff":  # lez-authority's library messages (LIBRARY_TAG), behind the program's own
        return "admin." + {0: "Init"}.get(msg[1], f"library{msg[1]}"), {}
    r, f = Reader(msg), {}
    v = r.u8()
    if v == 0:
        name = "Configure"
        f["token_program"], f["fee_bps"], f["treasury"] = opt_acct(r), str(r.u16()), opt_acct(r)
    elif v == 2:
        name = "CreateSchedule"
        r.take(32)  # salt
        f["asset"] = asset(r)
        r.take(64)  # creator and refund holdings
        f["beneficiary"], f["total"] = r.acct(), str(r.u128())
        kind(r, f)
        f["cancelable"], f["transferable"] = str(r.boolean()).lower(), str(r.boolean()).lower()
        f["cancel_authority"], f["milestone_authority"] = opt_acct(r), opt_acct(r)
        no_broker(r)
    elif v == 3:
        name = "BatchCreate"
        r.take(32)  # batch id
        f["asset"] = asset(r)
        r.take(64)
        no_broker(r)
        items, flags = [], set()
        for _ in range(r.u32()):
            g = {"beneficiary": r.acct(), "total": str(r.u128())}
            kind(r, g)
            flags.add((r.boolean(), r.boolean()))
            opt_acct(r); opt_acct(r)
            items.append(":".join([g["beneficiary"], g["total"], g["kind"]] + ([g["cliff_amount"]] if "cliff_amount" in g else [])))
        f["items"] = ",".join(items)
        if len(flags) == 1:
            c, t = flags.pop()
            f["cancelable"], f["transferable"] = str(c).lower(), str(t).lower()
    elif v == 4:
        name = "ClaimPublic"
        f["schedule"], f["destination"] = r.acct(), r.acct()
        a = r.option(lambda r: r.u128())
        f["amount"] = "all" if a is None else str(a)
    elif v == 5:
        name = "ClaimExact"
        f["schedule"], f["destination"], f["amount"] = r.acct(), r.acct(), str(r.u128())
        r.u64()
    elif v in (6, 7):
        name = "Cancel" if v == 6 else "MakeNonCancelable"
        f["schedule"] = r.acct()
    elif v == 8:
        name = "SignalMilestone"
        f["schedule"], f["index"] = r.acct(), str(r.u8())
    elif v == 9:
        name = "TransferBeneficiary"
        f["schedule"], f["to"] = r.acct(), r.acct()
    else:
        raise ValueError(f"Escapement message {v} (not one this run sent)")
    r.end(name)
    return "escapement." + name, f


def decode_call(root):
    """(call name, fields) of a root call (program, message)."""
    (account, program), msg = root
    r = Reader(msg)
    if program == ESCAPEMENT:
        return escapement_message(msg)
    if program == LOADER:
        t = r.u8()
        if t == 0:
            n = len(r.bytes_vec())
            nxt = r.option(lambda r: r.acct())
            r.end("WriteSegment")
            return "loader.WriteSegment", {"bytes": str(n), "next_segment": nxt or "none"}
        if t == 1:
            first = r.acct()
            imm = r.boolean()
            r.end("CreateHeader")
            return "loader.CreateHeader", {"first_segment": first, "immutable": str(imm).lower()}
    if program == NATIVE and r.u8() == 0:
        to, amount = r.acct(), r.u128()
        r.end("native transfer")
        return "native.Transfer", {"to": to, "amount": str(amount)}
    if program == TOKEN:
        t = r.u8()
        if t == 0:
            r.take(r.u32())  # the definition's name
            return "token.NewDefinition", {"supply": str(r.u128())}
        if t == 1:
            d = r.acct()
            r.end("InitHolding")
            return "token.InitHolding", {"definition": d}
    return f"unknown:{program}", {}


# The CLI command a step name records, and the call it must have made (first match wins).
STEP_CALLS = [
    (r"^\d+-batch-create", {"escapement.BatchCreate"}),
    (r"private-claim-confirm", {"escapement.ClaimExact"}),
    (r"token-definition", {"token.NewDefinition"}),
    (r"token-holding", {"token.InitHolding"}),
    (r"^\d+-(faucet|fund)", {"native.Transfer"}),
    (r"^\d+-deploy", {"loader.WriteSegment", "loader.CreateHeader", "admin.Init"}),
    (r"^\d+-configure", {"escapement.Configure"}),
    (r"^\d+-(refused-)?create", {"escapement.CreateSchedule"}),
    (r"make-non-cancelable", {"escapement.MakeNonCancelable"}),
    (r"^\d+-(refused-)?(second-)?signal", {"escapement.SignalMilestone"}),
    (r"^\d+-(refused-)?(over)?claim", {"escapement.ClaimPublic"}),
    (r"^\d+-(refused-)?transfer", {"escapement.TransferBeneficiary"}),
    (r"^\d+-(refused-)?cancel", {"escapement.Cancel"}),
]


def step_calls(step):
    return next((calls for pat, calls in STEP_CALLS if re.search(pat, step)), set())


def schedule(raw):
    """The fields of an Escapement schedule's state (escapement-core `ScheduleAccount`, after its enum tag)."""
    r = Reader(raw)
    if r.u8() != 0:
        raise ValueError("not a schedule")
    r.u8()  # version
    r.take(32)  # asset program
    f = {"creator": r.acct(), "beneficiary": r.acct(), "asset": asset(r)}
    r.take(32)  # escrow seed
    escrow = r.acct()
    r.take(32)  # refund holding
    total, claimed = r.u128(), r.u128()
    k = {}
    kind(r, k)
    f.update({"kind": k["kind"], "total": str(total), "claimed": str(claimed)})
    f["cancelable"], f["transferable"] = str(r.boolean()).lower(), str(r.boolean()).lower()
    f["cancel_authority"], f["milestone_authority"] = opt_acct(r), opt_acct(r)
    c = r.option(lambda r: (r.u64(), r.u128(), r.u128()))
    r.end("schedule")
    f["cancelled"] = "none" if c is None else f"{c[1]}/{c[2]}"
    owed = (c[1] if c else total) - claimed  # what the escrow still owes this schedule
    return f, escrow, owed


def config_state(raw):
    r = Reader(raw)
    f = {"token_program": opt_acct(r), "fee_bps": str(r.u16()), "treasury": opt_acct(r)}
    if r.u8() == 1:
        f["admin"] = r.acct()
    return f


def rows(name):
    with open(os.path.join(DATA, name)) as f:
        lines = [x.rstrip("\n").split("\t") for x in f if x.strip() and not x.startswith("#")]
    head = lines[0]
    for x in lines[1:]:
        if len(x) != len(head):
            raise ValueError(f"{name}: a row with {len(x)} columns, not {len(head)}")
    return [dict(zip(head, x)) for x in lines[1:]]


def structure(tx_rows, acct_rows, escrows):
    """Problems with the evidence set itself: the counts network.json pins, rows numbered 0..N-1, no hash, account or
    name twice. (The script checks this committed set of records, not every transaction the network ever carried.)"""
    want, problems = NETWORK["records"], []
    if len(tx_rows) != want["transactions"]:
        problems.append(f"{len(tx_rows)} transactions recorded, network.json pins {want['transactions']}")
    if [t["n"] for t in tx_rows] != [str(i) for i in range(len(tx_rows))]:
        problems.append("the transactions are not numbered 0, 1, 2, ... in order")
    if len({t["hash"] for t in tx_rows}) != len(tx_rows):
        problems.append("a transaction hash is recorded twice")
    if len(acct_rows) != want["accounts"]:
        problems.append(f"{len(acct_rows)} accounts recorded, network.json pins {want['accounts']}")
    if len({a["account"] for a in acct_rows}) != len(acct_rows) or len({a["name"] for a in acct_rows}) != len(acct_rows):
        problems.append("an account or a name is recorded twice")
    if escrows is not None and escrows != want["native_escrows"]:
        problems.append(f"{escrows} native escrows checked, network.json pins {want['native_escrows']}")
    return problems


def kv(s):
    return dict(x.split("=", 1) for x in s.split(";") if x)


SCHEDULE_KEYS = {"creator", "beneficiary", "asset", "kind", "total", "claimed", "cancelable", "transferable",
                 "cancel_authority", "milestone_authority", "cancelled"}


TX_CACHE, BLOCKS = {}, {}


def check_tx(t):
    """(problems, extra text, (tx, call name, fields)) for one row of transactions.tsv."""
    problems, extra, dec = [], "", None
    try:
        if t["outcome"] not in ("applied", "refused"):
            raise ValueError(f"outcome {t['outcome']!r}")
        if t["hash"] not in TX_CACHE:
            TX_CACHE[t["hash"]] = call("getTransaction", [t["hash"]])
        value, at = TX_CACHE[t["hash"]]
        tx = transaction(Reader(base64.b64decode(value)))
        if tx["hash"] != t["hash"]:
            problems.append(f"content hashes to {tx['hash']}")
        if at != int(t["block"]):
            problems.append(f"in block {at}, recorded {t['block']}")
        if at not in BLOCKS:
            BLOCKS[at] = block(base64.b64decode(call("getBlock", [at])))
        b, i = BLOCKS[at], int(t["index"])
        if b["id"] != at or not b["hash_ok"]:
            problems.append(f"block {at} does not hash to its header")
        if i >= len(b["txs"]) or b["txs"][i]["hash"] != t["hash"]:
            problems.append(f"not at index {i} of block {at}")
        if (i in b["reverted"]) != (t["outcome"] == "refused"):
            problems.append(f"outcome {'refused' if i in b['reverted'] else 'applied'}, recorded {t['outcome']}")
        if tx["kind"] != t["kind"]:
            problems.append(f"a {tx['kind']} transaction, recorded {t['kind']}")
        name, fields = decode_call(tx["root"]) if tx["root"] else ("none", {})
        dec = (tx, name, fields)
        if name != t["call"]:
            problems.append(f"calls {name}, recorded {t['call']}")
        if name not in step_calls(t["step"]):
            problems.append(f"step {t['step']} does not make {name}")
        if t["root"] and tx["root"] and tx["root"][0][0] != t["root"]:
            problems.append(f"rooted at {tx['root'][0][0]}, recorded {t['root']}")
        if t["signed_by"] not in tx["signers"]:
            problems.append(f"signed by {tx['signers']}, recorded {t['signed_by']}")
        for k, v in kv(t["expect"]).items():
            got = str(tx["gas"]) if k == "gas" else fields.get(k)
            if got != v:
                problems.append(f"{k} is {got}, recorded {v}")
        if tx["kind"] == "private":
            variant = RECEIPTS.get(tx["proof"][0] if tx["proof"] else -1, "none")
            if variant not in ("composite", "succinct", "groth16"):
                problems.append(f"its receipt is {variant}, not a real proof")
            if f"{variant}:{len(tx['proof'])}" != t["proof"]:
                problems.append(f"receipt {variant}:{len(tx['proof'])}, recorded {t['proof']}")
            if (fields.get("schedule"), ESCAPEMENT) not in tx["actors"]:
                problems.append("the schedule is not among its actors")
            extra = f", {variant} proof {len(tx['proof']):,} B"
    except Exception as e:  # noqa: BLE001 (one line per transaction, whatever went wrong)
        problems.append(f"{type(e).__name__}: {e}")
    return problems, extra, dec


def mutated(rows_by_n):
    """Wrong records that must each fail: one per kind of claim this script makes about a transaction."""
    def m(n, what, **change):
        t = dict(rows_by_n[n])
        for k, v in change.items():
            t[k] = v(t) if callable(v) else v
        return what, t
    def expect(**kw):
        return lambda t: ";".join(f"{k}={kw.get(k, v)}" for k, v in kv(t["expect"]).items())
    a, b = rows_by_n["7"], rows_by_n["12"]
    return [
        m("22", "a claim's amount", expect=expect(amount="20000001")),
        m("22", "a claim's destination", expect=expect(destination=rows_by_n["26"]["root"])),
        m("22", "the account a claim is rooted at", root=rows_by_n["26"]["root"]),
        m("22", "the account that signed", signed_by=rows_by_n["26"]["root"]),
        m("22", "the operation", call="escapement.Cancel"),
        m("44", "a batch recipient's total", expect=lambda t: t["expect"].replace(":40000000:", ":40000001:")),
        m("19", "a schedule's milestone authority", expect=expect(milestone_authority=rows_by_n["22"]["root"])),
        m("12", "the configured fee", expect=expect(fee_bps="1")),
        m("23", "a refusal's outcome", outcome="applied"),
        m("23", "a refusal's gas limit", expect=expect(gas="999999")),
        m("64", "the private claim's receipt (dev mode's)", proof="fake:237142"),
        m("64", "the private claim's amount", expect=expect(amount="50000001")),
        ("two rows' operations swapped", dict(a, step=b["step"], call=b["call"], root=b["root"], signed_by=b["signed_by"], expect=b["expect"])),
    ]


NONCES = {}


def completeness(tx_rows, decoded):
    """Problems if the records miss a transaction: every account that signed a recorded transaction (the faucet's,
    which the network uses for everyone, aside) must have an on-chain nonce equal to the number of recorded
    transactions it signed, counted from the transactions' own witnesses."""
    faucet = {t["signed_by"] for t in tx_rows if t["step"].startswith("00-faucet")}
    signed = {}
    for t in tx_rows:
        dec = decoded.get(t["n"])
        for a in set(dec[0]["signers"]) if dec else ():
            signed[a] = signed.get(a, 0) + 1
    problems = []
    for a, n in sorted(signed.items()):
        if a in faucet:
            continue
        if a not in NONCES:
            NONCES[a] = int((call("getAccount", [a]) or {}).get("nonce", -1))
        if NONCES[a] != n:
            problems.append(f"{a} has signed {NONCES[a]} transactions on chain, {n} recorded")
    return problems, len([a for a in signed if a not in faucet])


def main():
    print(f"RPC {RPC}\nexplorer {EXPLORER}")
    failed, blocks, decoded = 0, BLOCKS, {}

    def report(ok, text, problems):
        nonlocal failed
        failed += not ok
        print(("ok   " if ok else "FAIL ") + text + ("" if ok else "\n       " + "; ".join(problems)))

    for t in rows("transactions.tsv"):
        problems, extra, dec = check_tx(t)
        if dec:
            decoded[t["n"]] = dec
        report(not problems, f"{t['n']:>3} {t['step']:<46} {t['call']:<31} block {t['block']:>6} {t['outcome']:<7}"
               f"{extra}  {EXPLORER}#/tx/{t['hash']}", problems)

    # Deployments: the segments, written tail first, point each to the next; the header to the first.
    for step in sorted({t["step"] for t in rows("transactions.tsv") if re.match(r"^\d+-deploy-", t["step"])}):
        problems = []
        group = [decoded.get(t["n"]) for t in rows("transactions.tsv") if t["step"] == step]
        if None in group:
            problems.append("a transaction of it was not decoded")
        else:
            segs = [(tx["root"][0][0], f) for tx, name, f in group if name == "loader.WriteSegment"]
            head = [(tx["root"][0][0], f) for tx, name, f in group if name == "loader.CreateHeader"]
            want_next = "none"
            for account, f in segs:
                if f["next_segment"] != want_next:
                    problems.append(f"segment {account} points to {f['next_segment']}, not {want_next}")
                want_next = account
            if len(head) != 1 or head[0][1]["first_segment"] != want_next or head[0][1]["immutable"] != "true":
                problems.append("the header does not point to the first segment, immutable")
        n = sum(1 for g in group if g and g[1].startswith("loader."))
        report(not problems, f"    {step}: {n} loader transactions, the segments chained tail first, the header on the "
               f"first, immutable", problems)

    problems, accounts = completeness(rows("transactions.tsv"), decoded)
    report(not problems, f"    complete: each of the {accounts} accounts that signed has exactly its recorded transactions on chain "
           f"(its nonce)", problems)

    linked = [n for n in blocks if n + 1 in blocks]
    problems = [f"block {n + 1}'s parent is not block {n}" for n in linked if blocks[n + 1]["parent"] != blocks[n]["hash"]]
    report(not problems, f"    {len(blocks)} blocks fetched, {len(linked)} consecutive pairs linked by their parent hashes", problems)

    escrows = {}
    for a in rows("accounts.tsv"):
        problems = []
        try:
            acct = call("getAccount", [a["account"]])
            states = (acct or {}).get("data", {}).get("actor_states", {})
            check = a["check"].split()
            if check[0] == "program":
                if check[1] == "image-ids.tsv":
                    line = next(x for x in open(os.path.join(ROOT, "image-ids.tsv")) if x.startswith("escapement\t"))
                    image = bytes.fromhex(line.split("\t")[1])
                else:
                    image = bytes.fromhex(check[1])
                header = bytes(states.get(LOADER, []))
                if len(header) != 66 or header[0] != 0:
                    problems.append(f"its loader state is not a program header ({len(header)} B)")
                if header[1:33] != image:
                    problems.append("its program header does not carry image id " + image.hex())
                if not header or header[-1] != 1:
                    problems.append("its program header is not immutable")
            elif check[0] == "config":
                got = config_state(states.get(ESCAPEMENT, []))
                for k, v in kv(";".join(check[1:])).items():
                    if got.get(k) != v:
                        problems.append(f"{k} is {got.get(k)}, recorded {v}")
            elif check[0] == "schedule":
                want = kv(";".join(check[1:]))
                if set(want) != SCHEDULE_KEYS:
                    raise ValueError(f"the record does not give {sorted(SCHEDULE_KEYS - set(want))}")
                got, escrow, owed = schedule(states.get(ESCAPEMENT, []))
                for k, v in want.items():
                    if got.get(k) != v:
                        problems.append(f"{k} is {got.get(k)}, recorded {v}")
                if got["asset"] == "native":
                    escrows.setdefault(escrow, []).append((a["name"], owed))
            elif check[0] == "exists":
                if not states:
                    problems.append("no state")
            else:
                raise ValueError(f"check {check[0]!r}")
        except Exception as e:  # noqa: BLE001
            problems.append(f"{type(e).__name__}: {e}")
        report(not problems, f"{a['name']:<40} {a['account']}  {a['check'].split()[0]}  {EXPLORER}#/account/{a['account']}", problems)

    problems = structure(rows("transactions.tsv"), rows("accounts.tsv"), len(escrows))
    report(not problems, f"    the evidence set: {NETWORK['records']['transactions']} transactions numbered in order, "
           f"{NETWORK['records']['accounts']} accounts and {NETWORK['records']['native_escrows']} native escrows, "
           f"as network.json pins, none twice", problems)

    for escrow, owed in sorted(escrows.items()):
        problems = []
        try:
            bal = int(call("getAccountBalance", [escrow]))
            if bal != sum(o for _, o in owed):
                problems.append(f"holds {bal:,}, its schedules are owed {sum(o for _, o in owed):,}")
        except Exception as e:  # noqa: BLE001
            problems.append(f"{type(e).__name__}: {e}")
        report(not problems, f"native escrow {escrow} holds what {len(owed)} schedule(s) are owed: "
               f"{sum(o for _, o in owed):,}", problems)

    # The host's records (private-claim.json, refusals.json) must describe these same transactions.
    txs = {t["hash"]: t for t in rows("transactions.tsv")}
    problems = []
    try:
        pc = json.load(open(os.path.join(DATA, "private-claim.json")))
        c = pc["confirm"]
        row = txs.get(c["tx"]["hash"])
        tx, name, fields = decoded.get(row["n"]) if row else (None, None, {})
        if not row or row["kind"] != "private":
            problems.append("its transaction is not the private row of transactions.tsv")
        elif c["proof_bytes"] != len(tx["proof"]) or c["amount"] != fields.get("amount") or c["dev_mode"] is not False:
            problems.append("its proof size, amount or dev_mode does not match the chain")
    except Exception as e:  # noqa: BLE001
        problems.append(f"private-claim.json: {type(e).__name__}: {e}")
    report(not problems, "    private-claim.json describes the private transaction on chain (proof size, amount, not dev mode)", problems)
    problems = []
    try:
        ref = json.load(open(os.path.join(DATA, "refusals.json")))["refusals"]
        refused = {h for h, t in txs.items() if t["outcome"] == "refused"}
        if {x["tx"]["hash"] for x in ref} != refused:
            problems.append("its transactions are not the refused rows")
        clock = {"clock_ms", "claimable_now", "next_unlock_ms", "next_unlock_utc", "reason"}
        for x in ref:
            before, after = ({k: v for k, v in x[s].items() if k not in clock} for s in ("schedule_before", "schedule_after"))
            if before != after:
                problems.append(f"{x['step']}: the schedule changed")
            row = txs.get(x["tx"]["hash"])
            if not row or kv(row["expect"]).get("schedule") != x["schedule_before"].get("schedule"):
                problems.append(f"{x['step']}: its schedule is not the one its transaction names")
    except Exception as e:  # noqa: BLE001
        problems.append(f"refusals.json: {type(e).__name__}: {e}")
    report(not problems, f"    refusals.json: the {len(ref) if not problems else '?'} refused transactions, each schedule unchanged", problems)

    if "--self-test" in sys.argv[1:]:
        by_n = {t["n"]: t for t in rows("transactions.tsv")}
        for what, t in mutated(by_n):
            problems = check_tx(t)[0]
            report(bool(problems), f"    self-test: a wrong record of {what} fails ({problems[0] if problems else 'it passed'})",
                   ["a wrong record passed"])
        accts = rows("accounts.tsv")
        problems = structure(rows("transactions.tsv"), [a for a in accts if a["name"] != "schedule: native transferable"], None)
        report(bool(problems), f"    self-test: records missing a schedule's account fail ({problems[0] if problems else 'they passed'})",
               ["records missing an account passed"])
        problems = completeness([t for t in rows("transactions.tsv") if t["n"] != "30"], decoded)[0]
        report(bool(problems), f"    self-test: records missing a transaction (row 30) fail ({problems[0] if problems else 'they passed'})",
               ["records missing a transaction passed"])

    print("all checks passed" if not failed else f"{failed} FAILED")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
