// node basecamp/escapement_ui/tests/amount.test.mjs: the view's amount and time helpers (qml/js/amount.js).
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
const src = readFileSync(new URL("../qml/js/amount.js", import.meta.url), "utf8").replace(/^\.pragma library\s*$/m, "");
const A = new Function(src + "; return { toBase, fromBase, isZero, parseWhen, utc, short, plain, promptProblem };")();
const bad = (f) => assert.throws(f);
assert.equal(A.toBase("1.5", 9), "1500000000");
assert.equal(A.toBase("0.000000001", 9), "1");
assert.equal(A.toBase("90", 9), "90000000000");
assert.equal(A.toBase(".5", 9), "500000000");
assert.equal(A.toBase("0", 9), "0");
assert.equal(A.toBase("340282366920938463463374607431.768211455", 9), "340282366920938463463374607431768211455");
bad(() => A.toBase("340282366920938463463374607431.768211456", 9));
bad(() => A.toBase("1.0000000001", 9));
bad(() => A.toBase("-1", 9)); bad(() => A.toBase("1e9", 9)); bad(() => A.toBase("1.2.3", 9)); bad(() => A.toBase("", 9)); bad(() => A.toBase(".", 9));
assert.equal(A.fromBase("1500000000", 9), "1.5");
assert.equal(A.fromBase("1", 9), "0.000000001");
assert.equal(A.fromBase("0", 9), "0");
assert.equal(A.fromBase("340282366920938463463374607431768211455", 9), "340282366920938463463374607431.768211455");
for (const t of ["1", "0.1", "123.456789", "0.000000001", "99999999999999999999.999999999"]) assert.equal(A.fromBase(A.toBase(t, 9), 9), t);
assert.equal(A.parseWhen("now", 1000), 1000);
assert.equal(A.parseWhen("+30m", 0), 1800000);
assert.equal(A.parseWhen("+2d", 5), 5 + 2 * 86400000);
assert.equal(A.parseWhen("2026-12-01 09:30", 0), Date.UTC(2026, 11, 1, 9, 30));
bad(() => A.parseWhen("tomorrow", 0));
assert.equal(A.utc(Date.UTC(2026, 11, 1, 9, 30, 5)), "2026-12-01 09:30:05 UTC");
assert.equal(A.short("AKRYNTU8c4MZ4fSr5FHcn6BGE6T4dfRCzn1ziQCNKFBu"), "AKRYNT…KFBu");
// Review R1 (Kimi L2): no separators in amounts.
bad(() => A.toBase("1_000", 9));
bad(() => A.toBase("1,5", 9));
// Review R1 nit: an impossible date is refused, not rolled over.
bad(() => A.parseWhen("2026-02-31 09:30", 0));
bad(() => A.parseWhen("2026-13-01 09:30", 0));
bad(() => A.parseWhen("2026-12-01 24:00", 0));
assert.equal(A.parseWhen("2028-02-29 00:00", 0), Date.UTC(2028, 1, 29));
// Review R2 (Kimi L2): relative times stay exact integers.
bad(() => A.parseWhen("+99999999999999999999d", 0));
bad(() => A.parseWhen("+9007199254740991s", 0));
bad(() => A.parseWhen("+1d", Number.MAX_SAFE_INTEGER));
bad(() => A.parseWhen("+1d", Infinity));
assert.equal(A.parseWhen("+3650d", 1795600000000), 1795600000000 + 3650 * 86400000);
// Review R1 M1: a prompt is shown only in the units the view converted the amount with.
const good = { pending_id: "p", rows: [["Claim", "1 LEZ (1000000000 base units)"]], title: "Claim", decimals: 9, unit: "LEZ" };
assert.equal(A.promptProblem(good, 9, "LEZ"), "");
assert.match(A.promptProblem({ ...good, decimals: 12 }, 9, "LEZ"), /12 decimals.*Nothing was signed/);
assert.match(A.promptProblem({ ...good, unit: "XYZ" }, 9, "LEZ"), /XYZ/);
assert.notEqual(A.promptProblem({ ...good, decimals: undefined }, 9, "LEZ"), "");
assert.notEqual(A.promptProblem(null, 9, "LEZ"), "");
console.log("amount.js: all checks passed");
