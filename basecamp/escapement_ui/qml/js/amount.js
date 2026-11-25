.pragma library
// Amounts and times for the Escapement view, without floating point: an amount the person types in display units
// ("1.5") becomes a whole number of base units as a decimal string ("1500000000" at 9 decimals) by string arithmetic
// alone, and back. The module takes and returns base units as strings, so no amount ever passes through a JS number.

// "1.5" at `decimals` -> "1500000000"; throws a plain message when the text is not an amount.
function toBase(text, decimals) {
    var t = String(text === undefined || text === null ? "" : text).trim();
    if (t === "") throw "enter an amount";
    if (!/^[0-9]*\.?[0-9]*$/.test(t) || t === ".") throw "\"" + t + "\" is not an amount: use digits and at most one decimal point (no signs or exponents)";
    var parts = t.split(".");
    var whole = parts[0] || "0";
    var frac = parts.length > 1 ? parts[1] : "";
    if (frac.length > decimals) throw "at most " + decimals + " digits after the decimal point";
    while (frac.length < decimals) frac += "0";
    var s = (whole + frac).replace(/^0+/, "");
    if (s === "") s = "0";
    // u128 at most: 39 digits, and compared as a string at 39.
    var max = "340282366920938463463374607431768211455";
    if (s.length > max.length || (s.length === max.length && s > max)) throw "the amount is too large";
    return s;
}

// "1500000000" base units at `decimals` -> "1.5".
function fromBase(base, decimals) {
    var s = String(base === undefined || base === null ? "0" : base).trim();
    if (!/^[0-9]+$/.test(s)) return "?";
    s = s.replace(/^0+/, "");
    if (decimals <= 0) return s === "" ? "0" : s;
    while (s.length <= decimals) s = "0" + s;
    var whole = s.slice(0, s.length - decimals);
    var frac = s.slice(s.length - decimals).replace(/0+$/, "");
    return frac === "" ? whole : whole + "." + frac;
}

function isZero(base) {
    return /^0*$/.test(String(base === undefined || base === null ? "" : base).trim());
}

// A time the person types -> unix milliseconds: "now", "+30m", "+2h", "+7d" (from `nowMs`), or a UTC date
// "2026-12-01 09:30" / "2026-12-01T09:30:00". Throws a plain message otherwise.
function parseWhen(text, nowMs) {
    var t = String(text === undefined || text === null ? "" : text).trim().toLowerCase();
    if (t === "" || t === "now") return nowMs;
    var rel = /^\+\s*([0-9]+)\s*(s|m|h|d)$/.exec(t);
    if (rel) {
        var unit = { s: 1000, m: 60000, h: 3600000, d: 86400000 }[rel[2]];
        var n = parseInt(rel[1], 10), ms = nowMs + n * unit;
        // Only exact integers (review R2, Kimi L2): no rounding, no overflow, no infinities.
        if (!Number.isSafeInteger(nowMs) || !Number.isSafeInteger(n) || !Number.isSafeInteger(n * unit) || !Number.isSafeInteger(ms))
            throw "\"" + text + "\" is too far in the future";
        return ms;
    }
    var abs = /^([0-9]{4})-([0-9]{2})-([0-9]{2})[ t]([0-9]{2}):([0-9]{2})(?::([0-9]{2}))?(?:z| ?utc)?$/.exec(t);
    if (abs) {
        var y = +abs[1], mo = +abs[2], d = +abs[3], h = +abs[4], mi = +abs[5], se = abs[6] ? +abs[6] : 0;
        var ms = Date.UTC(y, mo - 1, d, h, mi, se);
        var back = new Date(ms);
        // Date.UTC rolls over (31 February is 3 March): a date that does not come back as typed is refused.
        if (isNaN(ms) || back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d
                || back.getUTCHours() !== h || back.getUTCMinutes() !== mi || back.getUTCSeconds() !== se)
            throw "\"" + text + "\" is not a date";
        return ms;
    }
    throw "\"" + text + "\": use now, +30m, +2h, +7d, or a UTC time like 2026-12-01 09:30";
}

// Why a prompt from the module may not be shown, or "": its amounts must be in the units this view converted with
// (review R1 M1), and it must name them.
function promptProblem(summary, decimals, unit) {
    if (!summary || typeof summary !== "object") return "The module's answer is not a transaction to approve.";
    if (summary.decimals !== decimals || summary.unit !== unit)
        return "Not shown: the module prepared this in " + summary.unit + " with " + summary.decimals + " decimals, but this view converted your amount with "
            + unit + " and " + decimals + " decimals. Nothing was signed; it was rejected. Refresh and try again.";
    if (!summary.pending_id || !summary.rows || !summary.title) return "The module's answer is not a transaction to approve.";
    return "";
}

// unix ms -> "2026-12-01 09:30:00 UTC"
function utc(ms) {
    if (ms === undefined || ms === null || ms === "") return "—";
    var d = new Date(Number(ms));
    function p(n) { return (n < 10 ? "0" : "") + n; }
    return d.getUTCFullYear() + "-" + p(d.getUTCMonth() + 1) + "-" + p(d.getUTCDate()) + " " + p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + ":" + p(d.getUTCSeconds()) + " UTC";
}

// A long account id shortened for a row: first 6 and last 4 characters.
function short(id) {
    var s = String(id || "");
    return s.length > 14 ? s.slice(0, 6) + "…" + s.slice(-4) : s;
}

// The module's error text, made plain: the host's wrapper and transport details moved to a second line.
function plain(err) {
    var s = String(err === undefined || err === null ? "" : err);
    if (/did not answer|connection refused|Connection refused|timed out/i.test(s))
        return "The sequencer did not answer. Check that it is running and that the address under Network is right.\n" + s;
    if (/no network is set/i.test(s)) return "Connect to a network first (Network, above).";
    if (/no key/i.test(s)) return "Choose a key first: a key file, or a new key (Account, above).";
    return s;
}
