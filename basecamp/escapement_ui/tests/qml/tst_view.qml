// The view's tests (Qt Quick Test): `qmltestrunner -input basecamp/escapement_ui/tests/qml` with QT_QPA_PLATFORM=offscreen.
// The view is loaded as Basecamp loads it; a stand-in for Logos's bridge (`fake`) answers its calls and records them.
// Review R1 findings: M4 (text from the module or the sequencer rendered as rich text), L3 (a failed reject shown as
// success), M1 (a prompt shown in other units than the amount was converted with).
import QtQuick
import QtTest
import "../../qml" as App

Item {
    id: top
    width: 1200
    height: 900

    App.Main {
        id: view
        anchors.fill: parent
    }

    // `slow`: answers come later (Qt.callLater), as Basecamp's bridge does, so refreshes land after the call's own
    // handling (review R2 M1).
    QtObject {
        id: fake
        property var replies: ({})
        property var calls: []
        property bool slow: false
        function callModuleAsync(module, method, args, done, timeoutMs) {
            calls.push(method);
            var r = replies[method] !== undefined ? replies[method] : { ok: true };
            if (slow)
                Qt.callLater(function () { done(JSON.stringify(r)); });
            else
                done(JSON.stringify(r));
        }
    }

    // A Qt Quick Controls part: a button's or check box's label (under an AbstractButton, which has `icon`) or a text
    // field's placeholder. Their text is the static text written in Main.qml, never the module's or the sequencer's.
    function controlPart(item) {
        for (var a = item.parent, i = 0; a && a !== view && i < 3; a = a.parent, i++)
            if (a.placeholderText !== undefined || (a.icon !== undefined && a.pressed !== undefined))
                return true;
        return false;
    }

    // Every Text item the view declares under `item` (Text and Label have textFormat and lineCount; TextEdit also has a
    // cursor), without the controls' own parts.
    function texts(item, out) {
        if (item.textFormat !== undefined && item.lineCount !== undefined && item.cursorPosition === undefined && !controlPart(item))
            out.push(item);
        for (var i = 0; i < item.children.length; i++)
            texts(item.children[i], out);
        return out;
    }

    // Whether a visible Text under `item` shows `needle` (wherever the view puts it).
    function shown(item, needle) {
        var all = texts(item, []);
        for (var i = 0; i < all.length; i++)
            if (all[i].visible && String(all[i].text).indexOf(needle) >= 0)
                return true;
        return false;
    }

    TestCase {
        name: "EscapementViewR1"
        when: windowShown

        function init() {
            try { view.backend = fake; } catch (e) { console.log("no backend seam in this view: " + e); }
            fake.calls = [];
            fake.replies = {};
            fake.slow = false;
            try { view.lastTx = null; } catch (e) {}
            view.pending = null;
            view.errorText = "";
            view.noticeText = "";
        }

        function test_m4_text_is_plain_everywhere_including_the_prompt() {
            view.pending = { pending_id: "p", title: "<b>Claim</b>", rows: [["<i>Claim</i>", "1 LEZ<font color='white'> hidden</font>"]],
                             effects: ["<img src='http://127.0.0.1:9/x.png'>"], expires_in_s: 300, decimals: 9, unit: "LEZ" };
            view.errorText = "<h1>error</h1>";
            view.noticeText = "<b>notice</b>";
            wait(50);
            var all = texts(view, []);
            verify(all.length > 20, "Text items found: " + all.length);
            var bad = [];
            for (var i = 0; i < all.length; i++)
                if (all[i].textFormat !== Text.PlainText)
                    bad.push(String(all[i].text).slice(0, 40));
            compare(bad.length, 0, "Text items that may render markup: " + bad.join(" | "));
        }

        function test_l3_a_failed_reject_keeps_the_prompt() {
            view.pending = { pending_id: "p1", title: "Claim 1 LEZ (1000000000 base units)", rows: [["Claim", "1 LEZ (1000000000 base units)"]],
                             effects: [], expires_in_s: 300, decimals: 9, unit: "LEZ" };
            fake.replies = { reject: { ok: false, error: "the module could not drop it" } };
            view.rejectPending();
            verify(view.pending !== null, "the prompt must stay when reject failed");
            verify(view.errorText.indexOf("could not drop it") >= 0, "the error is shown: " + view.errorText);
            verify(view.noticeText.indexOf("Rejected") < 0, "no success notice: " + view.noticeText);
            fake.replies = { reject: { ok: true, rejected: "p1", signed: false } };
            view.rejectPending();
            compare(view.pending, null);
            verify(view.noticeText.indexOf("Rejected") >= 0, view.noticeText);
        }

        function test_m1_a_prompt_in_other_units_is_not_shown() {
            fake.replies = { prepare_claim: { ok: true, pending_id: "p2", title: "Claim 10 LEZ", rows: [["Claim", "10 LEZ"]], effects: [],
                                              expires_in_s: 300, decimals: 12, unit: "LEZ" } };
            view.prepareClaim("SCHEDULE", "10");
            compare(view.pending, null, "a prompt in 12 decimals must not be shown to a view that converted with " + view.decimals);
            verify(view.errorText.indexOf("12 decimals") >= 0, view.errorText);
            verify(fake.calls.indexOf("reject") >= 0, "and it is rejected in the module: " + fake.calls.join(","));
        }

        // Kimi L1: a reject the module answers without naming this transaction is not a rejection.
        function test_kimi_l1_a_reject_that_names_no_transaction_is_not_success() {
            view.pending = { pending_id: "p9", title: "Claim 1 LEZ (1000000000 base units)", rows: [["Claim", "1 LEZ (1000000000 base units)"]],
                             effects: [], expires_in_s: 300, decimals: 9, unit: "LEZ" };
            fake.replies = { reject: { ok: true, rejected: null, signed: false } };
            view.rejectPending();
            verify(view.noticeText.indexOf("Rejected") < 0, "no success notice: " + view.noticeText);
            verify(view.errorText.indexOf("no longer held") >= 0, view.errorText);
        }

        // Kimi M6: a transaction whose outcome the module could not establish is shown as unknown, with its hash.
        function test_kimi_m6_an_unknown_outcome_is_shown_with_its_hash() {
            view.pending = { pending_id: "p8", title: "Claim 1 LEZ (1000000000 base units)", rows: [["Claim", "1 LEZ (1000000000 base units)"]],
                             effects: [], expires_in_s: 300, decimals: 9, unit: "LEZ" };
            fake.replies = { approve: { ok: true, state: "unknown", tx_hash: "abc123def456", warning: "signed and sent, but the answer did not arrive" } };
            view.approvePending();
            var t = findChild(view, "escapement.opentx.text");
            verify(t !== null && t.text.indexOf("Outcome unknown") >= 0 && t.text.indexOf("abc123def456") >= 0, "the hash is shown: " + (t ? t.text : "no banner"));
            verify(view.noticeText.indexOf("Done") < 0, view.noticeText);
        }

        // R2 M1: after a lost send the refresh fails too (the sequencer is down) and answers later; the hash must stay
        // on screen, new transactions must be held, and Check must settle it once it is in a block.
        function test_r2_m1_an_unknown_outcome_survives_a_failing_slow_refresh() {
            var hash = "feedbeef00112233445566778899aabbccddeeff00112233445566778899aabb";
            fake.slow = true;
            fake.replies = {
                approve: { ok: true, state: "unknown", tx_hash: hash, warning: "signed and sent, but the sequencer's answer did not arrive" },
                status: { ok: true, account: "ACCT", network: { rpc_url: "http://127.0.0.1:3040", program: "PROG", read_only: false, asset_label: "LEZ", decimals: 9 } },
                schedules: { ok: false, error: "the sequencer at http://127.0.0.1:3040 did not answer" }
            };
            view.pending = { pending_id: "p7", title: "Create a schedule of 90 LEZ (90000000000 base units)", rows: [["Total", "90 LEZ (90000000000 base units)"]],
                             effects: [], expires_in_s: 300, decimals: 9, unit: "LEZ" };
            view.approvePending();
            wait(150);
            verify(fake.calls.indexOf("schedules") >= 0, "the refresh ran: " + fake.calls.join(","));
            verify(view.errorText.indexOf("did not answer") >= 0, "the refresh's own error is shown: " + view.errorText);
            verify(shown(view, hash), "the transaction's full hash is still on screen after the failed refresh");
            var banner = findChild(view, "escapement.opentx");
            var t = findChild(view, "escapement.opentx.text");
            verify(banner !== null && banner.visible, "the open-transaction banner is up");
            verify(t.text.indexOf(hash) >= 0, "the full hash is still on screen: " + t.text);
            compare(findChild(view, "escapement.create").enabled, false, "new transactions are held");
            fake.replies.tx_status = { ok: true, tx_hash: hash, state: "in_block", block: 12, outcome: { applied: true, detail: "the schedule exists and its escrow is funded" } };
            fake.replies.schedules = { ok: true, positions: [], created: [], clock_ms: 0, clock_utc: "", decimals: 9, asset_label: "LEZ" };
            view.checkTx();
            wait(150);
            verify(!banner.visible, "settled: the banner is gone");
            verify(view.noticeText.indexOf("Done") >= 0 && view.noticeText.indexOf("block 12") >= 0, view.noticeText);
        }

        // R2 (Kimi M1): the host's reply to approve is lost (a timeout); the module's record comes back through status
        // into the banner, the host's message stays, and Dismiss tells the module.
        function test_r2_kimi_a_lost_host_reply_is_recovered_from_the_module_record() {
            var hash = "c0ffee" + "00".repeat(29);
            fake.slow = true;
            fake.replies = {
                approve: { error: "timeout", message: "the call timed out" },
                status: { ok: true, account: "ACCT", unsettled: [{ tx_hash: hash, op: "claim", title: "Claim 1 LEZ (1000000000 base units) (public)",
                                                                   sent_utc: "2026-11-25 18:00:00 UTC" }] }
            };
            view.pending = { pending_id: "p5", title: "Claim 1 LEZ (1000000000 base units)", rows: [["Claim", "1 LEZ (1000000000 base units)"]],
                             effects: [], expires_in_s: 300, decimals: 9, unit: "LEZ" };
            view.approvePending();
            wait(150);
            verify(view.errorText.indexOf("timed out") >= 0, "the host's message stays: " + view.errorText);
            verify(shown(view, hash), "the recorded transaction's hash is on screen");
            verify(findChild(view, "escapement.opentx").visible);
            fake.replies.tx_status = { ok: true, tx_hash: hash, dismissed: true };
            fake.replies.status = { ok: true, account: "ACCT", unsettled: [] };
            view.dismissTx();
            wait(100);
            verify(fake.calls.indexOf("tx_status") >= 0, "the module is told: " + fake.calls.join(","));
            verify(!findChild(view, "escapement.opentx").visible);
        }

        // R2 L1 (view): a transaction the sequencer refused is shown as refused, with its hash, until checked.
        function test_r2_l1_a_refused_transaction_is_shown_as_refused() {
            fake.replies = { approve: { ok: true, state: "refused_by_sequencer", tx_hash: "0011aa", warning: "the sequencer refused it (nonce too low); it should not be in a block." } };
            view.pending = { pending_id: "p6", title: "Claim 1 LEZ (1000000000 base units)", rows: [["Claim", "1 LEZ (1000000000 base units)"]],
                             effects: [], expires_in_s: 300, decimals: 9, unit: "LEZ" };
            view.approvePending();
            var t = findChild(view, "escapement.opentx.text");
            verify(t !== null && t.text.indexOf("Refused by the sequencer") >= 0 && t.text.indexOf("0011aa") >= 0, t ? t.text : "no banner");
            fake.replies.tx_status = { ok: true, tx_hash: "0011aa", dismissed: true };
            view.dismissTx();
            verify(!findChild(view, "escapement.opentx").visible);
        }

        // Kimi M1: a token schedule's row is in its own base units, and cannot be claimed from the view.
        function test_kimi_m1_token_rows_cannot_be_claimed_here() {
            var amt = function (b) { return { base_units: b, display: b, unit: "base units of token TOKENDEF" }; };
            view.tab = 0;
            view.positions = [{ schedule: "TOKENSCHED", native: false, claimable_now: amt("500"), locked: amt("500"), claimed: amt("0"),
                                total: amt("1000"), vested: amt("500"), next_unlock_label: "accruing", status: "tokens are claimable now",
                                kind: { type: "linear", start_utc: "a", end_utc: "b" }, cancelled: null, cancelable: true }];
            wait(50);
            var b = findChild(view, "escapement.claim");
            verify(b !== null, "the claim button is there");
            compare(b.enabled, false, "a token schedule cannot be claimed from the view");
            var c = findChild(view, "escapement.claimable");
            verify(c.text.indexOf("base units of token") >= 0 && c.text.indexOf("LEZ") < 0, c.text);
            view.positions = [];
        }

        function test_m1_a_prompt_in_the_view_units_is_shown() {
            fake.replies = { prepare_claim: { ok: true, pending_id: "p3", title: "Claim 10 LEZ (10000000000 base units)",
                                              rows: [["Claim", "10 LEZ (10000000000 base units)"]], effects: [], expires_in_s: 300, decimals: 9, unit: "LEZ" } };
            view.prepareClaim("SCHEDULE", "10");
            verify(view.pending !== null, "the prompt is shown: " + view.errorText);
            compare(view.pending.pending_id, "p3");
        }
    }
}
