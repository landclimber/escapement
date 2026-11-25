// Escapement: the vesting mini-app for Logos Basecamp (ui_qml module, prototype, unaudited).
//
// Two views over `escapement_core_module`:
//   Recipient: the account's schedules (locked, claimable now, next unlock in UTC) and a public claim.
//   Creator:   one new schedule (native asset, linear or cliff + linear), the account's schedules, cancel.
// Every write is two calls: prepare_* (the module checks and builds it, nothing is signed) shows what will happen;
// only "Approve and sign" calls approve, which signs inside the module and sends. "Reject" drops it.
// Amounts: typed in display units, converted to base units by string arithmetic (js/amount.js); no floats.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "js/amount.js" as Amt

Rectangle {
    id: root
    objectName: "escapement.root"
    width: 1100
    height: 900
    color: "#f4f5f7"

    readonly property bool inLogos: typeof logos !== "undefined" && logos !== null
    // Where calls go: Logos's bridge inside Basecamp (`logos`); the view's tests set a stand-in with the same calls.
    property var backend: inLogos ? logos : null
    readonly property string moduleName: "escapement_core_module"
    property int moduleTimeoutMs: 60000
    property int busy: 0
    property string errorText: ""
    property string noticeText: ""
    property var network: null
    property string account: ""
    property string keySource: ""
    property var balance: null
    property int decimals: 9
    property string unit: "LEZ"
    property bool readOnly: false
    property var positions: []
    property var created: []
    property var unreadable: []
    property double clockMs: Date.now()
    property string clockUtc: ""
    property var pending: null
    property var lastTx: null
    // A transaction the module signed whose outcome is not settled (sent, unknown, refused by the sequencer). It has
    // its own banner, bound to lastTx and not to the error line, so no later refresh or error can hide its hash; new
    // transactions are held until Check finds it in a block or the person dismisses it (review R2 M1).
    readonly property bool openTx: lastTx !== null && lastTx !== undefined && lastTx.state !== "in_block"
    property int tab: 0
    property var callLog: []

    // ---- the module --------------------------------------------------------------------------------------------
    function call(method, req, done) {
        busy += 1;
        var t0 = Date.now();
        var finish = function (ok, value) {
            busy -= 1;
            callLog.push({ method: method, ok: ok, ms: Date.now() - t0 });
            if (!ok) errorText = Amt.plain(value);
            if (done) done(ok, value);
        };
        if (!backend) { finish(false, "This view runs inside Logos Basecamp: escapement_core_module is not reachable here."); return; }
        var args = (req === null) ? [] : [JSON.stringify(req || {})];
        try {
            if (typeof backend.callModuleAsync === "function")
                backend.callModuleAsync(moduleName, method, args, function (payload) { moduleReply(payload, finish); }, moduleTimeoutMs);
            else
                moduleReply(backend.callModule(moduleName, method, args), finish);
        } catch (e) {
            finish(false, moduleName + ": " + e);
        }
    }

    // The reply as the host hands it over: the object, its JSON text, or that text serialised once more (Basecamp's
    // bridge); a host error ({error, message}) is reported as the host's, a timeout as an unknown outcome.
    function moduleReply(raw, finish) {
        var r = raw;
        try {
            for (var i = 0; i < 3 && typeof r === "string"; i++) r = JSON.parse(r);
        } catch (e) {
            finish(false, moduleName + ": unreadable reply: " + String(raw).slice(0, 200));
            return;
        }
        if (r && r.ok === false) { finish(false, r.error); return; }
        if (r && r.ok === undefined && r.error !== undefined) {
            var what = "Logos host: " + r.error + (r.message ? ": " + r.message : "");
            if (/timed out|timeout/i.test(String(r.error) + " " + String(r.message)))
                what += " (the outcome is unknown: refresh before repeating the step)";
            finish(false, what);
            return;
        }
        finish(true, (r && r.result !== undefined && r.ok === undefined) ? r.result : r);
    }

    function applyNetwork(n) {
        if (!n) return;
        network = n;
        if (n.decimals !== undefined) decimals = n.decimals;
        if (n.asset_label) unit = n.asset_label;
        readOnly = !!n.read_only;
        if (n.rpc_url && !rpcField.activeFocus) rpcField.text = n.rpc_url;
        if (n.program && !programField.activeFocus) programField.text = n.program;
    }

    function refreshStatus(done) {
        call("status", {}, function (ok, v) {
            if (ok) {
                applyNetwork(v.network);
                account = v.account || "";
                keySource = v.key_source || "";
                // A signed transaction the module recorded but never saw in a block (a lost reply, a restart): back in the
                // open-transaction banner (review R2, Kimi M1).
                if (v.unsettled && v.unsettled.length > 0 && !openTx) {
                    var u = v.unsettled[0];
                    lastTx = { state: "unknown", tx_hash: u.tx_hash, op: u.op,
                               note: "the module recorded it (" + (u.title || u.op) + ", sent " + u.sent_utc + ") but has not seen it in a block." };
                }
                balance = v.balance || null;
                if (v.clock_utc) clockUtc = v.clock_utc;
            }
            if (done) done(ok, v);
        });
    }

    function refreshSchedules() {
        if (!network) return;
        call("schedules", {}, function (ok, v) {
            if (!ok) return;
            positions = v.positions || [];
            created = v.created || [];
            unreadable = v.unreadable || [];
            clockMs = v.clock_ms || Date.now();
            clockUtc = v.clock_utc || "";
            if (v.decimals !== undefined) decimals = v.decimals;
            if (v.asset_label) unit = v.asset_label;
        });
    }

    function refreshAll() {
        errorText = "";
        refreshStatus(function (ok) { if (ok) refreshSchedules(); });
    }

    function connectNetwork() {
        errorText = ""; noticeText = "";
        call("configure", { rpc_url: rpcField.text.trim(), program: programField.text.trim(), read_only: readOnlyBox.checked },
             function (ok, v) {
                 if (!ok) return;
                 applyNetwork(v);
                 clockUtc = v.clock_utc || "";
                 noticeText = "Connected: block " + v.head + ", chain clock " + v.clock_utc +
                     (v.program_configured ? ", program configured (fee " + v.fee_bps + " bps)" : ". " + (v.note || "the program is not configured there"));
                 refreshAll();
             });
    }

    function useKey(action) {
        errorText = ""; noticeText = "";
        var req = { action: action };
        if (action === "import") {
            if (keyPathField.text.trim() === "") { errorText = "Enter the path of a key file first."; return; }
            req.path = keyPathField.text.trim();
        }
        call("key", req, function (ok, v) {
            if (!ok) return;
            account = v.account || "";
            keySource = v.key_source || "";
            noticeText = "Signing account: " + account + (action === "new" ? " (new: fund it before it can pay fees)" : "");
            refreshAll();
        });
    }

    // ---- writes: prepare, then approve or reject ---------------------------------------------------------------
    function show(v) {
        var why = Amt.promptProblem(v, decimals, unit);
        if (why !== "") {
            errorText = why;
            if (v && v.pending_id) call("reject", { pending_id: v.pending_id }, null);
            return;
        }
        pending = v; lastTx = null;
    }

    function prepareClaim(schedule, amountText) {
        errorText = ""; noticeText = "";
        var req = { schedule: schedule };
        if (amountText.trim() !== "") {
            try { req.amount = Amt.toBase(amountText, decimals); } catch (e) { errorText = "Amount: " + e; return; }
        }
        call("prepare_claim", req, function (ok, v) { if (ok) show(v); });
    }

    function prepareCreate() {
        errorText = ""; noticeText = "";
        var req = { beneficiary: beneficiaryField.text.trim(), kind: kindBox.currentIndex === 0 ? "linear" : "cliff",
                    cancelable: cancelableBox.checked };
        try {
            req.total = Amt.toBase(totalField.text, decimals);
            var now = clockMs > 0 ? clockMs : Date.now();
            req.start_ms = Amt.parseWhen(startField.text, now);
            req.end_ms = Amt.parseWhen(endField.text, now);
            if (req.kind === "cliff") {
                req.cliff_ms = Amt.parseWhen(cliffField.text, now);
                req.cliff_amount = Amt.toBase(cliffAmountField.text, decimals);
            }
        } catch (e) { errorText = String(e); return; }
        if (req.beneficiary === "") { errorText = "Enter the beneficiary's account id."; return; }
        call("prepare_create", req, function (ok, v) { if (ok) show(v); });
    }

    function prepareCancel(schedule) {
        errorText = ""; noticeText = "";
        call("prepare_cancel", { schedule: schedule }, function (ok, v) { if (ok) show(v); });
    }

    function approvePending() {
        if (!pending) return;
        var id = pending.pending_id;
        call("approve", { pending_id: id }, function (ok, v) {
            pending = null;
            // No answer (a host timeout, a dropped reply): the module may have signed and sent it. Its record comes back
            // through status into the open-transaction banner; the error line keeps the host's message.
            if (!ok) { refreshStatus(null); return; }
            lastTx = v;   // anything not in a block stays in the open-transaction banner
            refreshAll();
            if (v.state === "in_block") noticeText = settled(v);
        });
    }

    function settled(v) {
        var applied = v.outcome ? v.outcome.applied : null;
        return (applied === true ? "Done: " : applied === false ? "In block " + v.block + " but not applied: " : "In block " + v.block + ", outcome not read: ")
            + (v.outcome ? v.outcome.detail : "") + " (tx " + Amt.short(v.tx_hash) + ", block " + v.block
            + (v.approved_by ? "; approved by " + v.approved_by : "") + ")";
    }

    // Ask the module where the open transaction stands; once in a block, the banner gives way to the outcome.
    function checkTx() {
        if (!openTx) return;
        var hash = lastTx.tx_hash;
        call("tx_status", { tx_hash: hash }, function (ok, v) {
            if (!ok || !lastTx || lastTx.tx_hash !== hash) return;
            if (v.state === "in_block") {
                noticeText = settled(v);
                lastTx = null;
                refreshAll();
            } else {
                lastTx = Object.assign({}, lastTx, { check_note: "checked at " + Amt.utc(Date.now()) + ": not in a block yet" });
            }
        });
    }

    function dismissTx() {
        if (!lastTx) return;
        var hash = lastTx.tx_hash;
        call("tx_status", { tx_hash: hash, dismiss: true }, function (ok) { if (ok && lastTx && lastTx.tx_hash === hash) lastTx = null; });
    }

    function rejectPending() {
        if (!pending) return;
        var id = pending.pending_id;
        call("reject", { pending_id: id }, function (ok, v) {
            if (!ok) return;   // the prompt stays, with the error above it: the module still holds the transaction
            pending = null;
            if (v && v.rejected === id)
                noticeText = "Rejected: nothing was signed or sent.";
            else
                errorText = "The module no longer held this transaction (it expired, or was already approved or rejected): Refresh before doing anything else.";
        });
    }

    function trackSchedule() {
        errorText = "";
        var id = trackField.text.trim();
        if (id === "") { errorText = "Enter a schedule id."; return; }
        call("track", { schedule: id }, function (ok) { if (ok) { trackField.text = ""; refreshSchedules(); } });
    }

    Component.onCompleted: if (backend) refreshAll()

    // ---- layout ------------------------------------------------------------------------------------------------
    component Label2: Text { textFormat: Text.PlainText; font.pixelSize: 13; color: "#5b6270" }
    component Value2: Text { textFormat: Text.PlainText; font.pixelSize: 14; color: "#1d2330"; wrapMode: Text.WrapAnywhere }
    component Card: Rectangle { color: "white"; radius: 8; border.color: "#dde1e8"; Layout.fillWidth: true }

    ScrollView {
        id: scroll
        anchors.fill: parent
        contentWidth: availableWidth
        clip: true

        ColumnLayout {
            width: scroll.availableWidth
            spacing: 12

            // header
            Rectangle {
                Layout.fillWidth: true
                height: 64
                color: "#16324f"
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 20
                    anchors.rightMargin: 20
                    Text { textFormat: Text.PlainText; text: "Escapement"; color: "white"; font.pixelSize: 24; font.bold: true }
                    Text { textFormat: Text.PlainText; text: "token vesting on LEZ v0.4 · prototype, not audited"; color: "#c9d6e6"; font.pixelSize: 14; Layout.leftMargin: 8 }
                    Item { Layout.fillWidth: true }
                    Text { textFormat: Text.PlainText;
                        objectName: "escapement.busy"
                        text: busy > 0 ? "working…" : (clockUtc !== "" ? "chain clock " + clockUtc : "")
                        color: "#c9d6e6"; font.pixelSize: 13
                    }
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 20
                Layout.rightMargin: 20
                spacing: 12

                // network and account
                Card {
                    implicitHeight: setup.implicitHeight + 24
                    GridLayout {
                        id: setup
                        anchors.fill: parent
                        anchors.margins: 12
                        columns: 6
                        columnSpacing: 10
                        rowSpacing: 8
                        Label2 { text: "Network" ; font.bold: true }
                        TextField { id: rpcField; objectName: "escapement.rpc"; Layout.fillWidth: true; Layout.columnSpan: 2; text: "http://127.0.0.1:3040"; placeholderText: "sequencer RPC: http://127.0.0.1:3040 or https://…" }
                        TextField { id: programField; objectName: "escapement.program"; Layout.fillWidth: true; Layout.columnSpan: 2; placeholderText: "Escapement program id" }
                        Button { objectName: "escapement.connect"; text: "Connect"; onClicked: connectNetwork(); enabled: busy === 0 }
                        Label2 { text: "Units" }
                        RowLayout {
                            Layout.columnSpan: 4
                            Value2 { objectName: "escapement.units"; text: unit + ", " + decimals + " decimals (fixed in the module)" }
                            Item { implicitWidth: 24 }
                            CheckBox { id: readOnlyBox; objectName: "escapement.readonly"; text: "read-only (never sign here)"; checked: readOnly }
                        }
                        Item { width: 1 }
                        Label2 { text: "Account"; font.bold: true }
                        TextField { id: keyPathField; objectName: "escapement.keypath"; Layout.fillWidth: true; Layout.columnSpan: 3; placeholderText: "key file (64 hex digits, or `escapement keygen` JSON); the key stays in the module" }
                        Button { objectName: "escapement.usekey"; text: "Use key file"; onClicked: useKey("import"); enabled: busy === 0 }
                        Button { objectName: "escapement.newkey"; text: "New key"; onClicked: useKey("new"); enabled: busy === 0 }
                        Item { width: 1 }
                        Value2 {
                            objectName: "escapement.account"
                            Layout.columnSpan: 4
                            Layout.fillWidth: true
                            text: account === "" ? "No signing account yet." :
                                  account + (balance ? "   ·   balance " + balance.display + " " + balance.unit : "")
                        }
                        Button { text: "Refresh"; onClicked: refreshAll(); enabled: busy === 0 }
                    }
                }

                // messages: an open transaction first (its own banner, review R2 M1), then errors and notices
                Rectangle {
                    objectName: "escapement.opentx"
                    Layout.fillWidth: true
                    visible: openTx
                    color: "#fff4e0"; border.color: "#e0b060"; radius: 6
                    implicitHeight: openCol.implicitHeight + 20
                    ColumnLayout {
                        id: openCol
                        anchors.fill: parent
                        anchors.margins: 10
                        Text {
                            textFormat: Text.PlainText
                            objectName: "escapement.opentx.text"
                            Layout.fillWidth: true
                            wrapMode: Text.WrapAnywhere
                            color: "#6b4a00"; font.pixelSize: 14
                            text: !openTx ? "" :
                                  (lastTx.state === "unknown" ? "Outcome unknown" : lastTx.state === "refused_by_sequencer" ? "Refused by the sequencer" : "Sent, not in a block yet")
                                  + ": transaction " + lastTx.tx_hash + ". " + (lastTx.warning || lastTx.note || "")
                                  + (lastTx.check_note ? " (" + lastTx.check_note + ")" : "")
                                  + " New transactions are held until you Check this or Dismiss it."
                        }
                        RowLayout {
                            Item { Layout.fillWidth: true }
                            Button { objectName: "escapement.opentx.check"; text: "Check"; enabled: busy === 0; onClicked: checkTx() }
                            Button { objectName: "escapement.opentx.dismiss"; text: "Dismiss"; onClicked: dismissTx() }
                        }
                    }
                }
                Rectangle {
                    Layout.fillWidth: true
                    visible: errorText !== ""
                    color: "#fdecec"; border.color: "#e2a3a3"; radius: 6
                    implicitHeight: errText.implicitHeight + 20
                    Text { textFormat: Text.PlainText; id: errText; objectName: "escapement.error"; anchors.fill: parent; anchors.margins: 10; text: errorText; wrapMode: Text.Wrap; color: "#7a1f1f"; font.pixelSize: 14 }
                }
                Rectangle {
                    Layout.fillWidth: true
                    visible: noticeText !== ""
                    color: "#eaf5ee"; border.color: "#9ccfae"; radius: 6
                    implicitHeight: noteText.implicitHeight + 20
                    Text { textFormat: Text.PlainText; id: noteText; objectName: "escapement.notice"; anchors.fill: parent; anchors.margins: 10; text: noticeText; wrapMode: Text.Wrap; color: "#1f5a33"; font.pixelSize: 14 }
                }

                TabBar {
                    id: tabs
                    objectName: "escapement.tabs"
                    Layout.fillWidth: true
                    currentIndex: tab
                    onCurrentIndexChanged: tab = currentIndex
                    TabButton { objectName: "escapement.tab.recipient"; text: "Recipient" }
                    TabButton { objectName: "escapement.tab.creator"; text: "Creator" }
                }

                // ---------------------------------------------------------------- Recipient
                ColumnLayout {
                    visible: tab === 0
                    Layout.fillWidth: true
                    spacing: 10
                    RowLayout {
                        Layout.fillWidth: true
                        Text { textFormat: Text.PlainText; text: "Your vesting positions"; font.pixelSize: 18; font.bold: true; color: "#1d2330" }
                        Item { Layout.fillWidth: true }
                        TextField { id: trackField; objectName: "escapement.track"; implicitWidth: 380; placeholderText: "add a schedule by its id" }
                        Button { text: "Add"; onClicked: trackSchedule(); enabled: busy === 0 && network !== null }
                        Button { objectName: "escapement.refresh"; text: "Refresh"; onClicked: refreshAll(); enabled: busy === 0 }
                    }
                    Text { textFormat: Text.PlainText;
                        visible: positions.length === 0
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        color: "#5b6270"; font.pixelSize: 14
                        text: account === "" ? "Choose your account (Account, above) to see the schedules that pay you." :
                              "No schedule pays " + Amt.short(account) + " among the ones this module knows. A schedule made elsewhere appears once you add its id (there is no indexer yet)."
                    }
                    Repeater {
                        model: positions
                        delegate: Card {
                            id: pcard
                            required property var modelData
                            implicitHeight: pgrid.implicitHeight + 24
                            GridLayout {
                                id: pgrid
                                anchors.fill: parent
                                anchors.margins: 12
                                columns: 4
                                columnSpacing: 14
                                rowSpacing: 6
                                Label2 { text: "Schedule" }
                                Value2 { text: pcard.modelData.schedule; Layout.columnSpan: 3; Layout.fillWidth: true; font.family: "monospace"; font.pixelSize: 13 }
                                Label2 { text: "Claimable now" }
                                Value2 { objectName: "escapement.claimable"; text: pcard.modelData.claimable_now.display + " " + pcard.modelData.claimable_now.unit; font.bold: true; color: "#14633a"; font.pixelSize: 16 }
                                Label2 { text: "Next unlock" }
                                Value2 { Layout.fillWidth: true; text: pcard.modelData.next_unlock_label ? pcard.modelData.next_unlock_label : (pcard.modelData.next_unlock_utc ? pcard.modelData.next_unlock_utc : "—") }
                                Label2 { text: "Locked (not vested yet)" }
                                Value2 { text: pcard.modelData.locked.display + " " + pcard.modelData.locked.unit }
                                Label2 { text: "Claimed" }
                                Value2 { text: pcard.modelData.claimed.display + " of " + pcard.modelData.total.display + " " + pcard.modelData.total.unit }
                                Label2 { text: "Vesting" }
                                Value2 {
                                    Layout.columnSpan: 3; Layout.fillWidth: true
                                    text: pcard.modelData.kind.type === "linear" ? "linear, " + pcard.modelData.kind.start_utc + " → " + pcard.modelData.kind.end_utc :
                                          pcard.modelData.kind.type === "cliff_linear" ? "cliff at " + pcard.modelData.kind.cliff_utc + ", then linear to " + pcard.modelData.kind.end_utc :
                                          "milestones (" + pcard.modelData.kind.tranches.length + ")"
                                }
                                Label2 { text: "Status" }
                                Value2 { Layout.columnSpan: 3; Layout.fillWidth: true; text: pcard.modelData.status + (pcard.modelData.cancelled ? " · cancelled " + pcard.modelData.cancelled.at_utc : "") }
                                Label2 { text: "Claim" }
                                RowLayout {
                                    Layout.columnSpan: 3
                                    TextField { id: claimAmount; implicitWidth: 220; placeholderText: "all claimable, or an amount in " + unit }
                                    Button {
                                        objectName: "escapement.claim"
                                        text: "Claim (public)…"
                                        enabled: busy === 0 && !readOnly && !openTx && pcard.modelData.native === true && !Amt.isZero(pcard.modelData.claimable_now.base_units)
                                        onClicked: prepareClaim(pcard.modelData.schedule, claimAmount.text)
                                    }
                                    Label2 { text: pcard.modelData.native === true ? "Private claim: CLI only for now" : "Token schedule: claim it with the CLI for now"; font.italic: true }
                                }
                            }
                        }
                    }
                }

                // ---------------------------------------------------------------- Creator
                ColumnLayout {
                    visible: tab === 1
                    Layout.fillWidth: true
                    spacing: 10
                    Text { textFormat: Text.PlainText; text: "Create a vesting schedule"; font.pixelSize: 18; font.bold: true; color: "#1d2330" }
                    Card {
                        implicitHeight: cgrid.implicitHeight + 24
                        GridLayout {
                            id: cgrid
                            anchors.fill: parent
                            anchors.margins: 12
                            columns: 4
                            columnSpacing: 12
                            rowSpacing: 8
                            Label2 { text: "Beneficiary" }
                            TextField { id: beneficiaryField; objectName: "escapement.beneficiary"; Layout.columnSpan: 3; Layout.fillWidth: true; placeholderText: "the recipient's LEZ account id" }
                            Label2 { text: "Total (" + unit + ")" }
                            TextField { id: totalField; objectName: "escapement.total"; Layout.fillWidth: true; placeholderText: "e.g. 1000.5" }
                            Label2 { text: "Vesting" }
                            ComboBox { id: kindBox; objectName: "escapement.kind"; Layout.fillWidth: true; model: ["Linear", "Cliff, then linear"] }
                            Label2 { text: "Start" }
                            TextField { id: startField; objectName: "escapement.start"; Layout.fillWidth: true; text: "now"; placeholderText: "now, +1h, or 2026-12-01 09:30 (UTC)" }
                            Label2 { text: "End" }
                            TextField { id: endField; objectName: "escapement.end"; Layout.fillWidth: true; text: "+30m"; placeholderText: "+30d, or 2027-12-01 09:30 (UTC)" }
                            Label2 { text: "Cliff at"; visible: kindBox.currentIndex === 1 }
                            TextField { id: cliffField; Layout.fillWidth: true; visible: kindBox.currentIndex === 1; text: "+10m" }
                            Label2 { text: "Cliff amount (" + unit + ")"; visible: kindBox.currentIndex === 1 }
                            TextField { id: cliffAmountField; Layout.fillWidth: true; visible: kindBox.currentIndex === 1; placeholderText: "released at the cliff" }
                            CheckBox { id: cancelableBox; objectName: "escapement.cancelable"; Layout.columnSpan: 2; checked: true; text: "Cancelable by me (the unvested part comes back)" }
                            Label2 { Layout.columnSpan: 1; text: "Asset: native " + unit + " (tokens: CLI)" }
                            Button { objectName: "escapement.create"; text: "Review and sign…"; enabled: busy === 0 && !readOnly && !openTx; onClicked: prepareCreate() }
                        }
                    }
                    RowLayout {
                        Layout.fillWidth: true
                        Text { textFormat: Text.PlainText; text: "Schedules you created"; font.pixelSize: 18; font.bold: true; color: "#1d2330" }
                        Item { Layout.fillWidth: true }
                        Button { text: "Refresh"; onClicked: refreshAll(); enabled: busy === 0 }
                    }
                    Text { textFormat: Text.PlainText;
                        visible: created.length === 0
                        color: "#5b6270"; font.pixelSize: 14
                        text: "None yet from " + (account === "" ? "this account" : Amt.short(account)) + "."
                    }
                    Repeater {
                        model: created
                        delegate: Card {
                            id: ccard
                            required property var modelData
                            implicitHeight: crow.implicitHeight + 24
                            GridLayout {
                                id: crow
                                anchors.fill: parent
                                anchors.margins: 12
                                columns: 4
                                columnSpacing: 14
                                rowSpacing: 6
                                Label2 { text: "Schedule" }
                                Value2 { text: ccard.modelData.schedule; Layout.columnSpan: 3; Layout.fillWidth: true; font.family: "monospace"; font.pixelSize: 13 }
                                Label2 { text: "Beneficiary" }
                                Value2 { text: ccard.modelData.beneficiary; Layout.columnSpan: 3; Layout.fillWidth: true; font.family: "monospace"; font.pixelSize: 13 }
                                Label2 { text: "Total" }
                                Value2 { text: ccard.modelData.total.display + " " + ccard.modelData.total.unit }
                                Label2 { text: "Vested / claimed" }
                                Value2 { text: ccard.modelData.vested.display + " / " + ccard.modelData.claimed.display + " " + ccard.modelData.claimed.unit }
                                Label2 { text: "Status" }
                                Value2 { Layout.columnSpan: 2; Layout.fillWidth: true; text: ccard.modelData.cancelled ? "cancelled " + ccard.modelData.cancelled.at_utc + " (refunded " + (ccard.modelData.native === true ? Amt.fromBase(ccard.modelData.cancelled.refunded, decimals) + " " + unit : ccard.modelData.cancelled.refunded + " " + ccard.modelData.total.unit) + ")" : ccard.modelData.status }
                                Button {
                                    objectName: "escapement.cancel"
                                    text: "Cancel…"
                                    enabled: busy === 0 && !readOnly && !openTx && ccard.modelData.native === true && ccard.modelData.cancelable && !ccard.modelData.cancelled
                                    onClicked: prepareCancel(ccard.modelData.schedule)
                                }
                            }
                        }
                    }
                }

                Text { textFormat: Text.PlainText;
                    Layout.fillWidth: true
                    Layout.bottomMargin: 20
                    wrapMode: Text.Wrap
                    color: "#7a8190"; font.pixelSize: 12
                    text: "Not yet in this view: the private claim (escapement CLI), token schedules, milestone signals, discovery of schedules without their id. " +
                          "Public on chain: every schedule's terms, beneficiary and claims."
                }
            }
        }
    }

    // ---- the approval prompt: nothing is signed before "Approve and sign" ---------------------------------------
    // A panel of fixed size: what will happen scrolls inside it, and the two buttons stay at its bottom.
    Rectangle {
        anchors.fill: parent
        visible: pending !== null
        color: "#99000000"
        MouseArea { anchors.fill: parent }
        Rectangle {
            objectName: "escapement.approval"
            anchors.centerIn: parent
            width: Math.min(parent.width - 60, 760)
            height: Math.min(parent.height - 60, 560)
            radius: 10
            color: "white"
            ScrollView {
                id: approvalScroll
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.bottom: approvalButtons.top
                anchors.margins: 20
                contentWidth: availableWidth
                clip: true
                ColumnLayout {
                    id: approvalCol
                    width: approvalScroll.availableWidth
                    spacing: 10
                    Text { textFormat: Text.PlainText; text: pending ? pending.title : ""; font.pixelSize: 20; font.bold: true; color: "#1d2330"; wrapMode: Text.WrapAnywhere; Layout.fillWidth: true }
                    Text { textFormat: Text.PlainText; text: "Check before signing. Nothing has been signed or sent yet."; color: "#5b6270"; font.pixelSize: 13 }
                    GridLayout {
                        columns: 2
                        columnSpacing: 14
                        rowSpacing: 6
                        Layout.fillWidth: true
                        Repeater {
                            model: pending ? pending.rows : []
                            delegate: Text { textFormat: Text.PlainText;
                                required property var modelData
                                required property int index
                                text: modelData[0]
                                color: "#5b6270"; font.pixelSize: 13
                                Layout.row: index; Layout.column: 0
                                Layout.alignment: Qt.AlignTop
                            }
                        }
                        Repeater {
                            model: pending ? pending.rows : []
                            delegate: Text { textFormat: Text.PlainText;
                                required property var modelData
                                required property int index
                                text: modelData[1]
                                color: "#1d2330"; font.pixelSize: 14; wrapMode: Text.WrapAnywhere
                                Layout.row: index; Layout.column: 1; Layout.fillWidth: true
                            }
                        }
                    }
                    Repeater {
                        model: pending ? pending.effects : []
                        delegate: Text { textFormat: Text.PlainText; required property var modelData; text: "• " + modelData; wrapMode: Text.Wrap; Layout.fillWidth: true; color: "#1d2330"; font.pixelSize: 13 }
                    }
                }
            }
            RowLayout {
                id: approvalButtons
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.margins: 20
                Text { textFormat: Text.PlainText; text: pending ? "Expires in " + Math.round(pending.expires_in_s / 60) + " min if not approved." : ""; color: "#7a8190"; font.pixelSize: 12 }
                Item { Layout.fillWidth: true }
                Button { objectName: "escapement.reject"; text: "Reject"; onClicked: rejectPending(); enabled: busy === 0 }
                Button { objectName: "escapement.approve"; text: "Approve and sign"; highlighted: true; onClicked: approvePending(); enabled: busy === 0 }
            }
        }
    }
}
