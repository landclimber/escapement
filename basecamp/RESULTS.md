# Results: the Basecamp mini-app after two review rounds, 25 Nov 2026

Two rounds of independent review (two reviewers each) found, in round 1:
- `approve` let a caller Logos Core cannot name (`unknown`) through, and every other method was open to any caller;
- a prompt's units could be rescaled, or a token schedule shown as LEZ;
- the loopback check could be bypassed;
- the view rendered text as rich text;
- a failure after signing looked like a refusal.

In round 2 they found:
- an unsettled transaction's hash could disappear from the view;
- a failed read-back after a create was reported as a revert;
- a sequencer's refusal was reported as a lost answer;
- smaller points.

Each finding is fixed, with the tests below. This branch is one commit on `2ddc57c`.

All runs used:
- a Linux x86-64 build box (Ubuntu 24.04 in a gVisor container, Nix 2.28.3);
- a local standalone LEZ **v0.4.0-rc3** sequencer (`e2e/sequencer.sh start`, mock Bedrock, 2 s blocks);
- Escapement deployed from the guest that matches `image-ids.tsv` (`adc8b81f…df4c`), immutable, admin initialised.

Every transaction there is public, so no proof is involved. Records: [`results/`](results/).

## Tests

| Suite | Before the fixes | Now |
|---|---|---|
| The module's calls (`cargo test -p escapement-module-calls`), through the single entry point `call()`, against a stand-in sequencer that records what it is sent | On round 1's code (run with a thin `call()` shim), 11 of the 17 tests that run there fail: every round-1 finding test that exists there ([`review-r1/rust-before.txt`](results/review-r1/rust-before.txt)). On round 2's code, the 6 round-2 tests fail ([`review-r2/rust-before.txt`](results/review-r2/rust-before.txt)). | **25 of 25** ([`review-r2/rust-after.txt`](results/review-r2/rust-after.txt)) |
| The view (Qt Quick Test, `tests/qml/tst_view.qml`, offscreen; the stand-in for Logos answers late when a test needs it) | Round 1's view: 7 of 7 fail. Round 2's view: 4 fail, including the hash disappearing after a lost send and a failing late refresh ([`review-r2/qml-before.txt`](results/review-r2/qml-before.txt)) | **10 of 10** ([`qml-after.txt`](results/review-r2/qml-after.txt)) |
| Amounts and times (`tests/amount.test.mjs`) | On round 1's code: impossible dates rolled over and `1_000` accepted | passes |
| `sign-test.sh` against a stand-in `lgx`; `keyscan.py` | the old `sign-test.sh` signed an untrusted signer (2 of 4 fail) | 4 of 4; passes |

Two finding tests have no counterpart in the old code and were not run there:
- `key_files_are_small_regular_files` (bounded, non-blocking key files);
- `nit_the_nonce_is_checked_before_anything_is_signed`.

The second review round checked both by taking each fix out; that run is not recorded here. Wiping the JSON form's key
copy has no test.

## Packages (linux-amd64)

| Package | Unsigned SHA-256 | Signed SHA-256 (test key) | Size |
|---|---|---|---|
| `escapement_core_module-0.1.0.lgx` | `9893703adf32b90bad4be79c13144fc77ba472adf21248cd0050d4ea30ef4bdb` | `6ed37848d8c36a3f5be209c346569459aafb26bd4bffb522d5e816fbcdd20194` | 8.1 MB |
| `escapement_ui-0.1.0.lgx` | `dc21ed2499937bd5c2ac9c601bbcdbc9568a92623f5c46cd875e1094d6a0a823` | `71861615e01c0dd602a733bd4c2973e104e3f33387c2b90dd9a3c62ae62d4029` | 26 kB |

- **Source.** They were built from the trees this commit holds (git hashes):
  - `basecamp/escapement_core_module` = `84a127209827888cdb94d0735f9402bfe9344e25`
  - `basecamp/escapement_ui` = `9eed77bce607a1a02c6796607b70703236404788`
  - `basecamp/scripts` = `018a7318d38748b7cbe34fb7a1cc83bf01ccb5c2`

  Check with `git rev-parse HEAD:basecamp/escapement_core_module` and the like. The staged crates are from `2ddc57c`.
  The packages themselves are not committed; their hashes are.
- **Build.** `scripts/build-lgx.sh` (logos-module-builder `5f74cdb`, lgx `4bdd904`) built the core module in 109 s and
  the view in 5 s ([`build.json`](results/build/build.json)).
- **Signing.** `scripts/sign-test.sh` signed them with the Escapement **test** key made on the build box; its private
  half never left the box. The signer is `did:jwk:…nqrzhllbL1GVT-37rBUroAEdWepnATjrlk-jEPx5hUM`
  ([`escapement-test.did`](results/build/escapement-test.did)). With a keyring holding only that DID, `lgx verify`
  prints "Signature is valid" and "Signer is trusted: escapement-test" ([`verify.txt`](results/build/verify.txt)).
- **Key scan.** What came back from the box was scanned with `scripts/keyscan.py` for the test key and the three
  devnet accounts' keys: "90 files, 0 with key material (4 secrets)" ([`keyscan.txt`](results/build/keyscan.txt)).

## Headless Logos Core: 31 of 31

`scripts/install-test.sh` ran with logosctl (logos-logoscore-cli `66d098d`, portable), `signature_policy: require`, and
the test DID as the only trusted key ([`steps.tsv`](results/install-test/steps.tsv); each step's output is in `out/`).

- **Refused:**
  - both packages unsigned;
  - the core package with one bit of its plugin flipped ("Content hash mismatch");
  - with its manifest edited after signing ("Invalid signature: Ed25519 signature verification failed");
  - signed by another key under the test signer's name ("Package signed by untrusted key").
- **Installed:** both signed packages, then the core module loaded and `version` called.
- **On the sequencer, through Logos Core (the caller is `host`):**
  - units other than the fixed ones refused;
  - `prepare_create` → `approve`: applied in block 25, `approved_by: host`;
  - a claim rejected, then approving the rejected id refused;
  - a claim of 0.1 LEZ applied in block 27;
  - a cancel applied in block 28.

## Logos Basecamp 0.4.0-rc.2 (the release AppImage, SHA-256 `e59e14cd…47a0`)

The packages above were installed and used through Basecamp's window on a virtual screen (Xvfb, 1920×1080, mouse and
keyboard driven by xdotool), with the local sequencer beside it. Screenshots: [`results/basecamp/shots/`](results/basecamp/shots/);
Basecamp's log lines about Escapement: [`basecamp-log-escapement-lines.txt`](results/basecamp/basecamp-log-escapement-lines.txt).

| Shot | Step | Result |
|---|---|---|
| 01, 02 | Package Manager → Install Local Package, each `.lgx` → **Install** | the prompt names "Escapement test build (not a release)" (self-asserted), key `B77D 19F8 F4EB 514C` |
| 03 | Escapement opened; Network: `http://127.0.0.1:3040` and the program id; **Connect** | Basecamp loads `escapement_core_module` itself; units shown as "LEZ, 9 decimals (fixed in the module)" |
| 04–06 | Creator: the creator's key file; beneficiary, 90 LEZ, from now to +20 min; **Review and sign…** → **Approve and sign** | "Create a schedule of 90 LEZ (90000000000 base units) …", then "Done: the schedule exists and its escrow is funded (… block 56; **approved by module:escapement_ui**)" |
| 07 | Recipient: the beneficiary's key file | claimable now 2.550075 LEZ, locked 87.449925, next unlock "accruing continuously until 18:38:10 UTC", claimed 0 of 90 |
| 08, 09 | amount `0.25` → **Claim (public)…** → **Reject** | "Rejected: nothing was signed or sent." |
| 10 | again, then **Approve and sign** | "Done: the claim is recorded on the schedule (… block 79; approved by module:escapement_ui)" |
| 11 | amount `1000` → **Claim (public)…** | refused before anything is built: "You asked to claim 1000 LEZ but only 4.7 LEZ is claimable now; claim at most 4.7 LEZ." |
| 12–14 | Creator: **Cancel…** → the prompt → **Approve and sign** | prompt: vested 7.050075 LEZ (7050075000 base units), about 82.949925 to be refunded. Result: "Done: the schedule is cancelled (… block 99; approved by module:escapement_ui)": vested 7.35, refunded 82.65 |
| 15, 16 | Recipient: claimable 7.1 → **Claim (public)…** → approve | done in block 110; claimed 7.35 of 90 (all that vested); 7.35 + 82.65 = 90 |

Basecamp 0.4.0-rc.2 names the view `module:escapement_ui`: every approval above reports that name, which is the name the
module's caller rule allows.

After the session, everything that came back was scanned for the devnet key files the view imported by path: "27
files, 0 with key material (3 secrets)" ([`keyscan.txt`](results/basecamp/keyscan.txt)).

Basecamp logs one warning about the view: QML calls into Logos Core (`logos.callModuleAsync`) are deprecated and move to
a backend module in Basecamp's next breaking release.

## The public LEZ test network, read-only

The same signed core module ran in a headless Logos Core with `read_only: true` and no key loaded, pointed at the public
LEZ v0.4.0-rc3 test network where Escapement is deployed:
- RPC `https://54-156-116-24.sslip.io/rpc`;
- program `Be6eH1Ps2cr7zSmuV2XfwZDkF14naGcEG6h71ViszSXW`.

Results ([`results/public-network/`](results/public-network/), 25 Nov 18:16Z):

- `configure`: head block 20087, the program configured (fee 0 bps).
- `schedules`, for the published beneficiary and creator and six of the published schedule ids: all six read live.
  Five are native, shown in LEZ. The token schedule is shown in its token's base units. For example, the cliff + linear
  schedule had 0.125490131 LEZ claimable ([`summary.txt`](results/public-network/summary.txt)).
- `prepare_claim`: refused with "this network is set read-only in the module: nothing is signed or sent here".

This was not tried from Basecamp's window, because the view lists only the loaded key's own schedules.

## Not run here

- No private claim from the GUI (not built); the e2e suite runs it with the CLI.
- No macOS build, and no check that a rebuild gives byte-identical packages.
- No caller other than the view and `host` reached the module inside Logos Core (no third module was installed). The
  other callers (`unknown`, another module) are tested through the module's single entry point.
- The open-transaction banner (a lost send, a failing late refresh, a lost host reply, a module restart) was tested
  with stand-ins (view tests, module tests), not produced in Basecamp's window.
- The unsettled-transaction record lives in the module's state file (`ESCAPEMENT_MODULE_HOME`, else
  `~/.local/share/escapement-module`). A restart was tested by clearing the module's memory, not by restarting Logos
  Core.
