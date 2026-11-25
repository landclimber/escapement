# Escapement — Security Tier 2 & Release Integrity Plan

RFP-017 moves escrowed user funds and builds claim transactions inside Logos Basecamp, so it falls under **security tier 2** of the Logos RFP "Security and Release Integrity" requirements (`logos-co/rfp` PR 255, still open on 2026-11-24, so these are commitments we make, not RFP requirements). Program-level controls below are built and tested; items marked with a milestone (M1–M5 of the proposal) are not built yet.

## Program-level controls (built, tested)

- **Who may act for an account:** user transitions are accepted only as the signer's root call or, for a program-owned PDA (multisig, DAO, launchpad), as `AsPda` from the program that derives it; anything else exits with code 35. LEZ v0.4 authorizes a signer's account across the whole call tree, so without this any program a user signs for could claim, transfer or cancel in their name (D-12; `sec_relay_eoa_refused`, `sec_pda_cpi_succeeds_and_inherited_seed_relay_refused`, `sec_signer_authority_review_gaps`).
- **Immutable deployment:** `program_loader` `CreateHeader { immutable: true }`, header read back and compared with the reproducible image id (`e2e/run_e2e.sh`). No upgrade key, pause, freeze, blacklist or sweep exists.
- **Reproducible guest:** `scripts/build-guest.sh --check` rebuilds the guest anywhere and compares image id, SHA-256 and size with `image-ids.tsv`; CI runs it.
- **Metered refusals:** all 35 deterministic vesting refusals are exit codes (1..=35) charged by cycles used. Some refusals still panic and are charged the transaction's whole gas limit: `lez-authority`'s admin refusals (by that library's design, D-11), messages that do not decode, and assertions on internal continuations that only a misbehaving runtime or token program could reach.
- **Funds invariants:** exact funding delta at creation; the cancel clamp `vested_at_cancel >= max(claimed, vested_high_water)`; per-asset fee vaults; write-once token program id; conservation checked after every step of a randomized multi-actor suite.
- **Platform risk declared:** RISC Zero advisory GHSA-g6qg-9j8p-7j87 (critical) affects `risc0-zkvm < 3.1.0`, which LEZ `v0.4.0-rc3` uses; Escapement follows the LEZ release that bumps it (D-15).

## Catalog, signing, and releases (Baseline)

- **Organisation-hosted catalog (M1):** the module catalog is forked from `logos-modules-release-base` and hosted on a **GitHub organisation account** (`github.com/<github-org>`), never a personal account, and is not renamed or deleted during the grant or the 12-month support period.
- **Signed modules (M3):** every `.lgx` / `.lgx-portable` (`linux-amd64`, `linux-arm64`, `darwin-arm64`) is built with `logos-module-builder` and signed with `lgx sign`, `signing_mode: inline`, from a protected GitHub Actions secret that pull-request workflows cannot read.
- **Signer declared up front (M1):** the `did:jwk:` signer DID (`lgx keygen`) is declared in the first milestone delivery and the README, and listed under `trustedSigners` in `logos-repo.json`. Any key rotation is announced in the proposal issue before the new key signs anything.
- **Immutable releases (M3):** GitHub immutable releases are enabled before the first module release. A published release or asset is never replaced, deleted, or re-tagged; a fix is a new release.
- **Release Integrity Manifest (every milestone that ships a module):** security tier `2`; full source commit SHA; catalog URL (`logos-repo.json`); signer DID; Logos Storage CID if uploaded; and per package: version, immutable release URL, **`rootHash`**, SHA-256 of the `.lgx`, and built variants. Escapement adds the on-chain program ImageID. Reviewers recompute `rootHash` and SHA-256 with `lgx manifest` / `lgx verify`.
- **Canonical install instructions (M3):** README and demo give the exact catalog URL, signer DID, and `rootHash`; never "search for", chat links, or bypassing signature warnings.

## Repository and reviewer safety (Baseline)

- 2FA on every account with write access; protected `main` branch and release-tag rulesets.
- All GitHub Actions pinned to full commit SHAs (already the case in `.github/workflows/ci.yml`).
- Committed `Cargo.lock` files (workspace and guest) plus `cargo-deny` and a manual check that every dependency is the real, intended crate, with no AI-hallucinated or typosquatted names.
- No plaintext private keys, seed phrases, or tokens in the repository, logs, or CI output.
- Build and demo scripts run without `--accept-flake-config`, extra Nix substituters or trusted keys, unpinned remote scripts, or reviewer credentials.

## Tier 2 controls

1. **Threat model (M1):** in the repository, covering assets (escrowed tokens, fee vaults, beneficiary privacy), actors (creators, beneficiaries, delegated authorities, admin, sequencer, indexer), trust boundaries, and adversarial inputs: a malicious co-installed Basecamp module, untrusted RPC and indexer responses, and a lagging or non-monotonic chain clock.
2. **Approval enforced in the core module (M2):** the module holds no keys. All signing goes through the LEZ wallet stack (`lez_core`), which owns key custody. In addition, `escapement_core_module` requires an explicit user approval inside the core module (not only in the UI) and checks which module is calling before it builds any fund-moving transaction.
3. **No plaintext keys in the module or the mini-app:** neither stores, logs, or exports a key, seed, or token. The CLI, a tool for local sequencers today, is the one exception: it signs with the key given in `ESCAPEMENT_KEY` and keeps the private accounts it creates, and its deployment keys, in files the user names (mode 0600, never overwritten); wallet-held keys for testnet come in M4.
4. **Spend caps outside any agent:** not applicable. Every transaction is user-initiated; there is no autonomous agent or keeper.
5. **Independent security review (M5):** a third-party audit, contracted by Logos, of the guest program, `escapement-core`, `escapement-sdk`, and `escapement_core_module` (the approval boundary).

## Vulnerability disclosure

Any known vulnerability, or any compromise of a signing key or of an account with write access, is reported within **72 hours** by a comment on the proposal issue (without exploit details) or through a private channel Logos provides.
