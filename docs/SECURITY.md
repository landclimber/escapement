# Escapement — Security Tier 2 & Release Integrity Plan

RFP-017 moves escrowed user funds and builds claim transactions inside Logos Basecamp, so it falls under **security tier 2** of the Logos RFP "Security and Release Integrity" requirements (`logos-co/rfp` PR 255, open as of 2026-11-20). This file is the plan; items marked with a milestone are not built yet.

## Catalog, signing, and releases (Baseline)

- **Organisation-hosted catalog (M1):** the module catalog is forked from `logos-modules-release-base` and hosted on a **GitHub organisation account** (`github.com/<github-org>`), never a personal account, and is not renamed or deleted during the grant or the 12-month support period.
- **Signed modules (M4):** every `.lgx` / `.lgx-portable` (`linux-amd64`, `linux-arm64`, `darwin-arm64`) is built with `logos-module-builder` and signed with `lgx sign`, `signing_mode: inline`, from a protected GitHub Actions secret that pull-request workflows cannot read.
- **Signer declared up front (M1):** the `did:jwk:` signer DID (`lgx keygen`) is declared in the first milestone delivery and the README, and listed under `trustedSigners` in `logos-repo.json`. Any key rotation is announced in the proposal issue before the new key signs anything.
- **Immutable releases (M4):** GitHub immutable releases are enabled before the first module release. A published release or asset is never replaced, deleted, or re-tagged; a fix is a new release.
- **Release Integrity Manifest (every milestone that ships a module):** security tier `2`; full source commit SHA; catalog URL (`logos-repo.json`); signer DID; Logos Storage CID if uploaded; and per package: version, immutable release URL, **`rootHash`**, SHA-256 of the `.lgx`, and built variants. Escapement adds the on-chain program ImageID. Reviewers recompute `rootHash` and SHA-256 with `lgx manifest` / `lgx verify`.
- **Canonical install instructions (M4):** README and demo give the exact catalog URL, signer DID, and `rootHash`; never "search for", chat links, or bypassing signature warnings.

## Repository and reviewer safety (Baseline)

- 2FA on every account with write access; protected `main` branch and release-tag rulesets.
- All GitHub Actions pinned to full commit SHAs (already the case in `.github/workflows/ci.yml`).
- Committed `Cargo.lock` files (workspace and guest) plus `cargo-deny` and a manual check that every dependency is the real, intended crate, with no AI-hallucinated or typosquatted names.
- No plaintext private keys, seed phrases, or tokens in the repository, logs, or CI output.
- Build and demo scripts run without `--accept-flake-config`, extra Nix substituters or trusted keys, unpinned remote scripts, or reviewer credentials.

## Tier 2 controls

1. **Threat model (M1):** in the repository, covering assets (escrowed tokens, fee vaults, beneficiary privacy), actors (creators, beneficiaries, delegated authorities, admin, sequencer, indexer), trust boundaries, and adversarial inputs: a malicious co-installed Basecamp module, untrusted RPC and indexer responses, and a lagging or non-monotonic chain clock.
2. **Approval enforced in the core module (M3):** Escapement holds no keys. All signing goes through the LEZ wallet stack (`lez_core`), which owns key custody. In addition, `escapement_core_module` requires an explicit user approval inside the core module (not only in the UI) and checks which module is calling before it builds any fund-moving transaction.
3. **No plaintext keys:** nothing in Escapement stores, logs, or exports a key, seed, or token.
4. **Spend caps outside any agent:** not applicable. Every transaction is user-initiated; there is no autonomous agent or keeper.
5. **Independent security review (M6):** a third-party audit, contracted by Logos, of the guest program, `escapement-core`, `escapement-sdk`, and `escapement_core_module` (the approval boundary).

## Vulnerability disclosure

Any known vulnerability, or any compromise of a signing key or of an account with write access, is reported within **72 hours** by a comment on the proposal issue (without exploit details) or through a private channel Logos provides.
