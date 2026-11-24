#!/usr/bin/env bash
# Builds the Escapement guest and records its image id.
#
#   scripts/build-guest.sh            build; print "program, image id, SHA-256 and size of the program binary"
#   scripts/build-guest.sh --check    build, then compare with image-ids.tsv; exit 1 on a mismatch
#
# What makes the id reproducible wherever the tree, $HOME and the toolchains are:
#   - the committed lockfiles, used --locked;
#   - host Rust 1.98.1 (rust-toolchain.toml);
#   - RISC Zero's guest toolchain Rust 1.91.1 (LEZ's own guest builds use r0.1.91.1), alone in RISC0_HOME:
#         export RISC0_HOME="$PWD/.risc0-guest" && rzup install rust 1.91.1 && rzup install cpp 2024.1.5
#     and r0vm 3.0.5 on PATH, which computes the image id;
#   - scripts/guest-rustc (cargo's rustc wrapper, .cargo/config.toml), which remaps every build path to a fixed
#     name and replaces cargo's path-dependent -C metadata for the zkVM units (see guest-rustc.py).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
R0="${RISC0_HOME:-$HOME/.risc0}"
rusts="$(ls "$R0/toolchains" 2>/dev/null | grep -- '-rust-' || true)"
case "$rusts" in
  v1.91.1-rust-*) ;;
  *) echo "RISC0_HOME ($R0) must hold RISC Zero's Rust 1.91.1 and no other Rust; it holds: ${rusts:-nothing}" >&2; exit 1 ;;
esac
command -v r0vm >/dev/null || { echo "r0vm 3.0.5 is not on PATH" >&2; exit 1; }
export RUSTC_WRAPPER="$ROOT/scripts/guest-rustc" RISC0_BUILD_LOCKED=1 CARGO_TERM_COLOR=never
unset CARGO_TARGET_DIR RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RISC0_SKIP_BUILD
cd "$ROOT"
cargo build -p escapement-methods --locked >&2
bin="$ROOT/target/riscv-guest/escapement-methods/escapement-guest/riscv32im-risc0-zkvm-elf/release/escapement.bin"
line="$(printf 'escapement\t%s\t%s\t%s' "$(r0vm --elf "$bin" --id 2>&1 | tail -n 1)" "$(sha256sum "$bin" | cut -c1-64)" "$(wc -c < "$bin" | tr -d ' ')")"
echo "$line"
if [ "${1:-}" = "--check" ]; then
  if [ "$(grep -v '^#' "$ROOT/image-ids.tsv")" = "$line" ]; then
    echo "the image id matches image-ids.tsv" >&2
  else
    echo "MISMATCH against image-ids.tsv" >&2
    exit 1
  fi
fi
