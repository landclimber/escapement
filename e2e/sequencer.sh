#!/usr/bin/env bash
# A local standalone LEZ v0.4.0-rc3 sequencer (mock Bedrock, no Logos Blockchain node, no network
# beyond loopback) and the Escapement CLI that talks to it (crates/escapement-cli).
#
#   e2e/sequencer.sh build          build sequencer_service (feature `standalone`) and the CLI
#   e2e/sequencer.sh build-sequencer   only the sequencer
#   e2e/sequencer.sh start          set up a fresh home from LEZ's local.json and start it
#   e2e/sequencer.sh stop           stop it (SIGTERM, then SIGKILL after 40 s)
#   e2e/sequencer.sh status         pid and head block
#   e2e/sequencer.sh rpc METHOD [PARAMS_JSON]   one JSON-RPC call (curl)
#   e2e/sequencer.sh cli ARGS...    the Escapement CLI against this sequencer (escapement --help)
#
# Environment:
#   LEZ_SRC        a LEZ checkout at tag v0.4.0-rc3 (default: cloned into $E2E_HOME/lez-v0.4.0-rc3)
#   E2E_HOME       run directory (default: e2e/.run, ignored by git)
#   E2E_OUT        where smoke writes its records (default: $E2E_HOME/out)
#   E2E_RPC_PORT   RPC port on 127.0.0.1 (default 3040)
#   E2E_BLOCK_TIME block interval (default 2s; LEZ's local.json says 15s)
#   E2E_DEV_MODE   1: the sequencer accepts dev-mode (fake) receipts and the CLI makes them;
#                  unset: real proofs, verified by the sequencer
#   CARGO_TARGET_DIR, CARGO_BUILD_JOBS   as usual
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_HOME="${E2E_HOME:-$HERE/.run}"
E2E_OUT="${E2E_OUT:-$E2E_HOME/out}"
LEZ_TAG=v0.4.0-rc3
LEZ_COMMIT=bafd07be  # the tag's commit (prefix)
LEZ_SRC="${LEZ_SRC:-$E2E_HOME/lez-$LEZ_TAG}"
RPC_PORT="${E2E_RPC_PORT:-3040}"
BLOCK_TIME="${E2E_BLOCK_TIME:-2s}"
RPC="http://127.0.0.1:$RPC_PORT"
TARGET="${CARGO_TARGET_DIR:-$E2E_HOME/target}"
BIN="$E2E_HOME/bin"
HOME_DIR="$E2E_HOME/sequencer_home"
PID_FILE="$E2E_HOME/sequencer.pid"
LOG="$E2E_HOME/sequencer.log"
# Funded key of LEZ's local Bedrock node (Justfile BEDROCK_FUNDING_PUBLIC_KEY); with the mock
# Bedrock it pays nothing, but `setup` requires it.
FUNDING_PK=2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26
mkdir -p "$E2E_HOME" "$E2E_OUT" "$BIN"

die() { echo "sequencer.sh: $*" >&2; exit 1; }

ensure_lez() {
  if [ ! -d "$LEZ_SRC/.git" ] && [ ! -f "$LEZ_SRC/Cargo.toml" ]; then
    git clone --quiet --depth 1 --branch "$LEZ_TAG" https://github.com/logos-blockchain/logos-execution-zone.git "$LEZ_SRC"
  fi
  if [ -d "$LEZ_SRC/.git" ]; then
    local head; head="$(git -C "$LEZ_SRC" rev-parse HEAD)"
    case "$head" in "$LEZ_COMMIT"*) ;; *) die "$LEZ_SRC is at $head, not $LEZ_TAG ($LEZ_COMMIT)";; esac
  fi
}

build_sequencer() {
  ensure_lez
  ( cd "$LEZ_SRC" && CARGO_TARGET_DIR="$TARGET" cargo build --release --locked -p sequencer_service --features standalone )
  cp "$TARGET/release/sequencer_service" "$BIN/sequencer_service_standalone"
  sha256sum "$BIN/sequencer_service_standalone" | cut -d' ' -f1 > "$BIN/sequencer_service_standalone.sha256"
  echo "built: $BIN/sequencer_service_standalone ($(cat "$BIN/sequencer_service_standalone.sha256"))"
}

build_cli() {
  ( cd "$HERE/../crates/escapement-cli" && cargo build --release --locked ${E2E_CLI_CARGO_ARGS:-} )
  cp "$HERE/../crates/escapement-cli/target/release/escapement" "$BIN/escapement"
  echo "built: $BIN/escapement"
}

build() { build_sequencer; build_cli; }

rpc() { # METHOD [PARAMS_JSON]
  curl -sS -m 10 -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "$RPC"
}

head_block() { rpc getLastBlockId 2>/dev/null | sed -n 's/.*"result":\([0-9]*\).*/\1/p'; }

running() { [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; }

start() {
  [ -x "$BIN/sequencer_service_standalone" ] || die "build first"
  ensure_lez
  running && die "already running (pid $(cat "$PID_FILE"))"
  rm -rf "$HOME_DIR" "$E2E_HOME/config"; mkdir -p "$E2E_HOME/config"
  # LEZ's local network config, on loopback, with our block interval, and without gossip: one
  # sequencer needs no peers (and QUIC is refused by some sandboxes).
  python3 -I - "$LEZ_SRC/lez/sequencer/service/networks/local.json" "$E2E_HOME/config/sequencer_config.json" "$BLOCK_TIME" <<'EOF'
import json, sys
src, dst, block_time = sys.argv[1:4]
config = json.load(open(src))
config.pop("gossip", None)
config["bedrock_config"]["node_url"] = "http://127.0.0.1:18080"
config["block_create_timeout"] = block_time
json.dump(config, open(dst, "w"), indent=4)
EOF
  "$BIN/sequencer_service_standalone" setup "$HOME_DIR" --config "$E2E_HOME/config/sequencer_config.json" \
    --funding-public-key "$FUNDING_PK" --create-channel > "$E2E_HOME/setup.log" 2>&1 || { cat "$E2E_HOME/setup.log"; die "setup failed"; }
  local devenv=(env -u RISC0_DEV_MODE)
  [ "${E2E_DEV_MODE:-}" = 1 ] && devenv=(env RISC0_DEV_MODE=1)
  "${devenv[@]}" RUST_LOG="${E2E_RUST_LOG:-info,risc0_zkvm=warn,kameo=warn}" \
    "$BIN/sequencer_service_standalone" start "$HOME_DIR" --rpc-listen-address "127.0.0.1:$RPC_PORT" > "$LOG" 2>&1 &
  echo $! > "$PID_FILE"
  local t0; t0=$(date +%s)
  for _ in $(seq 1 180); do
    local h; h="$(head_block || true)"
    if [ -n "$h" ] && [ "$h" -ge 1 ]; then echo "started: pid $(cat "$PID_FILE"), head $h after $(( $(date +%s) - t0 )) s, RPC $RPC"; return 0; fi
    running || { tail -40 "$LOG"; die "the sequencer exited"; }
    sleep 1
  done
  tail -40 "$LOG"; die "no RPC answer within 180 s"
}

stop() {
  running || { echo "not running"; rm -f "$PID_FILE"; return 0; }
  local pid; pid="$(cat "$PID_FILE")"
  kill -TERM "$pid"
  for _ in $(seq 1 80); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
  if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid"; echo "stopped (SIGKILL) pid $pid"; else echo "stopped pid $pid"; fi
  rm -f "$PID_FILE"
}

cli() {
  local devenv=(env -u RISC0_DEV_MODE)
  [ "${E2E_DEV_MODE:-}" = 1 ] && devenv=(env RISC0_DEV_MODE=1)
  "${devenv[@]}" LEZ_RPC="$RPC" "$BIN/escapement" "$@"
}

case "${1:-}" in
  build) build ;;
  build-sequencer) build_sequencer ;;
  build-cli) build_cli ;;
  start) start ;;
  stop) stop ;;
  status) if running; then echo "running: pid $(cat "$PID_FILE"), head $(head_block)"; else echo "not running"; fi ;;
  rpc) shift; rpc "$@"; echo ;;
  cli) shift; cli "$@" ;;
  *) sed -n '2,23p' "${BASH_SOURCE[0]}"; exit 2 ;;
esac
