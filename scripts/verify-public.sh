#!/usr/bin/env bash
# Re-reads every recorded Escapement transaction and account on the public network, read-only, and checks them
# against the chain (scripts/verify-public.py says what is checked). Needs python3 only.
#   scripts/verify-public.sh            through the network's public RPC (docs/public-network/network.json)
#   RPC=<url> scripts/verify-public.sh  through another endpoint serving the same chain
exec python3 -I "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/verify-public.py" "$@"
