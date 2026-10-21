#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"

if [[ ! -x "$TN/network.sh" ]]; then
  echo "Fabric test-network not found at $TN." >&2
  exit 1
fi

cd "$TN"
./network.sh down
