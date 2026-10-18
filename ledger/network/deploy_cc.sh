#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQ="${CC_SEQ:-1}"
CC_PATH="$REPO_ROOT/ledger/chaincode/vanetauth"

if [[ ! -x "$FABRIC_HOME/test-network/network.sh" ]]; then
  echo "Fabric test-network not found at $TN. Run ./ledger/network/install_fabric.sh first." >&2
  exit 1
fi

"$REPO_ROOT/ledger/chaincode/vanetauth/build.sh"

cd "$TN"
args=(-c "$CHANNEL" -ccn "$CC_NAME" -ccp "$CC_PATH" -ccl go -ccv "$CC_VERSION" -ccs "$CC_SEQ")
if [[ -n "${CC_EP:-}" ]]; then
  args+=(-ccep "$CC_EP")
fi
./network.sh deployCC "${args[@]}"
