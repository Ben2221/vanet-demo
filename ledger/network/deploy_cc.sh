#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
CC_PATH="$REPO_ROOT/ledger/chaincode/vanetauth"
VERSION_FILE="$SCRIPT_DIR/VERSION"

if [[ ! -x "$FABRIC_HOME/test-network/network.sh" ]]; then
  echo "Fabric test-network not found at $TN. Run ./ledger/network/install_fabric.sh first." >&2
  exit 1
fi

"$REPO_ROOT/ledger/chaincode/vanetauth/build.sh"

cd "$TN"
source "$SCRIPT_DIR/env.sh"
use_identity 1 Admin

if [[ -n "${CC_VERSION:-}" || -n "${CC_SEQ:-}" ]]; then
  if [[ -z "${CC_VERSION:-}" || -z "${CC_SEQ:-}" ]]; then
    echo "Set both CC_VERSION and CC_SEQ when overriding the chaincode definition." >&2
    exit 2
  fi
elif peer lifecycle chaincode querycommitted -C "$CHANNEL" -n "$CC_NAME" >/dev/null 2>&1; then
  read -r CC_VERSION CC_SEQ < "$VERSION_FILE"
else
  CC_VERSION="${FRESH_CC_VERSION:-1.4}"
  CC_SEQ=1
fi

if [[ -z "${CC_VERSION:-}" || ! "${CC_SEQ:-}" =~ ^[0-9]+$ ]]; then
  echo "Invalid chaincode target in $VERSION_FILE; expected '<version> <sequence>'." >&2
  exit 2
fi

echo "Deploying $CC_NAME version $CC_VERSION sequence $CC_SEQ"
args=(-c "$CHANNEL" -ccn "$CC_NAME" -ccp "$CC_PATH" -ccl go -ccv "$CC_VERSION" -ccs "$CC_SEQ")
if [[ -n "${CC_EP:-}" ]]; then
  args+=(-ccep "$CC_EP")
fi
./network.sh deployCC "${args[@]}"
