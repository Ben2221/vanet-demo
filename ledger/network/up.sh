#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
BATCH_TIMEOUT="${BATCH_TIMEOUT:-500ms}"

if [[ ! "$BATCH_TIMEOUT" =~ ^[0-9]+(ms|s|m)$ ]]; then
  echo "BATCH_TIMEOUT must be a duration such as 200ms, 500ms, or 2s." >&2
  exit 2
fi
if [[ ! -x "$TN/network.sh" ]]; then
  echo "Fabric test-network not found at $TN. Run ./ledger/network/install_fabric.sh first." >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to start the Fabric network." >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required; run ./ledger/network/install_fabric.sh first." >&2
  exit 1
fi
docker compose version >/dev/null

CONFIG="$TN/configtx/configtx.yaml"
BACKUP="$TN/configtx/configtx.yaml.orig"
if [[ ! -f "$BACKUP" ]]; then
  cp "$CONFIG" "$BACKUP"
fi
cp "$BACKUP" "$CONFIG"
if ! grep -qE 'BatchTimeout:[[:space:]]*2s' "$CONFIG"; then
  echo "Expected the Fabric sample's default BatchTimeout: 2s in $CONFIG." >&2
  exit 1
fi
sed -i -E "s/(BatchTimeout:[[:space:]]*)2s/\\1$BATCH_TIMEOUT/g" "$CONFIG"

cd "$TN"
./network.sh down
./network.sh up createChannel -c "$CHANNEL" -ca
"$SCRIPT_DIR/deploy_cc.sh"
"$SCRIPT_DIR/enroll_identities.sh"
"$SCRIPT_DIR/smoke_test.sh"
