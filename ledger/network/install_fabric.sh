#!/usr/bin/env bash
set -euo pipefail

FABRIC_VERSION="${FABRIC_VERSION:-2.5.16}"
FABRIC_INSTALL_ROOT="${FABRIC_INSTALL_ROOT:-$HOME/fabric}"
LOCAL_BIN="$HOME/.local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER_URL="https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh"

for tool in curl docker; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Required command not found: $tool" >&2
    exit 1
  fi
done

docker compose version >/dev/null
mkdir -p "$LOCAL_BIN"
export PATH="$LOCAL_BIN:$PATH"

if ! command -v jq >/dev/null 2>&1; then
  case "$(uname -m)" in
    x86_64) JQ_ASSET=jq-linux-amd64 ;;
    aarch64|arm64) JQ_ASSET=jq-linux-arm64 ;;
    *) echo "jq is required; install it with your Linux package manager." >&2; exit 1 ;;
  esac

  curl -fsSL "https://github.com/jqlang/jq/releases/download/jq-1.7.1/$JQ_ASSET" -o "$LOCAL_BIN/jq"
  chmod +x "$LOCAL_BIN/jq"
  if ! "$LOCAL_BIN/jq" --version >/dev/null; then
    rm -f "$LOCAL_BIN/jq"
    echo "Failed to install jq." >&2
    exit 1
  fi
  export PATH="$LOCAL_BIN:$PATH"
fi

chmod +x "$SCRIPT_DIR/go"
ln -sf "$SCRIPT_DIR/go" "$LOCAL_BIN/go"
export PATH="$LOCAL_BIN:$PATH"

mkdir -p "$FABRIC_INSTALL_ROOT"
if [[ -x "$FABRIC_INSTALL_ROOT/fabric-samples/test-network/network.sh" && \
      -x "$FABRIC_INSTALL_ROOT/fabric-samples/bin/peer" && \
      -x "$FABRIC_INSTALL_ROOT/fabric-samples/bin/fabric-ca-client" ]] && \
   "$FABRIC_INSTALL_ROOT/fabric-samples/bin/peer" version | grep -q "Version: v$FABRIC_VERSION\$"; then
  echo "Fabric already installed at $FABRIC_INSTALL_ROOT/fabric-samples; skipping download."
else
  cd "$FABRIC_INSTALL_ROOT"
  curl -fsSLo install-fabric.sh "$INSTALLER_URL"
  chmod +x install-fabric.sh
  ./install-fabric.sh --fabric-version "$FABRIC_VERSION" docker samples binary
fi

echo "Fabric $FABRIC_VERSION is ready at $FABRIC_INSTALL_ROOT/fabric-samples"
echo "In this shell, run: export FABRIC_HOME=\"$FABRIC_INSTALL_ROOT/fabric-samples\""
