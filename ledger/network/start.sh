#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${FABRIC_HOME:-}" ]]; then
  export FABRIC_INSTALL_ROOT="${FABRIC_INSTALL_ROOT:-$(dirname "$FABRIC_HOME")}"
else
  export FABRIC_INSTALL_ROOT="${FABRIC_INSTALL_ROOT:-$HOME/fabric}"
  export FABRIC_HOME="$FABRIC_INSTALL_ROOT/fabric-samples"
fi

"$SCRIPT_DIR/install_fabric.sh"
exec "$SCRIPT_DIR/up.sh"
