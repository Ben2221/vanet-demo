#!/usr/bin/env bash
# Commit latency of Raft vs BFT ordering on a real Fabric network (Docker).
#
#   ./ledger/bench/consensus_bench.sh          # or: make ledger-bench
#
# Three networks, one after the other, all Fabric 3.1.5 (installed into ~/fabric3,
# next to the 2.5 install in ~/fabric), each with the vanetauth chaincode, CA identities
# and the REST gateway:
#   raft_500ms  Raft, 1 orderer, BatchTimeout 500 ms   (what the simulator's mock assumes)
#   raft_50ms   Raft, 1 orderer, BatchTimeout 50 ms    (same block cutting as BFT below)
#   bft_50ms    SmartBFT, 4 orderers (f = 1, n >= 3f + 1), RequestBatchMaxInterval 50 ms
# For each, ledger/bench/load.js submits auth records at BENCH_RATES tx/s for
# BENCH_SECONDS s and records the gateway's commit time. Results:
# experiments/results/ledger_consensus/<setup>.csv and summary.json.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
export FABRIC_VERSION="${FABRIC_VERSION:-3.1.5}"
export FABRIC_INSTALL_ROOT="${FABRIC_INSTALL_ROOT:-$HOME/fabric3}"
export FABRIC_HOME="$FABRIC_INSTALL_ROOT/fabric-samples"
export BENCH_SECONDS="${BENCH_SECONDS:-30}"
export BENCH_RATES="${BENCH_RATES:-5,10,20}"
PORT="${PORT:-3100}"
OUT="${OUT:-$REPO/experiments/results/ledger_consensus}"
SETUPS="${SETUPS:-raft_500ms raft_50ms bft_50ms}"
mkdir -p "$OUT"

if ss -ltnH "sport = :$PORT" 2>/dev/null | grep -q .; then
  echo "port $PORT is in use; run with PORT=<free port>" >&2
  exit 1
fi
"$REPO/ledger/network/install_fabric.sh" > "$OUT/install.log" 2>&1

GW_PID=""
cleanup() {
  [[ -n "$GW_PID" ]] && kill -- "-$GW_PID" 2>/dev/null || true
  "$REPO/ledger/network/down.sh" > /dev/null 2>&1 || true
}
trap cleanup EXIT

for setup in $SETUPS; do
  consensus="${setup%%_*}"
  batch="${setup#*_}"
  echo "== $setup: consensus=$consensus batch=$batch"
  "$REPO/ledger/network/down.sh" > /dev/null 2>&1 || true
  CONSENSUS="$consensus" BATCH_TIMEOUT="$batch" BFT_BATCH_INTERVAL="$batch" \
    "$REPO/ledger/network/up.sh" > "$OUT/$setup.up.log" 2>&1 || {
      echo "network failed to start; see $OUT/$setup.up.log" >&2; exit 1; }
  echo "   orderers: $(docker ps --format '{{.Names}}' | grep -c '^orderer')"
  (cd "$REPO/ledger/gateway" && exec setsid env PORT="$PORT" node server.js) > "$OUT/$setup.gateway.log" 2>&1 &
  GW_PID=$!
  for _ in $(seq 1 60); do
    curl -fs "http://127.0.0.1:$PORT/health" > /dev/null 2>&1 && break
    sleep 1
  done
  GATEWAY_URL="http://127.0.0.1:$PORT" node "$SCRIPT_DIR/load.js" | tee "$OUT/$setup.csv"
  kill -- "-$GW_PID" 2>/dev/null || true
  GW_PID=""
done

python3 - "$OUT" $SETUPS <<'EOF'
import csv, json, sys
from pathlib import Path
out, setups = Path(sys.argv[1]), sys.argv[2:]
summary = {s: list(csv.DictReader((out / f"{s}.csv").open())) for s in setups if (out / f"{s}.csv").exists()}
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
EOF
