#!/usr/bin/env bash
# One-command setup for a fresh clone (Linux / WSL2):
#
#   ./setup.sh               Python venv + all requirements + ns-3 + gateway npm packages
#   ./setup.sh --no-ns3      skip ns-3 (scripts then use the lite backend)
#   ./setup.sh --no-gateway  skip npm ci for the Fabric gateway
#   ./setup.sh --fabric      also install and start Hyperledger Fabric (needs Docker)
#
# Safe to re-run: it reuses .venv and skips what is already installed.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

WANT_NS3=1 WANT_GATEWAY=1 WANT_FABRIC=0
for arg in "$@"; do
  case "$arg" in
    --no-ns3) WANT_NS3=0 ;;
    --no-gateway) WANT_GATEWAY=0 ;;
    --fabric) WANT_FABRIC=1 ;;
    -h|--help) sed -n 2,9p "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n== %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

# ---------------------------------------------------------------- Python 3.11-3.13
# ns-3's wheel and coincurve have no Python 3.14 builds yet.
py_ok() { "$1" -c 'import sys; sys.exit(not (3, 11) <= sys.version_info[:2] <= (3, 13))' 2>/dev/null; }

PY=""
if [[ -x .venv/bin/python ]] && py_ok .venv/bin/python; then
  PY=.venv/bin/python
else
  if [[ -e .venv ]]; then
    warn ".venv uses an unsupported Python; recreating it"
    rm -rf .venv
  fi
  for cand in python3.13 python3.12 python3.11 python3; do
    if command -v "$cand" >/dev/null && py_ok "$(command -v "$cand")"; then
      BASE="$(command -v "$cand")"
      break
    fi
  done
  if [[ -z "${BASE:-}" ]] && command -v uv >/dev/null; then
    say "No Python 3.11-3.13 found; installing Python 3.13 with uv"
    uv python install 3.13
    BASE="$(uv python find 3.13)"
  fi
  if [[ -z "${BASE:-}" ]]; then
    echo "Python 3.11-3.13 is required (found: $(python3 --version 2>&1))." >&2
    echo "Install it (e.g. 'sudo dnf install python3.13' / 'sudo apt install python3.12')" >&2
    echo "or install uv (https://docs.astral.sh/uv/) and re-run ./setup.sh." >&2
    exit 1
  fi
  say "Creating .venv with $("$BASE" --version)"
  if ! "$BASE" -m venv .venv 2>/dev/null; then
    command -v uv >/dev/null || { echo "python venv module missing (apt install python3-venv)" >&2; exit 1; }
    uv venv --python "$BASE" .venv
  fi
  PY=.venv/bin/python
fi

pip_install() {
  if "$PY" -m pip --version >/dev/null 2>&1; then
    "$PY" -m pip install --disable-pip-version-check -q "$@"
  else
    uv pip install --python "$PY" -q "$@"     # venvs made by uv have no pip
  fi
}

say "Installing Python requirements"
pip_install -r requirements.txt

# ---------------------------------------------------------------- ns-3 (optional)
if [[ "$WANT_NS3" == 1 ]]; then
  if "$PY" -c 'import ns' >/dev/null 2>&1; then
    echo "ns-3 already installed"
  elif [[ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]]; then
    warn "ns-3 wheels exist only for Linux x86_64; using the lite backend (or use the Dockerfile)"
  else
    say "Installing ns-3 (first time compiles cppyy, ~10 min, needs g++ and ~4 GB RAM)"
    pip_install ns3 || warn "ns-3 install failed; scripts fall back to the lite backend"
  fi
  # uv stores CPyCppyy's headers as include/site/pythonX.Y/cpycppyy, but cppyy looks for
  # CPyCppyy (case-sensitive), so callbacks into Python fail. Add the expected name.
  for inc in .venv/include/site/python3.*; do
    if [[ -d "$inc/cpycppyy" && ! -e "$inc/CPyCppyy" ]]; then
      ln -s cpycppyy "$inc/CPyCppyy"
    fi
  done
fi

# ---------------------------------------------------------------- Fabric gateway (optional)
if [[ "$WANT_GATEWAY" == 1 ]]; then
  if ! command -v node >/dev/null; then
    warn "Node.js not found; skipping the Fabric gateway (needs Node >= 22.12). The mock ledger works without it."
  elif ! node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=12)?0:1)'; then
    warn "Node $(node --version) is too old for the gateway (needs >= 22.12); skipping npm ci"
  elif [[ -d ledger/gateway/node_modules ]]; then
    echo "gateway npm packages already installed"
  else
    say "Installing the Fabric gateway's npm packages"
    (cd ledger/gateway && npm ci --no-audit --no-fund)
  fi
fi

# ---------------------------------------------------------------- Fabric network (opt-in)
if [[ "$WANT_FABRIC" == 1 ]]; then
  say "Installing and starting Hyperledger Fabric (Docker)"
  ./ledger/start.sh
fi

say "Checking the install"
"$PY" - <<'EOF'
import importlib.util
from pathlib import Path
import sumo
ok = Path(sumo.SUMO_HOME, "bin", "sumo").exists()
ns3 = importlib.util.find_spec("ns") is not None
print(f"  SUMO   {'ok' if ok else 'MISSING'}  ({sumo.SUMO_HOME})")
print(f"  ns-3   {'ok' if ns3 else 'not installed (lite backend will be used)'}")
EOF

cat <<'EOF'

Setup done. Next:
  make test            run all tests
  make run             one scenario (real protocol); results in experiments/results/
  make show            print the key numbers of every run
  make help            all targets
EOF
