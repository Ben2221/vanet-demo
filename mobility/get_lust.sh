#!/usr/bin/env bash
# Download the LuST Scenario (Luxembourg, 24 h, Codeca et al. IEEE VNC 2015; MIT licence)
# into mobility/real/LuSTScenario (~450 MB). Used by mobility/real_scenario.py (--real lust:...).
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/real"
mkdir -p "$DIR"
if [[ -f "$DIR/LuSTScenario/scenario/dua.static.sumocfg" ]]; then
  echo "LuST already at $DIR/LuSTScenario"
  exit 0
fi
git clone --depth 1 https://github.com/lcodeca/LuSTScenario.git "$DIR/LuSTScenario"
echo "LuST ready at $DIR/LuSTScenario"
