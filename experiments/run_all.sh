#!/usr/bin/env bash
# Every v3 experiment, one config after the other (make evaluate-all). Each config runs JOBS
# ns-3 runs in parallel and skips runs that already have results (use --force to redo).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
PY=${PY:-.venv/bin/python}
JOBS=${JOBS:-5}
for cfg in compare_v3 ablation_v3 trust_v3 sensitivity_obu sensitivity_attack sensitivity_attackers \
           mixzone_tradeoff compare_lust; do
  echo "== $cfg $(date +%H:%M)"
  j=$JOBS
  [[ $cfg == compare_lust ]] && j=${JOBS_LUST:-4}     # LuST peak runs need ~2 GB each
  $PY experiments/run.py --config "experiments/configs/$cfg.json" --jobs "$j" --no-plots "$@"
  $PY experiments/plots.py "experiments/results/$cfg" > /dev/null
  $PY experiments/report.py "experiments/results/$cfg"
done
$PY experiments/dashboard.py
echo "== done $(date +%H:%M)"
