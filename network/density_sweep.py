"""Run the full scenario for several vehicle counts and seeds (Person 1's results:
delay and delivery ratio against vehicle density, channel busy ratio).

Each run is a separate process (ns-3 keeps global state), results are the mean
over seeds with a 95 % confidence interval (Student t).

  python network/density_sweep.py --vehicles 50 100 150 200 --seeds 1 2 3 --duration 120
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262}


def ci95(values: list[float]) -> tuple[float, float]:
    if not values:
        return math.nan, math.nan
    m = statistics.fmean(values)
    if len(values) < 2:
        return m, 0.0
    return m, T95.get(len(values) - 1, 1.96) * statistics.stdev(values) / math.sqrt(len(values))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vehicles", type=int, nargs="+", default=[50, 100, 150, 200])
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--backend", default="auto")
    ap.add_argument("--protocol", default="stub")
    ap.add_argument("--out", type=Path, default=ROOT / "experiments" / "results" / "density_sweep")
    ap.add_argument("extra", nargs=argparse.REMAINDER, help="more run_scenario.py options after --")
    a = ap.parse_args()
    extra = [x for x in a.extra if x != "--"]
    rows = []
    for n in a.vehicles:
        per = {"pdr": [], "bsm_delay_ms": [], "cbr_rsu": []}
        for seed in a.seeds:
            out = a.out / f"v{n}_s{seed}"
            cmd = [sys.executable, str(ROOT / "network" / "run_scenario.py"), "--vehicles", str(n),
                   "--seed", str(seed), "--duration", str(a.duration), "--backend", a.backend,
                   "--protocol", a.protocol, "--out", str(out), "--quiet", *extra]
            print("running", " ".join(cmd[2:]), flush=True)
            subprocess.run(cmd, check=True)
            s = json.loads((out / "summary.json").read_text())
            per["pdr"].append(s["broadcast_pdr"])
            per["bsm_delay_ms"].append(s["delay_ms"].get("BSM", {}).get("mean", math.nan))
            per["cbr_rsu"].append(s["cbr_rsu_mean"])
        row = {"vehicles": n, "seeds": len(a.seeds)}
        for k, v in per.items():
            row[f"{k}_mean"], row[f"{k}_ci95"] = ci95([x for x in v if x is not None])
        rows.append(row)
    a.out.mkdir(parents=True, exist_ok=True)
    path = a.out / "density_sweep.csv"
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {path}")
    try:
        sys.path.insert(0, str(ROOT))
        from network.plots import plot_sweep
        print(f"plot: {plot_sweep(path)}")
    except ImportError:
        print("matplotlib not installed: no plot")


if __name__ == "__main__":
    main()
