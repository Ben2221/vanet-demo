"""Print the key numbers of scenario runs as one table (Person 4).

    python experiments/show.py                       # every run under experiments/results/
    python experiments/show.py <run dir> [<run dir> ...]
    python experiments/show.py experiments/results/compare_real   # a sweep: its aggregate.csv

A run directory is anything with a summary.json (written by network/run_scenario.py);
the numbers come from experiments/collect.py, the same code the sweeps use.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.collect import collect_run  # noqa: E402

COLUMNS = [  # (header, key, format)
    ("auth p50 ms", "auth_ms_median", "{:.2f}"),
    ("auth p95 ms", "auth_ms_p95", "{:.2f}"),
    ("hand p95 ms", "handover_ms_p95", "{:.2f}"),
    ("BSM B", "bsm_bytes", "{:.0f}"),
    ("sec B/BSM", "security_bytes_per_bsm", "{:.0f}"),
    ("PDR", "pdr", "{:.3f}"),
    ("CBR", "cbr_rsu_mean", "{:.3f}"),
    ("caught", "attackers_reported", "{:.0f}"),
    ("attackers", "attackers", "{:.0f}"),
    ("honest rep", "honest_reported", "{:.0f}"),
]


def _fmt(row: dict, key: str, fmt: str) -> str:
    v = row.get(key)
    try:
        return fmt.format(float(v))
    except (TypeError, ValueError):
        return "-"


def _print(rows: list[tuple[str, dict]]) -> None:
    headers = ["run"] + [h for h, _, _ in COLUMNS]
    table = [[name] + [_fmt(r, k, f) for _, k, f in COLUMNS] for name, r in rows]
    widths = [max(len(x) for x in col) for col in zip(headers, *table)]
    line = lambda cells: "  ".join(c.ljust(w) if i == 0 else c.rjust(w)  # noqa: E731
                                   for i, (c, w) in enumerate(zip(cells, widths)))
    print(line(headers))
    print("  ".join("-" * w for w in widths))
    for cells in table:
        print(line(cells))


def _sweep(d: Path) -> list[tuple[str, dict]]:
    with (d / "aggregate.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    cols = list(rows[0]) if rows else []
    keys = cols[:cols.index("n_seeds")] if "n_seeds" in cols else cols[:1]   # the swept settings
    out = []
    for r in rows:
        label = " ".join(f"{k}={r[k].replace('experiments.baselines.', '')}" for k in keys if r.get(k))
        out.append((label, r))
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dirs", nargs="*", help="run or sweep folders (default: experiments/results/*)")
    a = ap.parse_args(argv)
    dirs = [Path(d) for d in a.dirs] or sorted((ROOT / "experiments" / "results").glob("*"))
    runs, sweeps = [], []
    for d in dirs:
        if (d / "aggregate.csv").exists():
            sweeps.append(d)
        elif (d / "summary.json").exists():
            runs.append((d.name, collect_run(d)))
    if not runs and not sweeps:
        raise SystemExit("no runs found; try: make run")
    if runs:
        _print(runs)
    for d in sweeps:
        print(f"\n{d.name} (mean over seeds; runs.csv has every run, plots/ the figures)")
        _print(_sweep(d))
    print("\nper run: summary.json (all numbers), metrics.csv (one row per event), "
          "flowmon.xml / netanim.xml with --backend ns3 [--netanim]")


if __name__ == "__main__":
    main()
