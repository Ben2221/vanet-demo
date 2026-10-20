"""Copy finished experiments into docs/results/ so they are versioned and viewable on GitHub,
and write docs/results/results.json, the numbers the slide deck (docs/presentation) reads.

    python experiments/export_results.py compare_bsm_ticket attacks sweep_report_k

experiments/results/ is git-ignored (run folders are large); this keeps only REPORT.md,
aggregate.csv and plots/ of each experiment.
"""

from __future__ import annotations

import csv
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "experiments" / "results"
DOCS = ROOT / "docs" / "results"


def _num(v):
    try:
        return float(v) if v not in ("", None) else None
    except ValueError:
        return v


def export(names: list[str]) -> Path:
    DOCS.mkdir(parents=True, exist_ok=True)
    data = json.loads((DOCS / "results.json").read_text()) if (DOCS / "results.json").exists() else {}
    for name in names:
        src, dst = RESULTS / name, DOCS / name
        if not (src / "aggregate.csv").exists():
            raise SystemExit(f"{src}/aggregate.csv not found: run experiments/run.py first")
        if dst.exists():
            shutil.rmtree(dst)
        (dst / "plots").mkdir(parents=True)
        for f in ("aggregate.csv", "REPORT.md"):
            if (src / f).exists():
                shutil.copy(src / f, dst / f)
        for p in (src / "plots").glob("*"):
            shutil.copy(p, dst / "plots" / p.name)
        with (src / "aggregate.csv").open(newline="") as f:
            data[name] = [{k: _num(v) for k, v in r.items()} for r in csv.DictReader(f)]
    out = DOCS / "results.json"
    out.write_text(json.dumps(data, indent=1))
    return out


if __name__ == "__main__":
    print(export(sys.argv[1:]))
