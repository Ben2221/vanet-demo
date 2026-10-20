"""One readable results page per experiment (Person 4): the numbers to put on the slides.

    python experiments/report.py experiments/results/<name>

Reads aggregate.csv, runs.csv and the run folders written by experiments/run.py and writes
<results>/REPORT.md: a headline table (mean +- 95 % CI over the seeds) per setting, which
detector checks fired on attackers and on honest vehicles, and the list of figures.
"""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.collect import flag_checks  # noqa: E402

# (column, header, format); a column that no row has is left out
HEADLINE = [
    ("auth_ms_median", "auth latency, median (ms)", "{:.2f}"),
    ("auth_ms_p95", "auth latency, p95 (ms)", "{:.2f}"),
    ("handover_ms_median", "handover latency, median (ms)", "{:.2f}"),
    ("auth_success_ratio", "auth success", "{:.3f}"),
    ("handover_success_ratio", "handover success", "{:.3f}"),
    ("handover_via_preauth", "handovers via PREAUTH", "{:.2f}"),
    ("pdr", "BSM PDR", "{:.3f}"),
    ("cbr_rsu_mean", "channel busy (RSU)", "{:.3f}"),
    ("security_bytes_per_bsm", "security bytes / BSM", "{:.0f}"),
    ("detection_rate", "attackers reported", "{:.2f}"),
    ("revocation_rate", "attackers revoked", "{:.2f}"),
    ("first_report_delay_s_median", "first lie -> report, median (s)", "{:.2f}"),
    ("report_to_revocation_s_mean", "report -> revocation (s)", "{:.2f}"),
    ("attack_to_exclusion_s_mean", "first lie -> identity reveal (s)", "{:.2f}"),
    ("honest_flagged", "honest flagged", "{:.1f}"),
    ("honest_reported", "honest reported", "{:.1f}"),
    ("honest_revoked", "honest revoked", "{:.1f}"),
    ("pseudonym_changes_per_vehicle", "pseudonym changes / vehicle", "{:.1f}"),
]
SETTING_KEYS = ["protocol", "vehicles", "attacker_ratio", "rsu_spacing", "beacon_rate", "report_k", "attack"]


def _read(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _cell(row: dict, col: str, fmt: str) -> str:
    v = row.get(col)
    if v in (None, ""):
        return "–"
    ci = row.get(col + "_ci95")
    s = fmt.format(float(v))
    return f"{s} ± {fmt.format(float(ci))}" if ci not in (None, "", "0.0") and float(ci) > 0 else s


def headline_table(agg: list[dict]) -> str:
    keys = [k for k in SETTING_KEYS if k in agg[0]]
    cols = [(c, h, f) for c, h, f in HEADLINE if any(r.get(c) not in (None, "") for r in agg)]
    # one table per setting would be too wide: transpose (metrics as rows, settings as columns)
    settings = [", ".join(f"{k}={r[k]}" for k in keys) or "all" for r in agg]
    lines = ["| metric | " + " | ".join(settings) + " |", "|---|" + "---|" * len(settings)]
    for c, h, f in cols:
        lines.append(f"| {h} | " + " | ".join(_cell(r, c, f) for r in agg) + " |")
    lines.append("| seeds | " + " | ".join(str(r.get("n_seeds", "")) for r in agg) + " |")
    return "\n".join(lines)


def checks_table(results: Path) -> str:
    totals: dict[str, dict[str, int]] = {"attacker": defaultdict(int), "honest": defaultdict(int)}
    for d in sorted((results / "runs").glob("*")):
        if (d / "metrics.csv").exists():
            for who, counts in flag_checks(d).items():
                for k, n in counts.items():
                    totals[who][k] += n
    names = sorted(set(totals["attacker"]) | set(totals["honest"]))
    if not names:
        return "_No DETECT_FLAG rows with check names (run with `--protocol real`)._"
    lines = ["| check | flags on attackers | flags on honest vehicles |", "|---|---|---|"]
    for k in names:
        lines.append(f"| {k} | {totals['attacker'].get(k, 0)} | {totals['honest'].get(k, 0)} |")
    return "\n".join(lines)


def write_report(results: str | Path) -> Path:
    results = Path(results)
    agg = _read(results / "aggregate.csv")
    figs = sorted((results / "plots").glob("*.png"))
    parts = [
        f"# Results: {results.name}",
        "",
        "Mean ± 95 % confidence interval over the seeds. Latencies are simulated time "
        "(radio + queueing + the measured compute times). `–` = not measured in this setting.",
        "",
        headline_table(agg),
        "",
        "## Which detector checks fired",
        "",
        "Counted once per pseudonym and RSU (the first flag). Honest flags alone revoke nothing: "
        "a pseudonym is reported after K flagged BSMs out of W, and revoked when 2 different RSUs report it.",
        "",
        checks_table(results),
        "",
        "## Figures",
        "",
        *[f"![{p.stem}](plots/{p.name})" for p in figs],
        "",
    ]
    out = results / "REPORT.md"
    out.write_text("\n".join(parts))
    return out


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results_dir")
    print(write_report(ap.parse_args().results_dir))
