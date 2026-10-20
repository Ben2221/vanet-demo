"""One readable comparison table per sweep (Person 4): every variant against every other.

    python experiments/report.py experiments/results/compare_v3 [more sweep dirs]

Writes <sweep>/report.md: for each setting of the swept parameter (e.g. vehicles) one
table, variants as rows, the key metrics as columns, "mean ± 95 % CI" over the seeds.
The arrow in each header says which direction is better. Plots are in <sweep>/plots/.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

# (header, column, format, better: "low" / "high" / "")
METRICS = [
    ("auth ms", "auth_ms_mean", "{:.2f}", "low"),
    ("ticket ms", "ticket_ms_mean", "{:.2f}", "low"),
    ("ticket ms after 10 s", "ticket_ms_steady_mean", "{:.2f}", "low"),
    ("handover ms", "handover_ms_mean", "{:.2f}", "low"),
    ("handovers", "handover_n", "{:.0f}", "low"),
    ("BSM/veh/s", "bsm_per_vehicle_s", "{:.2f}", "low"),
    ("BSM bytes", "bsm_bytes", "{:.0f}", "low"),
    ("safety B/veh/s", "safety_bytes_per_vehicle_s", "{:.0f}", "low"),
    ("PDR", "pdr", "{:.3f}", "high"),
    ("CBR", "cbr_rsu_mean", "{:.3f}", "low"),
    ("RSU accept ms", "rsu_accept_ms_mean", "{:.1f}", "low"),
    ("V2V verified", "v2v_verified_ratio", "{:.3f}", "high"),
    ("V2V accept ms", "v2v_accept_ms_mean", "{:.1f}", "low"),
    ("revoked accepted", "v2v_revoked_accepted_ratio", "{:.3f}", "low"),
    ("pos err p95 m", "awareness_error_m_p95", "{:.2f}", "low"),
    ("OBU load", "obu_cpu_util_mean", "{:.4f}", "low"),
    ("caught", "detection_rate", "{:.2f}", "high"),
    ("honest revoked", "honest_revoked", "{:.1f}", "low"),
    ("report->block s", "report_to_block_s_mean", "{:.2f}", "low"),
    ("tracked", "tracking_success", "{:.2f}", "low"),
    ("trip traced", "traceable_fraction", "{:.2f}", "low"),
]
ARROW = {"low": "↓", "high": "↑", "": ""}


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _cell(row: dict, col: str, fmt: str) -> str:
    m, ci = _f(row.get(col)), _f(row.get(col + "_ci95"))
    if m is None:
        return "–"
    return fmt.format(m) + (f" ± {fmt.format(ci)}" if ci else "")


def report(sweep: Path) -> Path:
    with (sweep / "aggregate.csv").open(newline="") as f:
        rows = list(csv.DictReader(f))
    cols = list(rows[0]) if rows else []
    keys = cols[:cols.index("n_seeds")] if "n_seeds" in cols else []
    series = "label" if "label" in keys else ("profile" if "profile" in keys else "protocol")
    # a swept setting is a grid parameter, not an option that only some variants set
    swept = [k for k in keys if k in ("vehicles", "real", "attacker_ratio", "rsu_spacing", "beacon_rate")
             and len({r[k] for r in rows}) > 1]
    metrics = [m for m in METRICS if any(_f(r.get(m[1])) is not None for r in rows)]
    lines = [f"# {sweep.name}", "",
             f"Mean ± 95 % confidence interval over {rows[0].get('n_seeds', '?')} seeds per cell. "
             "↓ lower is better, ↑ higher is better. Every run: experiments/results/"
             f"{sweep.name}/runs.csv; figures: plots/.", ""]
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(r[k] for k in swept), []).append(r)
    for key, rs in sorted(groups.items(), key=lambda kv: [(_f(v) if _f(v) is not None else -1.0) for v in kv[0]]):
        if swept:
            lines += [f"## " + ", ".join(f"{k} = {v}" for k, v in zip(swept, key)), ""]
        head = ["variant"] + [f"{h} {ARROW[b]}".strip() for h, _, _, b in metrics]
        lines.append("| " + " | ".join(head) + " |")
        lines.append("|" + "---|" * len(head))
        for r in rs:
            name = r.get(series, "").replace("experiments.baselines.", "")
            lines.append("| " + " | ".join([name] + [_cell(r, c, f) for _, c, f, _ in metrics]) + " |")
        lines.append("")
    lines += _significance(sweep, swept, series, metrics)
    out = sweep / "report.md"
    out.write_text("\n".join(lines))
    (sweep / "report.tex").write_text(_latex(groups, swept, series, metrics))
    return out


REFERENCE = "Phase-I"
CHALLENGERS = ("v3-fast", "v3-private")


def _significance(sweep: Path, swept: list, series: str, metrics: list) -> list[str]:
    """Welch's t-test (unequal variances) of each challenger against the Phase I design, per
    setting and metric, over the seeds in runs.csv. p < 0.05 is marked."""
    f = sweep / "runs.csv"
    if not f.exists():
        return []
    with f.open(newline="") as fh:
        runs = list(csv.DictReader(fh))
    names = {r.get(series, "") for r in runs}
    if REFERENCE not in names or not names & set(CHALLENGERS):
        return []
    from scipy.stats import ttest_ind
    out = ["## Significance against Phase-I", "",
           "Welch's t-test over the seeds; **bold** = p < 0.05. A dash: too few values or no variance.", ""]
    keys = sorted({tuple(r.get(k) for k in swept) for r in runs}, key=lambda k: [(_f(v) or 0) for v in k])
    for key in keys:
        sel = [r for r in runs if tuple(r.get(k) for k in swept) == key]
        head = ["challenger"] + [h for h, _, _, _ in metrics]
        if swept:
            out += [f"### " + ", ".join(f"{k} = {v}" for k, v in zip(swept, key)), ""]
        out += ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
        ref = [r for r in sel if r.get(series) == REFERENCE]
        for ch in CHALLENGERS:
            cr = [r for r in sel if r.get(series) == ch]
            if not cr:
                continue
            cells = []
            for _, col, _, _ in metrics:
                a = [x for x in (_f(r.get(col)) for r in ref) if x is not None]
                b = [x for x in (_f(r.get(col)) for r in cr) if x is not None]
                if len(a) < 2 or len(b) < 2 or (len(set(a)) == 1 and len(set(b)) == 1):
                    cells.append("–")
                    continue
                pv = float(ttest_ind(b, a, equal_var=False).pvalue)
                cells.append(f"**{pv:.3g}**" if pv < 0.05 else f"{pv:.2g}")
            out.append("| " + " | ".join([ch] + cells) + " |")
        out.append("")
    return out


def _tex(s: str) -> str:
    return s.replace("\\", "\\textbackslash{}").replace("_", "\\_").replace("%", "\\%").replace("&", "\\&")


def _latex(groups: dict, swept: list, series: str, metrics: list) -> str:
    """The same tables as booktabs LaTeX (\\usepackage{booktabs}), one per setting."""
    out = []
    for key, rs in groups.items():
        cap = ", ".join(f"{k} = {v}" for k, v in zip(swept, key)) or "all runs"
        out += ["\\begin{table}[ht]\\centering\\scriptsize", f"\\caption{{{_tex(cap)} (mean $\\pm$ 95\\,\\% CI)}}",
                "\\begin{tabular}{l" + "r" * len(metrics) + "}", "\\toprule",
                "variant & " + " & ".join(_tex(h) + (" $\\downarrow$" if b == "low" else " $\\uparrow$")
                                         for h, _, _, b in metrics) + " \\\\", "\\midrule"]
        for r in rs:
            name = r.get(series, "").replace("experiments.baselines.", "")
            cells = [_cell(r, c, f).replace("±", "$\\pm$").replace("–", "--") for _, c, f, _ in metrics]
            out.append(_tex(name) + " & " + " & ".join(cells) + " \\\\")
        out += ["\\bottomrule", "\\end{tabular}", "\\end{table}", ""]
    return "\n".join(out)


if __name__ == "__main__":
    for d in sys.argv[1:]:
        print(report(Path(d)))
