"""Tables, figures and in-text numbers of the project report (docs/report) from the results.

    python experiments/thesis_data.py                   # -> docs/report/generated/
    python experiments/thesis_data.py --results DIR     # another results folder

The report never types a measured number by hand. This script writes
  generated/numbers.tex   \\R{key}{metric} values: "cmp/v3-fast" = grid comparison at the
                          largest vehicle count, "lust:peak/v3-fast", "ev:lust:peak/EV + priority",
                          "abl/v2 +tesla", ..., plus derived percentages ("cmp/derived")
  generated/tab_*.tex     booktabs tables (mean ± 95 % CI over the seeds)
  generated/fig/*.pdf     figures copied from the sweeps' plots/
A sweep that has not run yet gives a table that says so, and \\R prints "??" in bold, so a
missing number is visible in the PDF instead of silently wrong.
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# column -> (header, format, unit)
M = {
    "ticket_ms_mean": ("Ticket", "{:.2f}", "ms"),
    "ticket_ms_steady_mean": ("Ticket after 10 s", "{:.2f}", "ms"),
    "auth_ms_mean": ("Login", "{:.2f}", "ms"),
    "handover_ms_mean": ("Handover", "{:.2f}", "ms"),
    "handover_n": ("Handovers", "{:.0f}", ""),
    "bsm_bytes": ("BSM size", "{:.0f}", "B"),
    "bsm_per_vehicle_s": ("BSM rate", "{:.2f}", "1/s"),
    "safety_bytes_per_vehicle_s": ("Safety traffic", "{:.0f}", "B/s"),
    "pdr": ("PDR", "{:.3f}", ""),
    "cbr_rsu_mean": ("CBR", "{:.3f}", ""),
    "rsu_accept_ms_mean": ("RSU accept", "{:.2f}", "ms"),
    "v2v_accept_ms_mean": ("V2V accept", "{:.2f}", "ms"),
    "v2v_verified_ratio": ("V2V verified", "{:.3f}", ""),
    "v2v_revoked_accepted_ratio": ("Revoked accepted", "{:.3f}", ""),
    "awareness_error_m_p95": ("Position error p95", "{:.2f}", "m"),
    "obu_cpu_util_mean": ("OBU load", "{:.4f}", ""),
    "detection_rate": ("Caught", "{:.2f}", ""),
    "honest_revoked": ("Honest revoked", "{:.1f}", ""),
    "report_to_revocation_s_mean": ("Report to revocation", "{:.2f}", "s"),
    "tracking_success": ("Tracked", "{:.2f}", ""),
    "traceable_fraction": ("Trip traced", "{:.2f}", ""),
    "silent_share": ("Silent share", "{:.3f}", ""),
    "ev_ticket_ms_mean": ("EV ticket", "{:.2f}", "ms"),
    "ev_ticket_ms_p95": ("EV ticket p95", "{:.1f}", "ms"),
    "other_ticket_ms_mean": ("Other ticket", "{:.2f}", "ms"),
    "other_ticket_ms_p95": ("Other ticket p95", "{:.1f}", "ms"),
    "ev_warned_ratio": ("Warned in 1 s", "{:.3f}", ""),
    "ev_alert_ms_mean": ("Alert delay", "{:.2f}", "ms"),
    "fake_alerts_accepted": ("Fake alerts accepted", "{:.0f}", ""),
    "fake_logins_denied": ("Fake logins denied", "{:.1f}", ""),
    "ev_priority_false_claims": ("False priority claims", "{:.1f}", ""),
}
HEADLINE = ["ticket_ms_mean", "ticket_ms_steady_mean", "handover_ms_mean", "bsm_bytes",
            "safety_bytes_per_vehicle_s", "pdr", "cbr_rsu_mean", "v2v_accept_ms_mean",
            "v2v_revoked_accepted_ratio", "detection_rate", "honest_revoked", "tracking_success"]
NON_KEYS = {"label", "profile", "protocol", "n_seeds"}


def _f(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def tex(s: str) -> str:
    return (str(s).replace("\\", "\\textbackslash{}").replace("_", "\\_").replace("%", "\\%")
            .replace("&", "\\&").replace("#", "\\#").replace("experiments.baselines.", ""))


def load(sweep: Path) -> tuple[list[dict], list[str]]:
    """aggregate.csv rows and the swept columns (grid parameters with > 1 value)."""
    f = sweep / "aggregate.csv"
    if not f.exists():
        return [], []
    with f.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        return [], []
    # variants in the order of the sweep's config (Phase-I before the baselines, ...)
    cfg = ROOT / "experiments" / "configs" / f"{sweep.name}.json"
    order = [v.get("label") for v in json.loads(cfg.read_text()).get("variants", [])] if cfg.exists() else []
    first = {"Phase-I": 0, "v2": 1, "v2-mac": 2, "v3-fast": 3, "v3-private": 4}
    rank = {lbl: first.get(lbl, 10 + i) for i, lbl in enumerate(order)}
    rows.sort(key=lambda r: rank.get(r.get("label"), 99))
    cols = list(rows[0])
    keys = cols[:cols.index("n_seeds")] if "n_seeds" in cols else []
    swept = [k for k in keys if k not in NON_KEYS and len({r[k] for r in rows}) > 1]
    return rows, swept


def name(r: dict) -> str:
    return r.get("label") or r.get("profile") or r.get("protocol", "")


def cell(r: dict, col: str) -> str:
    m, ci = _f(r.get(col)), _f(r.get(col + "_ci95"))
    if m is None:
        return "--"
    fmt = M.get(col, ("", "{:.3g}", ""))[1]
    return fmt.format(m) + (f" $\\pm$ {fmt.format(ci)}" if ci else "")


def head(col: str) -> str:
    h, _, unit = M.get(col, (col, "", ""))
    return tex(h) + (f" ({tex(unit)})" if unit else "")


def frame(caption: str, label: str, first: str, heads: list[str], sideways: bool = False):
    """Opening and closing lines of a generated table. Headers are horizontal and wrap; a table is
    shrunk to the available width, never enlarged; ``sideways`` puts a wide table on a landscape page."""
    n = len(heads)
    env = "sidewaystable" if sideways else "table"
    width = "\\textheight" if sideways else "\\textwidth"
    col = "1.4cm" if n > 5 else "2.1cm"
    cells = [f"\\multicolumn{{1}}{{>{{\\raggedleft\\arraybackslash}}p{{{col}}}}}{{{h}}}" for h in heads]
    head = [f"\\begin{{{env}}}" + ("" if sideways else "[htbp]") + "\\centering"
            + ("\\footnotesize\\setlength{\\tabcolsep}{3.5pt}" if n > 5 else "\\small"),
            f"\\caption{{{caption}}}\\label{{{label}}}",
            f"\\resizebox{{\\ifdim\\width>{width}{width}\\else\\width\\fi}}{{!}}{{%",
            "\\begin{tabular}{l" + "r" * n + "}", "\\toprule",
            f"{first} & " + " & ".join(cells) + " \\\\", "\\midrule"]
    return head, ["\\bottomrule", "\\end{tabular}}"], f"\\end{{{env}}}"


def table(path: Path, rows: list[dict], metrics: list[str], caption: str, label: str,
          group: str | None = None, note: str = "") -> None:
    """One booktabs table: variants as rows, ``metrics`` as columns; with ``group`` a block of
    rows per value of that column. More than eight metrics go on a landscape page."""
    metrics = [m for m in metrics if any(_f(r.get(m)) is not None for r in rows)]
    if not rows or not metrics:
        pending(path, caption, label)
        return
    out, tail, end = frame(caption, label, "Variant", [head(m) for m in metrics], sideways=len(metrics) > 8)
    blocks: dict[str, list[dict]] = {}
    for r in rows:
        blocks.setdefault(r.get(group, "") if group else "", []).append(r)
    keys = sorted(blocks, key=lambda k: (_f(k) if _f(k) is not None else 0, k))
    for i, k in enumerate(keys):
        if group:
            if i:
                out.append("\\midrule")
            out.append(f"\\multicolumn{{{len(metrics) + 1}}}{{l}}{{\\textit{{{tex(group)} = {tex(k)}}}}} \\\\")
        for r in blocks[k]:
            out.append(tex(name(r)) + " & " + " & ".join(cell(r, m) for m in metrics) + " \\\\")
    out += tail
    if note:
        out.append(f"\\par\\smallskip\\parbox{{\\textwidth}}{{\\scriptsize {note}}}")
    out.append(end)
    path.write_text("\n".join(out) + "\n")


def pending(path: Path, caption: str, label: str) -> None:
    path.write_text(f"\\begin{{table}}[htbp]\\centering\\caption{{{caption}}}\\label{{{label}}}\n"
                    "\\fbox{\\parbox{0.8\\textwidth}{\\centering\\textbf{Results pending:} this sweep has "
                    "not finished yet (make evaluate-all, then python experiments/thesis\\_data.py).}}\n"
                    "\\end{table}\n")


class Numbers:
    def __init__(self) -> None:
        self.lines = ["% generated by experiments/thesis_data.py -- do not edit"]

    def put(self, key: str, metric: str, value: str) -> None:
        self.lines.append(f"\\expandafter\\def\\csname r@{key}@{metric}\\endcsname{{{value}}}")

    def rows(self, prefix: str, rows: list[dict], key=name) -> None:
        for r in rows:
            for col, (_, fmt, _) in M.items():
                v = _f(r.get(col))
                if v is not None:
                    self.put(f"{prefix}/{key(r)}", col, fmt.format(v))


def pct(a, b) -> str | None:
    """Reduction from a to b in percent."""
    a, b = _f(a), _f(b)
    if a is None or b is None or not a:
        return None
    return f"{100 * (a - b) / a:.0f}"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=ROOT / "experiments" / "results")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "report" / "generated")
    a = ap.parse_args()
    out, res = a.out, a.results
    (out / "fig").mkdir(parents=True, exist_ok=True)
    N = Numbers()

    # ---- grid comparison: headline table at the largest vehicle count, all counts in a second one
    rows, _ = load(res / "compare_v3")
    top = max((int(_f(r["vehicles"])) for r in rows if _f(r.get("vehicles"))), default=None)
    sel = [r for r in rows if top is not None and int(_f(r["vehicles"])) == top]
    N.put("cmp", "vehicles", str(top) if top else "??")
    N.rows("cmp", sel)
    by = {name(r): r for r in sel}
    p1, v3 = by.get("Phase-I", {}), by.get("v3-fast", {})
    for col in ("ticket_ms_mean", "ticket_ms_steady_mean", "safety_bytes_per_vehicle_s", "cbr_rsu_mean",
                "v2v_accept_ms_mean", "bsm_bytes", "handover_ms_mean"):
        v = pct(p1.get(col), v3.get(col))
        if v is not None:
            N.put("cmp/derived", col + "_cut_pct", v)
    if _f(p1.get("safety_bytes_per_vehicle_s")) and _f(v3.get("safety_bytes_per_vehicle_s")):
        N.put("cmp/derived", "safety_factor", f"{_f(p1['safety_bytes_per_vehicle_s']) / _f(v3['safety_bytes_per_vehicle_s']):.1f}")
    table(out / "tab_compare.tex", sel, [m for m in HEADLINE[:8] if m != "ticket_ms_steady_mean"],
          f"Grid scenario, {top or '?'} vehicles: latency and overhead (ns-3, mean $\\pm$ 95\\,\\% CI over 5 seeds)",
          "tab:compare")
    table(out / "tab_compare_sec.tex", sel, HEADLINE[8:] + ["report_to_revocation_s_mean", "obu_cpu_util_mean"],
          f"Grid scenario, {top or '?'} vehicles: security and privacy", "tab:compare-sec",
          note="Caught: share of attackers reported; Revoked accepted: share of BSMs from revoked senders that "
               "vehicles still accepted; Tracked: share of pseudonym changes a global eavesdropper links.")
    table(out / "tab_compare_all.tex", rows, ["ticket_ms_mean", "safety_bytes_per_vehicle_s", "pdr", "cbr_rsu_mean",
                                              "v2v_accept_ms_mean"],
          "Grid scenario at 50, 100 and 150 vehicles", "tab:compare-all", group="vehicles")
    significance(res / "compare_v3", top, out / "tab_significance.tex")

    # ---- real traffic (LuST)
    rows, _ = load(res / "compare_lust")
    for r in rows:
        N.rows(r.get("real", "?"), [r])
    table(out / "tab_lust.tex", rows, ["ticket_ms_mean", "ticket_ms_steady_mean", "safety_bytes_per_vehicle_s",
                                       "pdr", "cbr_rsu_mean", "v2v_accept_ms_mean", "detection_rate"],
          "LuST (Luxembourg) traffic: low (06:00), mid (14:00) and peak (08:00) windows", "tab:lust", group="real")

    # ---- ablation, compromised RSUs, sensitivity, mix zones, emergency
    rows, _ = load(res / "ablation_v3")
    N.rows("abl", rows)
    table(out / "tab_ablation.tex", rows, ["ticket_ms_mean", "bsm_bytes", "safety_bytes_per_vehicle_s", "cbr_rsu_mean",
                                           "v2v_accept_ms_mean", "v2v_revoked_accepted_ratio", "detection_rate",
                                           "honest_revoked", "tracking_success"],
          "Ablation: v2 plus one mechanism at a time (100 vehicles)", "tab:ablation")
    rows, _ = load(res / "trust_v3")
    N.rows("trust", rows)
    table(out / "tab_trust.tex", rows, ["detection_rate", "honest_revoked", "report_to_revocation_s_mean"],
          "Compromised RSUs: 25\\,\\% of the RSUs report random honest vehicles (100 vehicles, 10 seeds)", "tab:trust")
    for cfg, grp, cap, cols in (
            ("sensitivity_obu", "obu_scale", "Vehicle processor speed: measured times $\\times$ 1, 5, 10",
             ["ticket_ms_mean", "v2v_accept_ms_mean", "obu_cpu_util_mean", "v2v_verified_ratio"]),
            ("sensitivity_attack", "attack", "Detection per attack type",
             ["detection_rate", "honest_revoked", "report_to_revocation_s_mean"]),
            ("sensitivity_attackers", "attacker_ratio", "Share of attackers",
             ["detection_rate", "honest_revoked", "pdr", "cbr_rsu_mean"]),
            ("mixzone_tradeoff", "mix_silent_max", "Mix zones: longest silent period (s) against tracking",
             ["tracking_success", "traceable_fraction", "silent_share", "awareness_error_m_p95"])):
        rows, _ = load(res / cfg)
        for r in rows:
            N.rows(f"{cfg}:{r.get(grp)}", [r])
        table(out / f"tab_{cfg}.tex", rows, cols, cap, f"tab:{cfg.replace('_', '-')}", group=grp)
    rows, _ = load(res / "emergency")
    for r in rows:
        N.rows(f"ev:{r.get('real')}", [r])
    table(out / "tab_emergency.tex", rows, ["ev_ticket_ms_mean", "ev_ticket_ms_p95", "other_ticket_ms_mean",
                                            "other_ticket_ms_p95", "ev_warned_ratio", "ev_alert_ms_mean",
                                            "fake_alerts_accepted", "fake_logins_denied", "detection_rate"],
          "Emergency vehicles (2\\,\\% of the honest vehicles) on LuST traffic", "tab:emergency", group="real")

    veremi(ROOT / "detection" / "results" / "veremi_benchmark.json", out / "tab_veremi.tex", N)
    # the Fabric benchmark is not part of the simulation sweeps: always the main results folder
    ledger(ROOT / "experiments" / "results" / "ledger_consensus" / "summary.json", out / "tab_ledger.tex", N)
    compute(ROOT / "experiments" / "compute_times_v3.json", out / "tab_compute.tex", N)
    figures(res, out / "fig")
    (out / "numbers.tex").write_text("\n".join(N.lines) + "\n")
    print(f"wrote {out}")


def significance(sweep: Path, top, path: Path) -> None:
    """Welch's t-test of v3-fast and v3-private against Phase-I at the largest vehicle count."""
    cap, label = "Welch's t-test against Phase-I (p-values; bold: p $<$ 0.05)", "tab:significance"
    f = sweep / "runs.csv"
    if not f.exists() or top is None:
        pending(path, cap, label)
        return
    from scipy.stats import ttest_ind
    with f.open(newline="") as fh:
        runs = [r for r in csv.DictReader(fh) if _f(r.get("vehicles")) == top]
    cols = HEADLINE[:8] + ["v2v_revoked_accepted_ratio"]
    out, tail, end = frame(cap, label, "Challenger", [head(c) for c in cols])
    ref = [r for r in runs if r.get("label") == "Phase-I"]
    for ch in ("v3-fast", "v3-private"):
        cr = [r for r in runs if r.get("label") == ch]
        cells = []
        for c in cols:
            x = [v for v in (_f(r.get(c)) for r in ref) if v is not None]
            y = [v for v in (_f(r.get(c)) for r in cr) if v is not None]
            if len(x) < 2 or len(y) < 2 or (len(set(x)) == 1 and len(set(y)) == 1):
                cells.append("--")
                continue
            p = float(ttest_ind(y, x, equal_var=False).pvalue)
            cells.append(f"\\textbf{{{p:.2g}}}" if p < 0.05 else f"{p:.2g}")
        out.append(f"{ch} & " + " & ".join(cells) + " \\\\")
    out += ["\\bottomrule", "\\end{tabular}}", "\\end{table}"]
    path.write_text("\n".join(out) + "\n")


def veremi(f: Path, path: Path, N: Numbers) -> None:
    """detection/benchmark.py: message-level F1 and FPR from its summary lines (veremi_benchmark.txt),
    ROC AUC and the honest vehicles from the JSON (mean, std over the splits)."""
    import re
    cap, label = "Misbehaviour detection on VeReMi Extension (5 vehicle-disjoint splits)", "tab:veremi"
    txt = f.with_suffix(".txt")
    if not f.exists() or not txt.exists():
        pending(path, cap, label)
        return
    d = json.loads(f.read_text())
    line = re.compile(r"^(\S+)\s+F1 ([0-9.]+) ± ([0-9.]+)\s+FPR ([0-9.]+)\s+attackers reported ([0-9.]+)")
    summ = {m.group(1): m.groups()[1:] for m in map(line.match, txt.read_text().splitlines()) if m}
    names = {"rules": "Plausibility rules", "rf": "Random forest", "hgb": "Gradient boosting",
             "hgb_window": "Gradient boosting + history window",
             "hgb_window_calibrated": "\\quad + calibrated threshold"}
    out = ["\\begin{table}[htbp]\\centering\\small", f"\\caption{{{cap}}}\\label{{{label}}}",
           "\\resizebox{\\ifdim\\width>\\textwidth\\textwidth\\else\\width\\fi}{!}{%", "\\begin{tabular}{lrrrr}", "\\toprule",
           "Detector & F1 & FPR & ROC AUC & Attackers reported \\\\", "\\midrule"]
    for k, lbl in names.items():
        if k not in summ:
            continue
        f1, sd, fpr, rep = summ[k]
        auc = (d.get("models", {}).get(k, {}).get("roc_auc") or [None])[0]
        out.append(f"{lbl} & {float(f1):.3f} $\\pm$ {float(sd):.3f} & {float(fpr):.4f} & "
                   f"{'--' if auc is None else f'{auc:.3f}'} & {float(rep):.3f} \\\\")
        N.put("veremi", k + "_f1", f"{float(f1):.3f}")
        N.put("veremi", k + "_fpr", f"{float(fpr):.4f}")
    N.put("veremi", "messages", f"{d.get('messages', 0):,}".replace(",", "{,}"))
    N.put("veremi", "vehicles", f"{d.get('vehicles', 0):,}".replace(",", "{,}"))
    out += ["\\bottomrule", "\\end{tabular}}", "\\end{table}"]
    path.write_text("\n".join(out) + "\n")


def ledger(f: Path, path: Path, N: Numbers) -> None:
    cap, label = "Hyperledger Fabric 3.1.5: commit latency of RecordAuth under load", "tab:ledger"
    if not f.exists():
        pending(path, cap, label)
        return
    d = json.loads(f.read_text())
    names = {"raft_500ms": "Raft, 500 ms batch timeout", "raft_50ms": "Raft, 50 ms batch timeout",
             "bft_50ms": "SmartBFT, 50 ms batch timeout"}
    out = ["\\begin{table}[htbp]\\centering\\small", f"\\caption{{{cap}}}\\label{{{label}}}",
           "\\resizebox{\\ifdim\\width>\\textwidth\\textwidth\\else\\width\\fi}{!}{%", "\\begin{tabular}{lrrrr}", "\\toprule",
           "Ordering service & Offered (tx/s) & Achieved (tx/s) & p50 (ms) & p95 (ms) \\\\", "\\midrule"]
    for k, lbl in names.items():
        for i, r in enumerate(d.get(k, [])):
            out.append(f"{lbl if i == 0 else ''} & {r['targetRate']} & {float(r['achievedTps']):.1f} & "
                       f"{float(r['p50Ms']):.0f} & {float(r['p95Ms']):.0f} \\\\")
            N.put("ledger", f"{k}_{r['targetRate']}_p50", f"{float(r['p50Ms']):.0f}")
            N.put("ledger", f"{k}_{r['targetRate']}_p95", f"{float(r['p95Ms']):.0f}")
        out.append("\\midrule" if k != "bft_50ms" else "")
    out = [l for l in out if l] + ["\\bottomrule", "\\end{tabular}}", "\\end{table}"]
    path.write_text("\n".join(out) + "\n")


def compute(f: Path, path: Path, N: Numbers) -> None:
    cap, label = "Measured cost of each cryptographic operation on the development PC (ms)", "tab:compute"
    d = {k: v for k, v in json.loads(f.read_text()).items() if not k.startswith("_")}
    rows = [("prove", "Schnorr proof (vehicle, with precomputed commitment)"),
            ("verify", "Schnorr proof verification (RSU)"), ("merkle_check", "Merkle path check"),
            ("sign", "Schnorr signature"), ("verify_sig", "Schnorr signature verification"),
            ("bsm_verify_one", "BSM signature verification"), ("tesla_mac", "TESLA MAC"),
            ("ecqv_issue", "ECQV certificate issue"), ("ecqv_reconstruct", "ECQV key reconstruction"),
            ("bbs_prove", "BBS proof"), ("bbs_prove_online", "BBS proof, online part"),
            ("bbs_verify", "BBS verification"), ("ecdsa_sign", "ECDSA P-256 sign (baseline)"),
            ("ecdsa_verify", "ECDSA P-256 verify (baseline)")]
    out = ["\\begin{table}[htbp]\\centering\\small", f"\\caption{{{cap}}}\\label{{{label}}}",
           "\\begin{tabular}{lr}", "\\toprule", "Operation & Time (ms) \\\\", "\\midrule"]
    for k, lbl in rows:
        if k in d:
            out.append(f"{lbl} & {d[k] * 1000:.3f} \\\\")
            N.put("ct", k, f"{d[k] * 1000:.3f}")
    for n in (8, 32):
        k = f"batch_speedup_{n}"
        if k in d:
            N.put("ct", k, f"{d[k]:.2f}")
    out += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    path.write_text("\n".join(out) + "\n")


# Report figures: small multiples with one shared legend. Each variant keeps its colour, marker
# and dash everywhere (validated categorical palette, fixed order), so print in grey still works.
STYLE = {
    "Phase-I": ("#2a78d6", "o", "-"), "v2": ("#eb6834", "s", "--"), "v2-mac": ("#1baf7a", "^", "-."),
    "v3-fast": ("#eda100", "D", "-"), "v3-private": ("#e87ba4", "v", "--"),
    "ECDSA-PKI": ("#008300", "P", ":"), "Central-TA": ("#6250d6", "X", ":"),
}
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"


def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 8, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
                         "xtick.color": MUTED, "ytick.color": MUTED, "axes.grid": True,
                         "grid.color": GRID, "grid.linewidth": 0.6, "axes.spines.top": False,
                         "axes.spines.right": False, "font.family": "serif", "pdf.fonttype": 42})
    return plt


def _legend(fig, axes, ncol):
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=ncol, frameon=False, bbox_to_anchor=(0.5, 1.0))


def fig_grid(rows: list[dict], path: Path) -> None:
    """Six metrics over vehicle density, one line per variant with its 95 % CI."""
    if not rows:
        return
    plt = _plt()
    panels = [("ticket_ms_mean", "Ticket (ms, log)", True), ("safety_bytes_per_vehicle_s", "Safety traffic (B/s per vehicle)", False),
              ("cbr_rsu_mean", "Channel busy ratio", False), ("pdr", "Packet delivery ratio", False),
              ("v2v_accept_ms_mean", "V2V acceptance (ms)", False), ("v2v_revoked_accepted_ratio", "Revoked senders' BSMs accepted", False)]
    fig, axes = plt.subplots(2, 3, figsize=(7.2, 4.6))
    axes = axes.ravel()
    for ax, (col, title, log) in zip(axes, panels):
        for lbl, (c, m, ls) in STYLE.items():
            pts = sorted((_f(r["vehicles"]), _f(r.get(col)), _f(r.get(col + "_ci95")) or 0)
                         for r in rows if name(r) == lbl and _f(r.get(col)) is not None)
            if pts:
                ax.errorbar([p[0] for p in pts], [p[1] for p in pts], yerr=[p[2] for p in pts], color=c,
                            marker=m, ls=ls, lw=1.6, ms=4.5, capsize=2, label=lbl)
        ax.set_title(title, fontsize=8.5, color=INK, loc="left")
        ax.set_xticks(sorted({_f(r["vehicles"]) for r in rows}))
        ax.set_xlabel("vehicles")
        if log:
            ax.set_yscale("log")
    _legend(fig, axes, 7)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    fig.savefig(path)
    plt.close(fig)


def fig_bars(rows: list[dict], group: str, panels: list[tuple[str, str]], path: Path,
             series: list[str] | None = None) -> None:
    """Grouped bars: one group per value of ``group``, one bar per variant, CI whiskers."""
    if not rows:
        return
    plt = _plt()
    groups = sorted({r.get(group) for r in rows}, key=lambda g: (_f(g) if _f(g) is not None else 0, g))
    names = series or [n for n in STYLE if any(name(r) == n for r in rows)] or sorted({name(r) for r in rows})
    fallback = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6"]
    fig, axes = plt.subplots(1, len(panels), figsize=(7.2, 2.7))
    axes = list(axes) if len(panels) > 1 else [axes]
    w = 0.8 / max(1, len(names))
    for ax, (col, title) in zip(axes, panels):
        for i, n in enumerate(names):
            c = STYLE.get(n, (fallback[i % len(fallback)],))[0]
            ys, es = [], []
            for g in groups:
                r = next((r for r in rows if name(r) == n and r.get(group) == g), {})
                ys.append(_f(r.get(col)) or 0)
                es.append(_f(r.get(col + "_ci95")) or 0)
            xs = [k + (i - (len(names) - 1) / 2) * w for k in range(len(groups))]
            ax.bar(xs, ys, w * 0.9, yerr=es, color=c, label=n, capsize=1.5, error_kw={"lw": 0.8, "ecolor": INK})
        ax.set_xticks(range(len(groups)), [str(g).replace("lust:", "") for g in groups])
        ax.set_title(title, fontsize=8.5, color=INK, loc="left")
        ax.grid(axis="x", visible=False)
    _legend(fig, axes, min(len(names), 7))
    fig.tight_layout(rect=(0, 0, 1, 0.84))
    fig.savefig(path)
    plt.close(fig)


def figures(res: Path, dst: Path) -> None:
    for f in dst.glob("*.pdf"):
        f.unlink()                                       # no stale figure from an older run
    rows, _ = load(res / "compare_v3")
    fig_grid(rows, dst / "grid_overview.pdf")
    rows, _ = load(res / "compare_lust")
    fig_bars(rows, "real", [("ticket_ms_steady_mean", "Ticket after 10 s (ms)"),
                            ("safety_bytes_per_vehicle_s", "Safety traffic (B/s)"),
                            ("cbr_rsu_mean", "Channel busy ratio")], dst / "lust_overview.pdf",
             series=["Phase-I", "v2", "v3-fast", "v3-private", "ECDSA-PKI", "Central-TA"])
    rows, _ = load(res / "mixzone_tradeoff")
    fig_bars(rows, "mix_silent_max", [("tracking_success", "Pseudonym changes linked"),
                                      ("silent_share", "Share of time silent")], dst / "mixzone.pdf")
    rows, _ = load(res / "emergency")
    fig_bars(rows, "real", [("ev_ticket_ms_mean", "Emergency vehicle ticket (ms)"),
                            ("other_ticket_ms_mean", "Other vehicles' ticket (ms)"),
                            ("ev_warned_ratio", "Warned within 1 s")], dst / "emergency.pdf")


if __name__ == "__main__":
    main()
