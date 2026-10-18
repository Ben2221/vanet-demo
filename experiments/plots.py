"""Every graph and table of the evaluation (Person 4), drawn from the aggregate tables.

    python experiments/plots.py experiments/results/<name>            # from aggregate.csv
    python experiments/plots.py experiments/results/<name> --detection detection/results/metrics.json

Each figure is a PNG in <results>/plots/ with 95 % confidence-interval bars over
the seeds, and a CSV of the plotted numbers next to it. A figure whose data is
missing is skipped with a message, not drawn empty.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# (file name, y column, y label, title); x is the swept parameter
LINE_FIGURES = [
    ("auth_latency", "auth_ms_mean", "authentication latency (ms)", "Authentication latency"),
    ("handover_latency", "handover_ms_mean", "handover latency (ms)", "Handover latency"),
    ("pdr", "pdr", "packet delivery ratio", "Packet delivery ratio"),
    ("channel_busy", "cbr_rsu_mean", "channel busy ratio at RSUs", "Channel load"),
    ("ledger_commit", "ledger_commit_ms_median", "Fabric commit time, median (ms)", "Ledger commit time"),
    ("ledger_commit_p95", "ledger_commit_ms_p95", "Fabric commit time, p95 (ms)", "Ledger commit time (95th percentile)"),
    ("report_to_revocation", "report_to_revocation_s_mean", "report to revocation (s)", "Time from report to revocation"),
    ("first_report_delay", "first_report_delay_s_mean", "attack start to first report (s)", "Time to first report"),
    ("honest_wrongly_revoked", "honest_reported", "honest vehicles reported", "Honest vehicles wrongly reported"),
    ("detection_rate", "detection_rate", "attackers reported", "Attackers caught"),
    ("security_bytes", "security_bytes_per_bsm", "bytes added per BSM", "Security overhead per safety message"),
]
X_PREFERENCE = ["vehicles", "attacker_ratio", "rsu_spacing", "beacon_rate"]


def _read(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k, v in r.items():
            try:
                r[k] = float(v) if v not in ("", None) else None
            except ValueError:
                pass
    return rows


def _x_axis(rows: list[dict], cfg: dict | None) -> str | None:
    swept = [k for k in (cfg or {}).get("grid", {}) if len((cfg or {})["grid"][k]) > 1]
    for k in X_PREFERENCE:
        if k in swept:
            return k
    return swept[0] if swept else None


def _line(rows, x, y, ylabel, title, out: Path, series_key: str | None) -> bool:
    ci = y + "_ci95"
    groups: dict[str, list] = {}
    for r in rows:
        if r.get(y) is None:
            continue
        groups.setdefault(str(r.get(series_key)) if series_key else "", []).append(r)
    if not groups:
        return False
    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    table = []
    for name, rs in sorted(groups.items()):
        rs = sorted(rs, key=lambda r: r[x])
        xs, ys, es = [r[x] for r in rs], [r[y] for r in rs], [r.get(ci) or 0.0 for r in rs]
        label = name.split(".")[-1] if name else None
        if len(xs) > 1:
            ax.errorbar(xs, ys, yerr=es, marker="o", capsize=3, label=label)
        else:
            ax.errorbar(xs, ys, yerr=es, marker="o", capsize=3, label=label)
        table += [{"series": name, x: a, y: b, ci: c} for a, b, c in zip(xs, ys, es)]
    ax.set_xlabel(x.replace("_", " "))
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(alpha=0.3)
    if series_key and len(groups) > 1:
        ax.legend(title=series_key)
    fig.tight_layout()
    fig.savefig(out.with_suffix(".png"), dpi=160)
    plt.close(fig)
    with out.with_suffix(".csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(table[0]))
        w.writeheader()
        w.writerows(table)
    return True


def detection_figures(metrics_json: Path, out_dir: Path) -> None:
    """Precision / recall / F1 / FPR per attack (from detection/train.py --metrics)."""
    data = json.loads(metrics_json.read_text())
    for key, label in (("rules", "rules"), ("random_forest", "random forest")):
        if key not in data:
            continue
        m = {a: v for a, v in data[key].items() if a != "ALL"}
        names = list(m)
        fig, ax = plt.subplots(figsize=(8, 4))
        width = 0.27
        for i, metric in enumerate(("precision", "recall", "f1")):
            ax.bar([j + (i - 1) * width for j in range(len(names))], [m[a][metric] for a in names],
                   width, label=metric)
        ax.set_xticks(range(len(names)))
        ax.set_xticklabels(names, rotation=30, ha="right")
        ax.set_ylim(0, 1.05)
        ax.set_title(f"Detection per attack ({label}); source: {data.get('source', '?')}")
        ax.legend()
        ax.grid(axis="y", alpha=0.3)
        fig.tight_layout()
        fig.savefig(out_dir / f"detection_{key}.png", dpi=160)
        plt.close(fig)
        with (out_dir / f"detection_{key}.csv").open("w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["attack", "precision", "recall", "f1", "fpr", "n_attack"])
            for a in names:
                w.writerow([a] + [round(m[a][k], 4) for k in ("precision", "recall", "f1", "fpr")] + [m[a]["n_attack"]])


def make_all(results_dir: str | Path, cfg: dict | None = None, detection_json: str | Path | None = None) -> list[Path]:
    results_dir = Path(results_dir)
    out_dir = results_dir / "plots"
    out_dir.mkdir(parents=True, exist_ok=True)
    made: list[Path] = []
    agg = results_dir / "aggregate.csv"
    if agg.exists():
        rows = _read(agg)
        if cfg is None and (results_dir / "config.json").exists():
            cfg = json.loads((results_dir / "config.json").read_text())
        x = _x_axis(rows, cfg)
        series = "protocol" if len({r.get("protocol") for r in rows}) > 1 else None
        if x is None:
            print("plots: no swept parameter in the config, line figures skipped")
        else:
            for name, y, ylabel, title in LINE_FIGURES:
                if _line(rows, x, y, ylabel, title, out_dir / name, series):
                    made.append(out_dir / f"{name}.png")
                else:
                    print(f"plots: no data for {name} ({y}); skipped")
    if detection_json and Path(detection_json).exists():
        detection_figures(Path(detection_json), out_dir)
        made += sorted(out_dir.glob("detection_*.png"))
    print(f"{len(made)} figures in {out_dir}")
    return made


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results_dir")
    ap.add_argument("--detection", default=None, help="metrics JSON from detection/train.py --metrics")
    a = ap.parse_args()
    make_all(a.results_dir, None, a.detection)
    sys.exit(0)
