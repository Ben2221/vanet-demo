"""Figures for the simulation chapter (needs matplotlib)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

INK = "#1f2937"
BLUE = "#2563eb"
ORANGE = "#ea580c"
GREY = "#9ca3af"


def _plt():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False, "axes.edgecolor": GREY,
                         "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK,
                         "font.size": 10, "axes.grid": True, "grid.color": "#e5e7eb"})
    return plt


def _rows(path: Path) -> list[dict]:
    with Path(path).open() as f:
        return list(csv.DictReader(f))


def plot_range(csv_path: Path) -> Path:
    plt = _plt()
    rows = _rows(csv_path)
    d = [float(r["distance_m"]) for r in rows]
    fig, ax = plt.subplots(figsize=(5, 3.2))
    ax.plot(d, [float(r["pdr"]) for r in rows], "o-", color=BLUE)
    ax.axvline(400, color=GREY, ls="--", lw=1)
    ax.set_xlabel("distance (m)")
    ax.set_ylabel("delivery ratio")
    ax.set_title("802.11p range: 20 dBm, -85 dBm threshold", loc="left", color=INK)
    out = Path(csv_path).with_suffix(".png")
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    return out


def plot_density(csv_path: Path) -> Path:
    plt = _plt()
    rows = _rows(csv_path)
    n = [int(r["vehicles"]) for r in rows]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 3.2))
    a1.plot(n, [float(r["pdr"]) for r in rows], "o-", color=BLUE, label="vehicle to vehicle")
    a1.plot(n, [float(r["pdr_at_rsu"]) for r in rows], "s--", color=ORANGE, label="at the RSU")
    a1.axhline(0.9, color=GREY, ls=":", lw=1)
    a1.set_xlabel("vehicles in range")
    a1.set_ylabel("BSM delivery ratio")
    a1.legend(frameon=False)
    a2.plot(n, [float(r["delay_mean_ms"]) for r in rows], "o-", color=BLUE, label="mean")
    a2.plot(n, [float(r["delay_p95_ms"]) for r in rows], "s--", color=ORANGE, label="95th percentile")
    a2.set_xlabel("vehicles in range")
    a2.set_ylabel("delay (ms)")
    a2.legend(frameon=False)
    fig.tight_layout()
    out = Path(csv_path).with_suffix(".png")
    fig.savefig(out, dpi=150)
    return out


def plot_sweep(csv_path: Path) -> Path:
    """Output of density_sweep.py: means with 95 % confidence intervals."""
    plt = _plt()
    rows = _rows(csv_path)
    n = [int(r["vehicles"]) for r in rows]
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.2))
    for ax, key, label in zip(axes, ["pdr", "bsm_delay_ms", "cbr_rsu"],
                              ["broadcast delivery ratio", "BSM delay (ms)", "channel busy ratio at RSUs"]):
        y = [float(r[f"{key}_mean"]) for r in rows]
        e = [float(r[f"{key}_ci95"]) for r in rows]
        ax.errorbar(n, y, yerr=e, fmt="o-", color=BLUE, capsize=3)
        ax.set_xlabel("vehicles in scenario")
        ax.set_ylabel(label)
    fig.tight_layout()
    out = Path(csv_path).with_suffix(".png")
    fig.savefig(out, dpi=150)
    return out


def plot_summary(run_dir: Path) -> Path:
    """PDR against distance for one run."""
    plt = _plt()
    s = json.loads((Path(run_dir) / "summary.json").read_text())
    bins = [b for b in s["pdr_by_distance"] if b["pdr"] is not None]
    fig, ax = plt.subplots(figsize=(5, 3.2))
    ax.plot([(b["from_m"] + b["to_m"]) / 2 for b in bins], [b["pdr"] for b in bins], "o-", color=BLUE)
    ax.set_xlabel("sender-receiver distance (m)")
    ax.set_ylabel("BSM delivery ratio")
    out = Path(run_dir) / "pdr_by_distance.png"
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    return out


def plot_snapshot(scenario_dir: Path, t: float = 150.0, out: Path | None = None) -> Path:
    """Road network, RSUs with their range and the vehicles on the road at time t
    (a still of what NetAnim shows)."""
    from mobility.place_rsus import read_csv as read_rsus
    from mobility.sumo_env import add_tools_to_path
    from network import ns2_mobility

    plt = _plt()
    add_tools_to_path()
    import sumolib

    d = Path(scenario_dir)
    meta = json.loads((d / "scenario.json").read_text())
    net = sumolib.net.readNet(str(Path(__file__).resolve().parent.parent / "mobility" / meta["net"]))
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.grid(False)
    for e in net.getEdges():
        xs, ys = zip(*e.getShape())
        ax.plot(xs, ys, color="#d1d5db", lw=3, solid_capstyle="round", zorder=1)
    for r in read_rsus(d / "rsus.csv"):
        ax.add_patch(plt.Circle((r["x"], r["y"]), r["range_m"], color=ORANGE, alpha=0.07, zorder=2))
        ax.plot(r["x"], r["y"], "^", color=ORANGE, ms=10, zorder=4)
        ax.annotate(r["rsu_id"], (r["x"], r["y"]), xytext=(6, 6), textcoords="offset points",
                    color=INK, fontsize=8, zorder=5)
    trajs = ns2_mobility.load(d / "trace.ns2")
    with (d / "node_map.csv").open() as f:
        rows = list(csv.DictReader(f))
    on = [trajs[int(r["node_id"])].position(t) for r in rows
          if float(r["first_seen"]) <= t < float(r["last_seen"])]
    if on:
        ax.scatter(*zip(*on), s=14, color=BLUE, zorder=3, label=f"{len(on)} vehicles")
    xmin, ymin, xmax, ymax = net.getBoundary()
    ax.set_xlim(xmin - 120, xmax + 120)
    ax.set_ylim(ymin - 120, ymax + 120)
    ax.set_aspect("equal")
    ax.set_xlabel("x (m)")
    ax.set_ylabel("y (m)")
    # vehicle count in the title: a legend box would cover RSU labels on dense real maps
    ax.set_title(f"Scenario at t = {t:g} s, {len(on)} vehicles (blue), RSUs (orange)", loc="left", color=INK)
    out = out or d / f"snapshot_t{int(t)}.png"
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    return out
