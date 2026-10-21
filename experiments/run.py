"""Experiment runner (Person 4): runs Person 1's scenario over a grid, collects the
metrics CSVs, and writes means with 95 % confidence intervals.

    python experiments/run.py --config experiments/configs/quick.json
    python experiments/run.py --config experiments/configs/full.json --jobs 4
    python experiments/run.py --config experiments/configs/full.json --collect-only
    python experiments/run.py --config ... --dry-run          # print the commands

Config (JSON):
    {
      "name": "quick",
      "seeds": [1, 2, 3],                      # at least 3
      "fixed": {"duration": 60, "backend": "lite", "ledger": "mock"},   # any run_scenario option
      "grid":  {"vehicles": [50, 100], "attacker_ratio": [0, 0.1]},     # every combination
      "variants": [{"protocol": "stub"}, {"protocol": "experiments.baselines.ecdsa_pki"}]
    }

A variant may have a "label" (its name in tables and plots; not passed to the scenario).

Option names are run_scenario.py options with "_" for "-" (rsu_spacing -> --rsu-spacing);
true adds a flag, false/null leaves it out. Results go to
experiments/results/<name>/: runs/ (one folder per run, cached), runs.csv (one row
per run), aggregate.csv (mean and ci95 per setting).
One command from scratch:  python experiments/run.py --config <cfg> --force
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.collect import collect_run  # noqa: E402
from experiments.stats import mean_ci  # noqa: E402

RESULTS = ROOT / "experiments" / "results"


def expand(cfg: dict) -> list[dict]:
    """Every (variant x grid point x seed) as a flat dict of run_scenario options."""
    grid = cfg.get("grid", {})
    keys = sorted(grid)
    variants = cfg.get("variants") or [{}]
    runs = []
    for variant in variants:
        for values in itertools.product(*(grid[k] for k in keys)):
            for seed in cfg.get("seeds", [1, 2, 3]):
                runs.append({**cfg.get("fixed", {}), **variant, **dict(zip(keys, values)), "seed": seed})
    return runs


def run_id(params: dict) -> str:
    blob = json.dumps(params, sort_keys=True, default=str)
    label = "_".join(f"{k}{v}" for k, v in sorted(params.items()) if k in ("vehicles", "seed"))
    return f"{label}_{hashlib.sha1(blob.encode()).hexdigest()[:8]}"


def to_args(params: dict) -> list[str]:
    args: list[str] = []
    for k, v in params.items():
        if k == "label":
            continue                    # a variant's name in the tables, not a scenario option
        flag = "--" + k.replace("_", "-")
        if v is True:
            args.append(flag)
        elif v is False or v is None:
            continue
        else:
            args += [flag, str(v)]
    return args


def command(params: dict, out: Path) -> list[str]:
    return [sys.executable, str(ROOT / "network" / "run_scenario.py"), *to_args(params),
            "--out", str(out), "--quiet"]


def execute(params: dict, out: Path, force: bool) -> tuple[Path, str | None]:
    if (out / "summary.json").exists() and not force:
        return out, None
    out.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(command(params, out), capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0 or not (out / "summary.json").exists():
        return out, (proc.stderr or proc.stdout)[-800:]
    return out, None


def prebuild(todo: list, force: bool) -> None:
    """Build every scenario the runs need, one at a time, before running them in parallel
    (parallel runs would otherwise build the same scenario folder at the same moment)."""
    from mobility.build_scenario import ensure_scenario
    from mobility.real_scenario import ensure_real_scenario
    seen = set()
    for p, out in todo:
        if (out / "summary.json").exists() and not force:
            continue
        step = float(p.get("mobility_step", 1.0))
        if p.get("real"):
            key = ("real", p["real"], p.get("duration", 300), p.get("seed", 1), step)
            if key not in seen:
                ensure_real_scenario(p["real"], float(p.get("duration", 300)), int(p.get("seed", 1)), step,
                                     float(p.get("rsu_spacing", 450)), float(p.get("rsu_range", 300)), quiet=True)
        else:
            key = ("grid", p.get("vehicles", 100), p.get("duration", 300), p.get("seed", 1), step,
                   p.get("rsu_spacing", 450))
            if key not in seen:
                ensure_scenario(int(p.get("vehicles", 100)), float(p.get("duration", 300)), int(p.get("seed", 1)),
                                p.get("net", "grid"), p.get("osm"), float(p.get("rsu_spacing", 450)),
                                float(p.get("rsu_range", 300)), quiet=True, step=step)
        seen.add(key)


def run_all(cfg: dict, jobs: int, force: bool, collect_only: bool) -> list[dict]:
    base = RESULTS / cfg["name"]
    runs = expand(cfg)
    if len(set(cfg.get("seeds", [1, 2, 3]))) < 3:
        print("warning: fewer than 3 seeds; the definition of done needs at least 3", file=sys.stderr)
    for ct in {p.get("compute_times") for p in runs if p.get("compute_times")}:
        if not (ROOT / ct).exists() and not Path(ct).exists():
            raise SystemExit(f"{ct} not found. Create it:  python experiments/measure_ecdsa.py "
                             f"--merge <Person 3's compute-times JSON> --out {ct}   (without --merge: ECDSA only)")
    todo = [(p, base / "runs" / run_id(p)) for p in runs]
    failures = []
    if not collect_only:
        prebuild(todo, force)
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            for i, (out, err) in enumerate(pool.map(lambda po: execute(po[0], po[1], force), todo), 1):
                print(f"[{i}/{len(todo)}] {out.name}" + (" FAILED" if err else ""), flush=True)
                if err:
                    failures.append((out.name, err))
    rows = []
    for params, out in todo:
        if (out / "metrics.csv").exists() and (out / "summary.json").exists():
            rows.append({**params, **collect_run(out), "run": out.name})
    for name, err in failures:
        print(f"\nrun {name} failed:\n{err}", file=sys.stderr)
    return rows


def write_tables(rows: list[dict], cfg: dict) -> tuple[Path, Path]:
    base = RESULTS / cfg["name"]
    base.mkdir(parents=True, exist_ok=True)
    cols = sorted({k for r in rows for k in r}, key=lambda k: (k == "run", k))
    with (base / "runs.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    group_keys = sorted({k for r in rows for k in r if k in cfg.get("grid", {})} |
                        {k for v in cfg.get("variants", [{}]) for k in v})
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(str(r.get(k)) for k in group_keys), []).append(r)
    metric_cols = [c for c in cols if c not in group_keys and c not in ("seed", "run")
                   and c not in cfg.get("fixed", {}) and any(isinstance(r.get(c), (int, float)) for r in rows)]
    agg_rows = []
    for key, rs in sorted(groups.items()):
        row = dict(zip(group_keys, key))
        row["n_seeds"] = len(rs)
        for c in metric_cols:
            m, ci, n = mean_ci(r.get(c) for r in rs)
            row[c], row[c + "_ci95"] = m, ci
        agg_rows.append(row)
    agg_cols = group_keys + ["n_seeds"] + [x for c in metric_cols for x in (c, c + "_ci95")]
    with (base / "aggregate.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=agg_cols)
        w.writeheader()
        w.writerows(agg_rows)
    return base / "runs.csv", base / "aggregate.csv"


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    ap.add_argument("--jobs", type=int, default=2, help="runs in parallel")
    ap.add_argument("--force", action="store_true", help="rerun even if a run folder already has results")
    ap.add_argument("--collect-only", action="store_true", help="only rebuild the tables from existing runs")
    ap.add_argument("--dry-run", action="store_true", help="print the commands and stop")
    ap.add_argument("--no-plots", action="store_true")
    a = ap.parse_args(argv)
    cfg = json.loads(Path(a.config).read_text())
    cfg.setdefault("name", Path(a.config).stem)
    if a.dry_run:
        for p in expand(cfg):
            print(" ".join(command(p, RESULTS / cfg["name"] / "runs" / run_id(p))))
        print(f"{len(expand(cfg))} runs")
        return
    rows = run_all(cfg, a.jobs, a.force, a.collect_only)
    if not rows:
        raise SystemExit("no run produced results; see the errors above")
    runs_csv, agg_csv = write_tables(rows, cfg)
    print(f"{len(rows)} runs -> {runs_csv}\naggregate (mean, ci95) -> {agg_csv}")
    if not a.no_plots:
        from experiments import plots
        plots.make_all(RESULTS / cfg["name"], cfg)


if __name__ == "__main__":
    main()
