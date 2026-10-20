"""Scenarios cut out of a real, calibrated city scenario (LuST, Luxembourg).

The grid scenarios (build_scenario.py) use random trips on a synthetic grid. This
builds the same files (trace.ns2, node_map.csv, rsus.csv, scenario.json) from the
LuST Scenario (Codeca et al., IEEE VNC 2015): 24 h of traffic for Luxembourg City,
generated with ACTIVITYGEN and validated against real traffic data.

    python mobility/real_scenario.py --real lust:peak --duration 120 --seed 1
    python network/run_scenario.py --real lust:peak ...        # same, from the scenario runner

Get LuST once:  mobility/get_lust.sh   (clones it into mobility/real/LuSTScenario)

How a scenario is cut:
  1. SUMO runs the whole city from WINDOW - WARMUP (900 s, so the roads are full) to
     WINDOW + duration with ``step`` s steps;
  2. only vehicles inside the box and only from WINDOW on are written
     (--device.fcd.begin, --fcd-output.filter-shapes);
  3. times are shifted to start at 0; a vehicle that leaves the box is parked until it
     comes back; RSUs are placed on the RSU grid inside the box.
Coordinates stay in LuST's network frame (the box is (x0, y0)-(x1, y1) there).

Windows (vehicles inside the box at the same time, measured): low = 06:00 (~150),
mid = 14:00 (~260), peak = 08:00 (~525). The box is the densest 1.35 km square at
08:00 (Luxembourg city centre): 3 x 3 RSUs at 450 m, like the 5 x 5 grid scenario.

Caveat: LuST was generated and validated with SUMO 0.26; this runs it with the
installed SUMO (1.28), which LuST's authors say is not validated mobility.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mobility import fcd_to_ns2, place_rsus
from mobility.sumo_env import LANECHANGE_ARGS, LANECHANGE_TAG, binary

MOBILITY_DIR = Path(__file__).resolve().parent
OUT_DIR = MOBILITY_DIR / "out"
WARMUP = 900.0

PRESETS = {
    "lust": {
        "home": os.environ.get("LUST_HOME", str(MOBILITY_DIR / "real" / "LuSTScenario")),
        "sumocfg": "scenario/dua.static.sumocfg",
        "net": "scenario/lust.net.xml",
        "box": (6150.0, 6300.0, 7500.0, 7650.0),
        "windows": {"low": 6 * 3600, "mid": 14 * 3600, "peak": 8 * 3600},
    },
}


def parse(real: str) -> tuple[dict, str, float]:
    """'lust:peak' -> (preset, window name, window start in s)."""
    name, _, window = real.partition(":")
    if name not in PRESETS:
        raise SystemExit(f"unknown real scenario '{name}'; known: {sorted(PRESETS)}")
    preset = PRESETS[name]
    window = window or "peak"
    if window not in preset["windows"]:
        raise SystemExit(f"unknown window '{window}' for {name}; known: {sorted(preset['windows'])}")
    home = Path(preset["home"])
    if not (home / preset["sumocfg"]).exists():
        raise SystemExit(f"{name} not found at {home}; run mobility/get_lust.sh (or set LUST_HOME)")
    return preset, window, float(preset["windows"][window])


def _additional_files(cfg: Path) -> list[str]:
    """The scenario's own additional files, as absolute paths (we add the box polygon)."""
    from defusedxml import ElementTree as ET     # third-party scenario files
    root = ET.parse(cfg).getroot()
    el = root.find("./input/additional-files")
    files = el.get("value").split(",") if el is not None else []
    return [str((cfg.parent / f.strip()).resolve()) for f in files if f.strip()]


def _sumo(args: list[str], log: Path) -> None:
    with log.open("a") as f:
        f.write("$ " + " ".join(args) + "\n")
        f.flush()
        res = subprocess.run(args, stdout=f, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        raise RuntimeError(f"SUMO failed ({res.returncode}); see {log}")


def ensure_real_scenario(real: str, duration: float = 120.0, seed: int = 1, step: float = 0.1,
                         rsu_spacing: float = 450.0, rsu_range: float = 300.0,
                         quiet: bool = False, force: bool = False) -> dict:
    """Build (or reuse) a scenario cut from a real city. Returns the dict of ensure_scenario."""
    preset, window, start = parse(real)
    name = real.split(":")[0]
    d = OUT_DIR / f"{name}_{window}_d{int(duration)}_s{seed}_st{step:g}{LANECHANGE_TAG}"
    meta_file = d / "scenario.json"
    if force and d.exists():
        shutil.rmtree(d)
    home = Path(preset["home"])
    cfg, net = home / preset["sumocfg"], home / preset["net"]
    x0, y0, x1, y1 = preset["box"]
    if not meta_file.exists():
        d.mkdir(parents=True, exist_ok=True)
        log = d / "build.log"
        log.write_text("")
        box = d / "box.add.xml"
        box.write_text(f'<additional>\n  <poly id="vanetbox" type="box" color="1,0,0" fill="0" layer="0" '
                       f'shape="{x0},{y0} {x1},{y0} {x1},{y1} {x0},{y1} {x0},{y0}"/>\n</additional>\n')
        common = [binary("sumo"), "-c", str(cfg), "--seed", str(seed), "--no-step-log", "true",
                  "--no-warnings", "true", "--verbose", "false",
                  "--summary-output", str(d / "summary.xml"), "--tripinfo-output", str(d / "tripinfo.xml"),
                  "--log", str(d / "sumo.log"), *LANECHANGE_ARGS]
        # one run: warm-up (so the roads are full when the window starts), then the window;
        # FCD only from the window start and only inside the box. (Saving the state after a
        # 1 s-step warm-up would be faster, but LuST's traffic lights cannot be reloaded
        # from a state file in current SUMO.)
        fcd = d / "fcd.xml"
        _sumo(common + ["--begin", f"{start - WARMUP:g}", "--end", f"{start + duration:g}",
                        "--step-length", f"{step:g}",
                        "--additional-files", ",".join(_additional_files(cfg) + [str(box)]),
                        "--fcd-output", str(fcd), "--device.fcd.begin", f"{start:g}",
                        "--fcd-output.filter-shapes", "vanetbox"], log)
        n = fcd_to_ns2.convert(fcd, d, step=step, time_offset=start, end_time=start + duration)
        pts = place_rsus.place(net, rsu_spacing, bounds=_rsu_bounds(preset, rsu_spacing))
        place_rsus.write_csv(pts, d / place_rsus_file(rsu_spacing), rsu_range, first_node_id=n)
        meta_file.write_text(json.dumps({
            "real": real, "source": "LuST Scenario (Codeca et al., IEEE VNC 2015)", "window_start_s": start,
            "box": [x0, y0, x1, y1], "net": str(net), "vehicles": n, "duration": duration, "seed": seed,
            "step": step, "trace": "trace.ns2", "node_map": "node_map.csv", "fcd": "fcd.xml"}, indent=2))
    meta = json.loads(meta_file.read_text())
    rsus = d / place_rsus_file(rsu_spacing)
    if not rsus.exists():
        n = meta["vehicles"]
        place_rsus.write_csv(place_rsus.place(net, rsu_spacing, bounds=_rsu_bounds(preset, rsu_spacing)), rsus, rsu_range,
                             first_node_id=n)
    shutil.copyfile(rsus, d / "rsus.csv")
    out = {"dir": d, "net": net, "trace": d / "trace.ns2", "node_map": d / "node_map.csv",
           "fcd": d / "fcd.xml", "rsus": rsus, "vehicles": meta["vehicles"], "duration": meta["duration"],
           "seed": meta["seed"]}
    if not quiet:
        print(f"scenario: {d}  vehicles={meta['vehicles']}  rsus={len(place_rsus.read_csv(rsus))}  ({real})")
    return out


def _rsu_bounds(preset: dict, spacing: float) -> tuple[float, float, float, float]:
    """RSU grid inset by half a spacing, so RSUs sit inside the box (3 x 3 at 450 m in 1.35 km)."""
    x0, y0, x1, y1 = preset["box"]
    h = spacing / 2
    return x0 + h, y0 + h, x1 - h, y1 - h


def place_rsus_file(spacing: float) -> str:
    return f"rsus_{int(spacing)}m.csv"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--real", default="lust:peak", help="preset:window, e.g. lust:low, lust:mid, lust:peak")
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--step", type=float, default=0.1)
    ap.add_argument("--rsu-spacing", type=float, default=450.0)
    ap.add_argument("--rsu-range", type=float, default=300.0)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    ensure_real_scenario(a.real, a.duration, a.seed, a.step, a.rsu_spacing, a.rsu_range, force=a.force)


if __name__ == "__main__":
    main()
