"""Build a SUMO scenario and export it for ns-3.

Steps:
  1. road network: a synthetic grid from netgenerate (default), an OSM extract
     (``--osm map.osm.xml``, e.g. from osmWebWizard.py) or an existing
     ``.net.xml`` (e.g. a cut of the InTAS Ingolstadt scenario)
  2. traffic: randomTrips.py, N vehicles inserted over the first part of the run
  3. SUMO run with --fcd-output (1 s samples)
  4. FCD -> ns-2 mobility file + SUMO-id -> ns-3-node-id table (fcd_to_ns2.py)
  5. RSUs on a road grid -> rsus.csv (place_rsus.py)

Everything goes into one folder per (network, vehicles, duration, seed), and a
finished folder is reused, so experiment sweeps only build each case once.

Example:
  python mobility/build_scenario.py --vehicles 100 --duration 300 --seed 1
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mobility import fcd_to_ns2, place_rsus
from mobility.sumo_env import binary, tool

MOBILITY_DIR = Path(__file__).resolve().parent
NETS_DIR = MOBILITY_DIR / "nets"
OUT_DIR = MOBILITY_DIR / "out"


def _run(cmd: list[str], log: Path | None = None) -> None:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if log is not None:
        with log.open("a") as f:
            f.write("$ " + " ".join(cmd) + "\n" + res.stdout + res.stderr + "\n")
    if res.returncode != 0:
        raise RuntimeError(f"command failed ({res.returncode}): {' '.join(cmd)}\n{res.stderr[-2000:]}")


def grid_net(junctions: int = 5, block: float = 250.0, lanes: int = 2) -> Path:
    """A Manhattan grid with traffic lights; cached in mobility/nets/."""
    NETS_DIR.mkdir(parents=True, exist_ok=True)
    net = NETS_DIR / f"grid{junctions}x{junctions}_{int(block)}m.net.xml"
    if not net.exists():
        _run([
            binary("netgenerate"), "--grid",
            "--grid.number", str(junctions), "--grid.length", str(block),
            "--default.lanenumber", str(lanes), "--default.speed", "13.89",
            "--tls.guess", "true", "--no-turnarounds", "true",
            "--output-file", str(net),
        ])
    return net


def osm_net(osm_file: Path) -> Path:
    """Convert an OSM extract (e.g. from osmWebWizard.py) into a SUMO network."""
    NETS_DIR.mkdir(parents=True, exist_ok=True)
    net = NETS_DIR / (osm_file.name.split(".")[0] + ".net.xml")
    if not net.exists():
        _run([
            binary("netconvert"), "--osm-files", str(osm_file),
            "--geometry.remove", "--ramps.guess", "--junctions.join",
            "--tls.guess-signals", "--tls.discard-simple", "--tls.join",
            "--keep-edges.by-vclass", "passenger", "--remove-edges.isolated",
            "--output-file", str(net),
        ])
    return net


def resolve_net(net_arg: str, osm: str | None) -> Path:
    if osm:
        return osm_net(Path(osm))
    if net_arg == "grid":
        return grid_net()
    path = Path(net_arg)
    if not path.exists():
        raise FileNotFoundError(net_arg)
    return path


def scenario_dir(net: Path, vehicles: int, duration: float, seed: int, step: float = 1.0) -> Path:
    name = net.name.replace(".net.xml", "")
    suffix = "" if step == 1.0 else f"_st{step:g}"     # 1 s scenarios keep their old names
    return OUT_DIR / f"{name}_v{vehicles}_d{int(duration)}_s{seed}{suffix}"


def rsu_file(d: Path, spacing: float) -> Path:
    return d / f"rsus_{int(spacing)}m.csv"


def ensure_scenario(vehicles: int = 100, duration: float = 300.0, seed: int = 1,
                    net: str = "grid", osm: str | None = None,
                    rsu_spacing: float = 450.0, rsu_range: float = 300.0,
                    insert_fraction: float = 0.5, traceexporter: bool = False,
                    force: bool = False, quiet: bool = False, step: float = 1.0) -> dict:
    """Build (or reuse) a scenario. Returns a dict of paths and counts.

    ``step`` is SUMO's step length and the ns-2 waypoint period: between waypoints a
    node moves in a straight line at constant speed (0.1 s gives smooth acceleration,
    which matters for dead reckoning)."""
    net_path = resolve_net(net, osm)
    d = scenario_dir(net_path, vehicles, duration, seed, step)
    meta_file = d / "scenario.json"
    if force and d.exists():
        shutil.rmtree(d)

    if not meta_file.exists():
        d.mkdir(parents=True, exist_ok=True)
        log = d / "build.log"
        trips, routes = d / "trips.trips.xml", d / "routes.rou.xml"
        insert_end = max(1.0, duration * insert_fraction)
        # randomTrips makes one trip per period over [begin, end)
        period = insert_end / vehicles
        _run([
            sys.executable, tool("randomTrips.py"), "-n", str(net_path),
            "-o", str(trips), "-r", str(routes),
            "-b", "0", "-e", f"{insert_end:.3f}", "-p", f"{period:.6f}",
            "--seed", str(seed), "--fringe-factor", "5", "--min-distance", "300",
            "--validate", "--prefix", "veh",
            "--trip-attributes", 'departLane="best" departSpeed="max"',
        ], log)

        cfg = d / "scenario.sumocfg"
        cfg.write_text(f"""<configuration>
  <input>
    <net-file value="{net_path.resolve()}"/>
    <route-files value="{routes.name}"/>
  </input>
  <time><begin value="0"/><end value="{duration}"/><step-length value="{step:g}"/></time>
  <random_number><seed value="{seed}"/></random_number>
  <processing><time-to-teleport value="120"/><ignore-route-errors value="true"/></processing>
  <report><no-step-log value="true"/><no-warnings value="true"/></report>
</configuration>
""")
        fcd = d / "fcd.xml"
        _run([binary("sumo"), "-c", str(cfg), "--fcd-output", str(fcd),
              "--fcd-output.geo", "false"], log)
        if traceexporter:
            # SUMO's own exporter, kept for comparison; run_scenario uses trace.ns2
            _run([sys.executable, tool("traceExporter.py"), "--fcd-input", str(fcd),
                  "--ns2mobility-output", str(d / "trace_traceexporter.ns2")], log)

        n = fcd_to_ns2.convert(fcd, d, step=step, end_time=duration)
        try:   # relative path, so the folder also works when the repo is mounted elsewhere
            net_ref = net_path.resolve().relative_to(MOBILITY_DIR).as_posix()
        except ValueError:
            net_ref = str(net_path.resolve())
        meta = {
            "net": net_ref, "vehicles_requested": vehicles,
            "vehicles": n, "duration": duration, "seed": seed,
            "trace": "trace.ns2", "node_map": "node_map.csv", "fcd": "fcd.xml",
        }
        meta_file.write_text(json.dumps(meta, indent=2))

    meta = json.loads(meta_file.read_text())
    meta["net"] = str(MOBILITY_DIR / meta["net"])     # no-op for absolute paths
    n = meta["vehicles"]
    rsus = rsu_file(d, rsu_spacing)
    if not rsus.exists():
        pts = place_rsus.place(Path(meta["net"]), rsu_spacing)
        place_rsus.write_csv(pts, rsus, rsu_range, first_node_id=n)
    shutil.copyfile(rsus, d / "rsus.csv")
    out = {
        "dir": d, "net": Path(meta["net"]), "trace": d / meta["trace"],
        "node_map": d / meta["node_map"], "fcd": d / meta["fcd"], "rsus": rsus,
        "vehicles": n, "duration": meta["duration"], "seed": meta["seed"],
    }
    if not quiet:
        print(f"scenario: {d}  vehicles={n}  rsus={len(place_rsus.read_csv(rsus))}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vehicles", type=int, default=100)
    ap.add_argument("--duration", type=float, default=300.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--net", default="grid", help="'grid' or a .net.xml file (e.g. an InTAS cut)")
    ap.add_argument("--osm", default=None, help="OSM extract to convert (osmWebWizard output)")
    ap.add_argument("--rsu-spacing", type=float, default=450.0)
    ap.add_argument("--rsu-range", type=float, default=300.0)
    ap.add_argument("--insert-fraction", type=float, default=0.5,
                    help="vehicles are inserted during the first fraction of the run")
    ap.add_argument("--traceexporter", action="store_true",
                    help="also write SUMO's traceExporter ns-2 file for comparison")
    ap.add_argument("--force", action="store_true", help="rebuild even if cached")
    ap.add_argument("--step", type=float, default=1.0, help="SUMO step / ns-2 waypoint period in s (default 1)")
    a = ap.parse_args()
    ensure_scenario(a.vehicles, a.duration, a.seed, a.net, a.osm, a.rsu_spacing,
                    a.rsu_range, a.insert_fraction, a.traceexporter, a.force, step=a.step)


if __name__ == "__main__":
    main()
