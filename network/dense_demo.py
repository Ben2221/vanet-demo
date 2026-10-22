"""Presentation: 250 concurrent cars in 1 km², with emergency vehicles and attackers.

Windows: powershell -ExecutionPolicy Bypass -File network/start_dense_demo.ps1
WSL: python network/dense_demo.py --open-browser
The default run is 30 simulated seconds; the final browser state stays until Ctrl+C.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.dense_results import save_completed, set_status, stored_run, write_json  # noqa: E402
from mobility.dense_presentation import VEHICLES, build_mobility  # noqa: E402
from mobility.place_rsus import read_csv  # noqa: E402
from network.ledger_client import make_client  # noqa: E402
from network.radio import RadioConfig  # noqa: E402
from network.run_scenario import load_detector, load_protocol, parse_args, read_vehicles  # noqa: E402
from network.scenario import RsuSpec, Scenario  # noqa: E402

ATTACKERS = [f"veh{i}" for i in range(25)]
EMERGENCY = [f"veh{i}" for i in range(25, 50)]


def main(argv: list[str] | None = None) -> dict | None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--attack-start", type=float, default=10.0)
    parser.add_argument("--attack", choices=["random_pos", "const_pos", "random_speed", "const_speed",
                                            "sudden_stop", "flood", "fake_emergency"], default="random_pos")
    parser.add_argument("--viz-port", type=int, default=8766)
    parser.add_argument("--live-pace", type=float, default=1.0)
    parser.add_argument("--open-browser", action="store_true")
    parser.add_argument("--hold-seconds", type=float, default=None,
                        help="keep the completed page for N seconds; default: until Ctrl+C")
    parser.add_argument("--no-viz", action="store_true", help="run without the presentation UI")
    parser.add_argument("--netanim", action="store_true", help="also record NetAnim node movement")
    parser.add_argument("--build-only", action="store_true", help="only prepare and verify SUMO mobility")
    args = parser.parse_args(argv)
    if not math.isfinite(args.duration) or args.duration <= 0:
        parser.error("--duration must be positive and finite")
    if not math.isfinite(args.attack_start) or not 0 <= args.attack_start < args.duration:
        parser.error("--attack-start must be between 0 and the run duration")
    if not math.isfinite(args.live_pace) or args.live_pace <= 0:
        parser.error("--live-pace must be positive and finite")
    if args.open_browser and args.no_viz:
        parser.error("--open-browser cannot be combined with --no-viz")

    with stored_run(vars(args)) as out:
        return run_demo(args, out)


def run_demo(args: argparse.Namespace, out: Path) -> dict | None:
    print("Building the 1 km² map with all 250 vehicles present from time zero...", flush=True)
    sc = build_mobility(out / "mobility", args.duration, args.seed)
    print(f"SUMO population verified: {sc['population_min']}–{sc['population_max']} vehicles; "
          "200 ordinary, 25 emergency, 25 attackers; 9 RSUs.", flush=True)
    if args.build_only:
        set_status(out, "built", note="SUMO mobility only; no network result was produced")
        return None

    # Use the same profile and measurement defaults as the team's live demo.
    config = vars(parse_args([
        "--profile", "v3-fast", "--backend", "ns3", "--protocol", "real",
        "--vehicles", str(VEHICLES), "--duration", str(args.duration), "--seed", str(args.seed),
        "--mobility", "traci", "--traci-step", "0.1", "--mobility-step", "0.1",
        "--rsu-spacing", "450", "--cluster-size", "1", "--rsu-cpu", "--v2v-verify", "--privacy-log",
        "--attacker-vehicles", ",".join(ATTACKERS), "--attacker-ratio", "0.1",
        "--attack", args.attack, "--attack-start", str(args.attack_start),
        "--emergency-vehicles", ",".join(EMERGENCY), "--emergency-priority",
        "--ledger", "builtin", "--trace-threshold", "5",
        "--compute-times", str(ROOT / "experiments/compute_times_v3.json"), "--out", str(out),
    ]))
    compute_times = {k: v for k, v in json.loads(Path(config["compute_times"]).read_text()).items()
                     if not k.startswith("_")}
    radio = RadioConfig()
    config.update({"demo": "dense_presentation_250", "area_km2": 1.0,
                   "density_vehicles_per_km2": VEHICLES, "ordinary_count": 200,
                   "emergency_count": 25, "attacker_count": 25, "rsu_count": 9,
                   "vehicles_in_trace": VEHICLES, "population_min": sc["population_min"],
                   "population_max": sc["population_max"], "scenario_dir": str(sc["dir"]),
                   "net_file": str(sc["net"]), "viz": not args.no_viz,
                   "viz_port": args.viz_port, "live_pace": args.live_pace,
                   "netanim": args.netanim, "radio": radio.as_table(), "compute_times_used": compute_times})
    (out / "config.json").write_text(json.dumps(config, indent=2))
    vehicles = read_vehicles(sc["node_map"])
    rsus = [RsuSpec(r["node_id"], r["rsu_id"], r["x"], r["y"], r["range_m"])
            for r in read_csv(sc["rsus"])]

    from network.backend_ns3 import Ns3Backend
    from network.traci_mobility import TraciMobility

    viz = None

    class PresentationBackend(Ns3Backend):
        def finish(self, out_dir):
            # Freeze the UI before Destroy invalidates ns-3 node positions.
            if viz:
                viz.finish()
                write_json(out / "ui_state.json", json.loads(viz.state))
                write_json(out / "ui_network.json", json.loads(viz.net))
                write_json(out / "ui_feed.json", {"events": list(viz.feed)})
            return super().finish(out_dir)

    print("Starting ns-3 and the real authentication protocol (dense runs may be slower than real time)...",
          flush=True)
    backend = PresentationBackend(None, VEHICLES, [(r.x, r.y) for r in rsus], radio, seed=args.seed,
                                  netanim=str(out / "netanim.xml") if args.netanim else None)
    live = TraciMobility(sc["dir"] / "scenario.sumocfg", {v.name: v.node_id for v in vehicles},
                         VEHICLES, [(r.x, r.y) for r in rsus], step=0.1, seed=args.seed)
    try:
        live.listeners.append(backend.set_pos_vel)
        for n in range(VEHICLES):
            backend.set_pos_vel(n, *live.pos[n], *live.vel[n])

        def sumo_step() -> None:
            live.advance(backend.now())
            backend.schedule(0.1, sumo_step)

        backend.schedule(0.1, sumo_step)
        scenario = Scenario(
            backend, vehicles, rsus, load_protocol("real"),
            make_client("builtin", report_k=2, trace_threshold=5, seed=args.seed, trust_weighted=True), out,
            duration=args.duration, seed=args.seed, detector=load_detector("auto"),
            attacker_names=ATTACKERS, attack=args.attack, attack_start=args.attack_start,
            compute_times=compute_times, config=config,
        )
        def checkpoint() -> None:
            now = backend.now()
            write_json(out / "progress.json", {"state": "running", "simulated_seconds": now,
                                               "requested_seconds": args.duration,
                                               "metrics_rows": scenario.metrics.rows})
            if now + 1 < args.duration:
                backend.schedule(1.0, checkpoint)

        backend.schedule(0.0, checkpoint)
        with (out / "vehicle_roles.csv").open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["node_id", "name", "role"])
            for vehicle in vehicles:
                role = "attacker" if vehicle.name in ATTACKERS else "emergency" if vehicle.name in EMERGENCY else "ordinary"
                writer.writerow([vehicle.node_id, vehicle.name, role])
                if args.netanim:
                    rgb = (255, 138, 61) if role == "attacker" else (255, 77, 94) if role == "emergency" else (90, 169, 255)
                    backend.color(vehicle.node_id, rgb, 9)
                    backend.describe(vehicle.node_id, f"{vehicle.name} ({role})")

        if not args.no_viz:
            from network.viz import Viz
            viz = Viz(scenario, str(sc["net"]), port=args.viz_port, speed=args.live_pace,
                      title="250 cars / 1 km² · 200 ordinary · 25 emergency · 25 attackers · ns-3 + SUMO")
            viz.start()
            if args.open_browser:
                url = f"http://localhost:{args.viz_port}"
                powershell = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
                if powershell.exists():
                    subprocess.run([str(powershell), "-NoProfile", "-Command", f"Start-Process '{url}'"],
                                   check=True, timeout=15)
                else:
                    webbrowser.open(url)
                time.sleep(3)
        started = time.monotonic()
        summary = scenario.run()
        summary.update(wall_time_s=round(time.monotonic() - started, 1), area_km2=1.0,
                       density_vehicles_per_km2=VEHICLES, ordinary=200, emergency=25,
                       population_min=sc["population_min"], population_max=sc["population_max"])
        write_json(out / "summary.json", summary)
        write_json(out / "progress.json", {"state": "completed", "simulated_seconds": args.duration,
                                           "requested_seconds": args.duration,
                                           "metrics_rows": scenario.metrics.rows})
        save_completed(out)
    finally:
        live.close()

    print(f"Completed {args.duration:g} simulated seconds in {summary['wall_time_s']} wall seconds. "
          f"Results: {out}", flush=True)
    if viz:
        print("The final presentation stays on screen. Ctrl+C to close; relaunch to replay.", flush=True)
        try:
            if args.hold_seconds is None:
                while True:
                    time.sleep(1)
            else:
                time.sleep(max(0.0, args.hold_seconds))
        except KeyboardInterrupt:
            pass
        finally:
            viz.server.shutdown()
            viz.server.server_close()
    return summary


if __name__ == "__main__":
    exit_code = 1
    try:
        main()
        exit_code = 0
    finally:
        if "ns" in sys.modules:
            # Also avoid cppyy teardown crashes after a logged failed run.
            sys.stdout.flush()
            sys.stderr.flush()
            os._exit(exit_code)
