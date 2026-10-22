"""Separate visibility demo: three vehicles pass two RSUs on a straight road.

Run in WSL: python network/visibility_demo.py --viz --open-browser
Windows: powershell -ExecutionPolicy Bypass -File network/start_visibility_demo.ps1
The default is 30 seconds with ns-3, live SUMO/TraCI and the real protocol.
Use --build-only for SUMO only.
Existing scenarios and their cached mobility files are never modified.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import time
import webbrowser
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mobility.fcd_to_ns2 import convert  # noqa: E402
from mobility.place_rsus import write_csv  # noqa: E402
from mobility.sumo_env import binary  # noqa: E402
from network.ledger_client import make_client  # noqa: E402
from network.radio import RadioConfig  # noqa: E402
from network.run_scenario import PROFILES, load_protocol, parse_args, pick_backend, read_vehicles  # noqa: E402
from network.scenario import RsuSpec, Scenario  # noqa: E402

DURATION = 30.0
RSU_POSITIONS = [(225.0, 20.0), (675.0, 20.0)]
SERVICE_RANGE = 300.0


def write_xml(path: Path, root: ET.Element) -> None:
    ET.indent(root)
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def run_sumo(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"SUMO command failed: {' '.join(command)}\n{result.stderr}")


def build_mobility(out: Path, seed: int = 1, duration: float = DURATION) -> Path:
    """Build only this demo's SUMO files, trace and fixed RSU layout."""
    out.mkdir(parents=True, exist_ok=True)
    (out / "nodes.nod.xml").write_text(
        '<nodes><node id="start" x="0" y="0" type="dead_end"/>'
        '<node id="end" x="900" y="0" type="dead_end"/></nodes>\n'
    )
    speed = 720.0 / duration
    (out / "edges.edg.xml").write_text(
        '<edges><edge id="road" from="start" to="end" '
        f'numLanes="1" speed="{speed}"/></edges>\n'
    )
    run_sumo([
        binary("netconvert"), "--node-files", str(out / "nodes.nod.xml"),
        "--edge-files", str(out / "edges.edg.xml"),
        "--output-file", str(out / "road.net.xml"),
    ])

    routes = ET.Element("routes")
    ET.SubElement(routes, "vType", id="car", accel="2.6", decel="4.5", sigma="0",
                  length="5", minGap="2.5", maxSpeed=str(speed), speedFactor="1")
    ET.SubElement(routes, "route", id="eastbound", edges="road")
    colors = ["30,110,220", "30,170,90", "235,155,30"]
    for i, (position, color) in enumerate(zip((30, 100, 170), colors)):
        ET.SubElement(routes, "vehicle", id=f"veh{i}", type="car", route="eastbound",
                      depart="0", departPos=str(position), departSpeed=str(speed), color=color)
    write_xml(out / "routes.rou.xml", routes)

    additional = ET.Element("additional")
    for i, ((x, y), color) in enumerate(zip(RSU_POSITIONS, ("220,60,40", "145,65,195"))):
        shape = " ".join(
            f"{x + SERVICE_RANGE * math.cos(a * math.pi / 24):.2f},"
            f"{y + SERVICE_RANGE * math.sin(a * math.pi / 24):.2f}"
            for a in range(49)
        )
        ET.SubElement(additional, "poly", id=f"rsu{i}_service_range", color=color,
                      fill="false", layer="-1", lineWidth="2", shape=shape)
        ET.SubElement(additional, "poi", id=f"rsu{i}", type="RSU", x=str(x), y=str(y),
                      color=color, width="15", height="15", layer="10")
    write_xml(out / "rsus.add.xml", additional)
    write_csv(RSU_POSITIONS, out / "rsus.csv", SERVICE_RANGE, first_node_id=3)

    view = ET.Element("viewsettings")
    scheme = ET.SubElement(view, "scheme", name="real world")
    ET.SubElement(scheme, "vehicles", vehicleQuality="2", vehicle_exaggeration="5",
                  vehicleName_show="true", vehicleName_size="20")
    ET.SubElement(scheme, "pois", poiName_show="true", poiName_size="25")
    ET.SubElement(view, "delay", value="100")
    write_xml(out / "gui-settings.xml", view)

    config = ET.Element("configuration")
    inputs = ET.SubElement(config, "input")
    for tag, filename in (("net-file", "road.net.xml"), ("route-files", "routes.rou.xml"),
                          ("additional-files", "rsus.add.xml")):
        ET.SubElement(inputs, tag, value=filename)
    timing = ET.SubElement(config, "time")
    for tag, value in (("begin", "0"), ("end", str(duration)), ("step-length", "1")):
        ET.SubElement(timing, tag, value=value)
    gui = ET.SubElement(config, "gui_only")
    ET.SubElement(gui, "gui-settings-file", value="gui-settings.xml")
    ET.SubElement(ET.SubElement(config, "random_number"), "seed", value=str(seed))
    write_xml(out / "scenario.sumocfg", config)
    run_sumo([binary("sumo"), "-c", str(out / "scenario.sumocfg"),
              "--fcd-output", str(out / "fcd.xml"), "--no-step-log", "true"])
    count = convert(out / "fcd.xml", out, step=1.0, end_time=duration)
    if count != 3:
        raise RuntimeError(f"Visibility demo requires exactly 3 vehicles; SUMO produced {count}")
    return out / "scenario.sumocfg"


def main(argv: list[str] | None = None) -> dict | None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", choices=["auto", "lite", "ns3"], default="ns3")
    parser.add_argument("--protocol", choices=["stub", "real", "echo"], default="real")
    parser.add_argument("--profile", choices=PROFILES, default="v3-fast")
    parser.add_argument("--duration", type=float, default=DURATION)
    parser.add_argument("--mobility", choices=["trace", "traci"], default="traci")
    parser.add_argument("--viz", action="store_true", help="show the existing live browser UI")
    parser.add_argument("--viz-port", type=int, default=8765)
    parser.add_argument("--live-pace", type=float, default=1.0)
    parser.add_argument("--open-browser", action="store_true")
    parser.add_argument("--hold-seconds", type=float, default=None,
                        help="keep the final UI for this many seconds; default: until Ctrl+C")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--out", type=Path, default=ROOT / "experiments/results/visibility_3v2r")
    parser.add_argument("--build-only", action="store_true", help="prepare SUMO view without running the network")
    args = parser.parse_args(argv)
    if args.duration <= 0 or not math.isfinite(args.duration):
        parser.error("--duration must be a positive finite number")
    if args.live_pace <= 0 or not math.isfinite(args.live_pace):
        parser.error("--live-pace must be a positive finite number")
    if args.open_browser and not args.viz:
        parser.error("--open-browser requires --viz")
    out = args.out.resolve()
    mobility = out / "mobility"
    cfg = build_mobility(mobility, args.seed, args.duration)
    print(f'View the road, vehicles and RSU service ranges: sumo-gui -c "{cfg}"')
    if args.build_only:
        return None

    vehicles = read_vehicles(mobility / "node_map.csv")
    rsus = [RsuSpec(3 + i, f"rsu{i}", x, y, SERVICE_RANGE)
            for i, (x, y) in enumerate(RSU_POSITIONS)]
    radio = RadioConfig()
    backend_name = pick_backend(args.backend)
    viz = None
    live = None
    if args.mobility == "traci":
        from network.traci_mobility import TraciMobility
        live = TraciMobility(cfg, {v.name: v.node_id for v in vehicles}, 3,
                             RSU_POSITIONS, step=0.1, seed=args.seed)
    if backend_name == "ns3":
        from network.backend_ns3 import Ns3Backend

        class DemoBackend(Ns3Backend):
            def finish(self, out_dir):
                # Freeze the UI while node positions still exist, before ns-3 teardown.
                if viz:
                    viz.finish()
                return super().finish(out_dir)

        backend = DemoBackend(None if live else mobility / "trace.ns2", 3, RSU_POSITIONS, radio, seed=args.seed,
                              netanim=str(out / "netanim.xml"), netanim_packets=True)
        for v in vehicles:
            backend.describe(v.node_id, v.name)
        if live:
            live.listeners.append(backend.set_pos_vel)
            for n in range(3):
                backend.set_pos_vel(n, *live.pos[n], *live.vel[n])
    else:
        from network.backend_lite import LiteBackend
        from network.mobility_model import ScenarioMobility
        positions = live or ScenarioMobility(mobility / "trace.ns2", 3, RSU_POSITIONS, args.duration + 2)
        backend = LiteBackend(positions, radio, seed=args.seed)
    if live:
        def sumo_step() -> None:
            live.advance(backend.now())
            backend.schedule(0.1, sumo_step)
        backend.schedule(0.1, sumo_step)

    compute_path = ROOT / "experiments/compute_times_v3.json"
    compute_times = {k: v for k, v in json.loads(compute_path.read_text()).items()
                     if not k.startswith("_")}
    config = vars(parse_args(["--profile", args.profile, "--rsu-cpu", "--v2v-verify", "--privacy-log"]))
    config.update({"demo": "visibility_3v2r", "vehicles": 3, "rsu_count": 2,
                   "duration": args.duration, "seed": args.seed, "protocol": args.protocol,
                   "backend": backend_name, "ledger": "builtin", "trace_threshold": 2,
                   "cluster_size": 1, "mobility": args.mobility, "traci_step": 0.1,
                   "viz": args.viz, "viz_port": args.viz_port, "live_pace": args.live_pace,
                   "scenario_dir": str(mobility), "net_file": str(mobility / "road.net.xml"),
                   "radio": radio.as_table(), "compute_times": str(compute_path),
                   "compute_times_used": compute_times})
    (out / "config.json").write_text(json.dumps(config, indent=2))
    scenario = Scenario(
        backend, vehicles, rsus, load_protocol(args.protocol),
        make_client("builtin", report_k=2, trace_threshold=2, seed=args.seed,
                    trust_weighted=config["trust_weighted"]), out,
        duration=args.duration, seed=args.seed, log_bsm=True,
        compute_times=compute_times, config=config,
    )
    if args.viz:
        from network.viz import Viz
        viz = Viz(scenario, config["net_file"], port=args.viz_port, speed=args.live_pace,
                  title=f"3 vehicles · 2 RSUs · {args.duration:g} seconds · {backend_name} / SUMO")
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
    try:
        summary = scenario.run()
        if viz and backend_name != "ns3":
            viz.finish()
    finally:
        if live:
            live.close()
    print(f"backend={backend_name} vehicles=3 rsus=2 duration={args.duration:g}s")
    print(f"output: {out}")
    if backend_name == "ns3":
        print(f"Open {out / 'netanim.xml'} in NetAnim to see packet exchanges.")
    if viz:
        print("Simulation complete. The browser shows the final state; Ctrl+C to close.", flush=True)
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
    main()
    if "ns" in sys.modules:
        # Match run_scenario.py: avoid cppyy's static-destructor crash on exit.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)
