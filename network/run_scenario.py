"""Run the VANET scenario: SUMO mobility + IEEE 802.11p network + protocol + ledger.

One command builds (or reuses) the SUMO scenario, sets up the radio network,
plugs in the protocol, detector and ledger, runs it, and writes:

  <out>/metrics.csv     one row per event (interface 6)
  <out>/summary.json    PDR, delays, channel busy ratio, ledger commit times, ...
  <out>/config.json     every parameter of the run
  <out>/attackers.csv   ground truth for misbehaviour detection
  <out>/flowmon.xml     FlowMonitor statistics (ns-3 backend)
  <out>/netanim.xml     NetAnim animation (ns-3 backend, --netanim)

Examples:
  python network/run_scenario.py --vehicles 100 --duration 300 --seed 1
  python network/run_scenario.py --backend lite --protocol echo --duration 60
  python network/run_scenario.py --protocol real --ledger http://localhost:3000 --netanim
"""

from __future__ import annotations

import argparse
import csv
import importlib
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mobility.build_scenario import ensure_scenario  # noqa: E402
from mobility.place_rsus import read_csv as read_rsus  # noqa: E402
from network.ledger_client import make_client  # noqa: E402
from network.radio import RadioConfig  # noqa: E402
from network.scenario import RsuSpec, Scenario, VehicleSpec  # noqa: E402

PROTOCOLS = {"stub": "network.protocols.stub_auth", "echo": "network.protocols.echo", "real": "protocol"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_argument_group("scenario")
    g.add_argument("--vehicles", type=int, default=100, help="vehicles in the SUMO scenario (default 100)")
    g.add_argument("--duration", type=float, default=300.0, help="simulated seconds (default 300)")
    g.add_argument("--seed", type=int, default=1, help="random seed for SUMO, ns-3 and the apps")
    g.add_argument("--net", default="grid", help="'grid' or a SUMO .net.xml (e.g. an InTAS cut)")
    g.add_argument("--osm", default=None, help="OSM extract to convert instead of the grid")
    g.add_argument("--bbox", default=None, help="with --osm: keep roads in minlon,minlat,maxlon,maxlat")
    g.add_argument("--rsu-spacing", type=float, default=450.0, help="RSU grid spacing in m (default 450)")
    g.add_argument("--rsu-range", type=float, default=300.0, help="nominal RSU service range in m (default 300)")
    g.add_argument("--mobility", choices=["trace", "traci"], default="trace",
                   help="'trace': exported ns-2 file (default); 'traci': live SUMO coupling")
    g.add_argument("--traci-step", type=float, default=1.0, help="SUMO step in s for --mobility traci")

    g = ap.add_argument_group("radio (IEEE 802.11p)")
    g.add_argument("--data-rate", type=float, default=6, help="Mb/s at 10 MHz (default 6)")
    g.add_argument("--tx-power", type=float, default=20.0, help="dBm (default 20)")
    g.add_argument("--rx-sensitivity", type=float, default=-85.0, help="dBm (default -85)")
    g.add_argument("--range", type=float, default=400.0, help="radio range in m; sets the path-loss exponent")
    g.add_argument("--fading", choices=["none", "nakagami"], default="none")

    g = ap.add_argument_group("applications")
    g.add_argument("--beacon-rate", type=float, default=10.0, help="BSM rate in Hz (default 10)")
    g.add_argument("--bsm-size", type=int, default=200, help="plain BSM size in bytes if the protocol builds none")
    g.add_argument("--congestion-control", action="store_true", help="halve the beacon rate when CBR > threshold")
    g.add_argument("--cbr-threshold", type=float, default=0.6)
    g.add_argument("--protocol", default="stub",
                   help="'stub' (stand-in auth), 'echo', 'real' (Person 3's protocol/ package) or a module path")
    g.add_argument("--detector", default="auto",
                   help="'auto' (detection.detector.check if present), 'none', or module:function")
    g.add_argument("--compute-times", default=None,
                   help="JSON {op: seconds} of processing delays (prove, verify, sign, ...); "
                        "default: experiments/compute_times_all.json or protocol/compute_times.json "
                        "if present, 'none' for zero delays")
    g.add_argument("--full-ticket-every", type=int, default=10,
                   help="real protocol: full ticket in every N-th BSM, an 8-byte digest in the others "
                        "(default 10 = once a second at 10 Hz, like IEEE 1609.2 certificates; 1 = always)")
    g.add_argument("--attacker-ratio", type=float, default=0.0, help="fraction of vehicles that lie in BSMs")
    g.add_argument("--attack", default="const_pos",
                   help="const_pos, random_pos, const_speed, random_speed, sudden_stop, flood")
    g.add_argument("--attack-start", type=float, default=30.0, help="s after which attackers start lying")

    g = ap.add_argument_group("ledger")
    g.add_argument("--ledger", default="mock", help="'mock', 'builtin' or the gateway URL (real Fabric)")
    g.add_argument("--mock-commit-ms", type=float, default=500.0, help="commit time of the built-in mock")
    g.add_argument("--report-k", type=int, default=2, help="RSU reports needed for auto-revocation")
    g.add_argument("--trace-threshold", type=int, default=0, help="approvals to reveal (0 = 2f+1 of the RSUs)")
    g.add_argument("--backbone-ms", type=float, default=2.0, help="RSU-to-RSU wired backbone latency (ms)")
    g.add_argument("--ledger-sync", type=float, default=1.0, help="revocation sync period (s), real Fabric only")
    g.add_argument("--identity-header", default="X-Identity", help="HTTP header carrying the caller identity")

    g = ap.add_argument_group("simulator and output")
    g.add_argument("--backend", choices=["auto", "ns3", "lite"], default="auto",
                   help="ns-3 if its Python bindings import, else the lite model")
    g.add_argument("--pdr-range", type=float, default=300.0, help="broadcast PDR counts receivers within this range")
    g.add_argument("--log-bsm", action="store_true", help="one CSV row per BSM and RSU beacon sent/received (large)")
    g.add_argument("--netanim", action="store_true", help="write netanim.xml (ns-3 backend)")
    g.add_argument("--netanim-packets", action="store_true", help="include packets in NetAnim (very large)")
    g.add_argument("--no-flowmon", action="store_true", help="disable FlowMonitor (ns-3 backend)")
    g.add_argument("--out", default=None, help="output folder (default experiments/results/<name>)")
    g.add_argument("--quiet", action="store_true")
    return ap


def load_protocol(name: str):
    module = PROTOCOLS.get(name, name)
    try:
        mod = importlib.import_module(module)
    except ImportError as exc:
        raise SystemExit(f"cannot import protocol '{module}': {exc}") from exc
    for fn in ("create_vehicle", "create_rsu"):
        if not hasattr(mod, fn):
            raise SystemExit(f"protocol '{module}' must define {fn}(node, env); see docs/interfaces.md")
    return mod


def load_detector(spec: str):
    if spec == "none":
        return None
    if spec == "auto":
        try:
            from detection.detector import check  # Person 4
            return check
        except ImportError:
            return None
    module, _, fn = spec.partition(":")
    return getattr(importlib.import_module(module), fn or "check")


def pick_backend(choice: str) -> str:
    if choice != "auto":
        return choice
    try:
        from ns import ns  # noqa: F401
        return "ns3"
    except ImportError:
        return "lite"


def read_vehicles(node_map: Path, limit: int | None = None) -> list[VehicleSpec]:
    with node_map.open() as f:
        rows = [VehicleSpec(int(r["node_id"]), r["sumo_id"], float(r["first_seen"]), float(r["last_seen"]))
                for r in csv.DictReader(f)]
    return rows[:limit] if limit else rows


def main(argv: list[str] | None = None) -> dict:
    a = build_parser().parse_args(argv)
    t_wall = time.time()
    sc = ensure_scenario(a.vehicles, a.duration, a.seed, a.net, a.osm, a.rsu_spacing, a.rsu_range,
                         quiet=a.quiet, bbox=a.bbox)
    vehicles = read_vehicles(sc["node_map"])
    rsus = [RsuSpec(r["node_id"], r["rsu_id"], r["x"], r["y"], r["range_m"]) for r in read_rsus(sc["rsus"])]

    backend_name = pick_backend(a.backend)
    tag = f"{Path(sc['dir']).name}_r{int(a.rsu_spacing)}_{backend_name}_{a.protocol.replace('.', '-')}"
    out = Path(a.out) if a.out else ROOT / "experiments" / "results" / tag
    out.mkdir(parents=True, exist_ok=True)

    radio = RadioConfig(data_rate_mbps=a.data_rate, tx_power_dbm=a.tx_power,
                        rx_sensitivity_dbm=a.rx_sensitivity, target_range_m=a.range, fading=a.fading)
    rsu_xy = [(r.x, r.y) for r in rsus]
    live = None
    if a.mobility == "traci":
        from network.traci_mobility import TraciMobility
        live = TraciMobility(Path(sc["dir"]) / "scenario.sumocfg", {v.name: v.node_id for v in vehicles},
                             len(vehicles), rsu_xy, step=a.traci_step, seed=a.seed)
    if backend_name == "ns3":
        from network.backend_ns3 import Ns3Backend
        backend = Ns3Backend(None if live else sc["trace"], len(vehicles), rsu_xy, radio, seed=a.seed,
                             flowmon=not a.no_flowmon,
                             netanim=str(out / "netanim.xml") if a.netanim else None,
                             netanim_packets=a.netanim_packets)
        if live:
            live.listeners.append(backend.set_pos_vel)
            for n in range(len(vehicles)):
                backend.set_pos_vel(n, *live.pos[n], *live.vel[n])
    else:
        from network.backend_lite import LiteBackend
        from network.mobility_model import ScenarioMobility
        mob = live or ScenarioMobility(sc["trace"], len(vehicles), rsu_xy, a.duration + 2)
        backend = LiteBackend(mob, radio, seed=a.seed)
    if live:
        def sumo_step() -> None:
            live.advance(backend.now())
            backend.schedule(a.traci_step, sumo_step)

        backend.schedule(a.traci_step, sumo_step)

    threshold = a.trace_threshold or (2 * ((len(rsus) - 1) // 3) + 1)
    client = make_client(a.ledger, report_k=a.report_k, trace_threshold=threshold,
                         commit_ms=a.mock_commit_ms, seed=a.seed, identity_header=a.identity_header)
    ct_path = a.compute_times
    if ct_path is None:
        # default: measured crypto costs (protocol/measure.py; with the ECDSA baseline merged in,
        # experiments/measure_ecdsa.py --merge) so latencies include computation, not only airtime
        for cand in (ROOT / "experiments" / "compute_times_all.json", ROOT / "protocol" / "compute_times.json"):
            if cand.exists():
                ct_path = str(cand)
                break
    compute_times = {k: v for k, v in json.loads(Path(ct_path).read_text()).items()
                     if not k.startswith("_")} if ct_path and ct_path != "none" else {}
    if not a.quiet:
        print(f"compute times: {ct_path or 'none (all processing delays are 0)'}")

    config = {**vars(a), "compute_times": ct_path, "compute_times_used": compute_times,
              "backend": backend_name, "scenario_dir": str(sc["dir"]),
              "vehicles_in_trace": len(vehicles), "rsu_count": len(rsus), "trace_threshold": threshold,
              "radio": radio.as_table()}
    (out / "config.json").write_text(json.dumps(config, indent=2, default=str))

    scenario = Scenario(
        backend, vehicles, rsus, load_protocol(a.protocol), client, out,
        duration=a.duration, seed=a.seed, beacon_rate=a.beacon_rate, bsm_size=a.bsm_size,
        congestion_control=a.congestion_control, cbr_threshold=a.cbr_threshold,
        pdr_range=a.pdr_range, log_bsm=a.log_bsm, detector=load_detector(a.detector),
        attacker_ratio=a.attacker_ratio, attack=a.attack, attack_start=a.attack_start,
        compute_times=compute_times, ledger_sync=a.ledger_sync, backbone_ms=a.backbone_ms, config=config,
    )
    try:
        summary = scenario.run()
    finally:
        if live:
            live.close()
    summary["wall_time_s"] = round(time.time() - t_wall, 1)
    (out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    if not a.quiet:
        pdr = summary["broadcast_pdr"]
        bsm = summary["delay_ms"].get("BSM", {})
        print(f"backend={backend_name} vehicles={len(vehicles)} rsus={len(rsus)} "
              f"duration={a.duration:g}s wall={summary['wall_time_s']}s")
        print(f"broadcast PDR (<= {a.pdr_range:g} m): {pdr:.3f}" if pdr is not None else "no broadcasts")
        if bsm.get("n"):
            print(f"BSM delay: mean {bsm['mean']:.3f} ms, p95 {bsm['p95']:.3f} ms")
        if summary.get("cbr_rsu_mean") is not None:
            print(f"channel busy ratio at RSUs: mean {summary['cbr_rsu_mean']:.3f}")
        print(f"ledger: {summary['ledger']}")
        print(f"output: {out}")
    return summary


if __name__ == "__main__":
    main()
    if "ns" in sys.modules:
        # every output is written and closed. With FlowMonitor or NetAnim loaded,
        # cppyy/cling crashes in its static destructors at interpreter exit
        # ("double free"), so leave without running them.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)
