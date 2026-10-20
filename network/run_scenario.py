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
from network.ledger_client import LedgerError, check_gateway, make_client  # noqa: E402
from network.radio import RadioConfig  # noqa: E402
from network.scenario import RsuSpec, Scenario, VehicleSpec  # noqa: E402

PROTOCOLS = {"stub": "network.protocols.stub_auth", "echo": "network.protocols.echo", "real": "protocol"}
# --profile: defaults for the real protocol options; options given explicitly win
PROFILES = {
    "baseline": {},
    "v2": {"bsm_ticket": "digest", "compact_wire": True, "auth_timeout": 0.2,
           "handover_hysteresis": True, "fast_revocation": True},
}
PROFILES["v2-mac"] = {**PROFILES["v2"], "bsm_auth": "mac", "adaptive_anchor": True}
# v3: every new mechanism on (see "v3 options"); measurement options (--rsu-cpu, --v2v-verify,
# --privacy-log) are not part of a profile, the comparison configs set them for every variant
# v3-fast: every mechanism that lowers latency or load, no extra privacy cost.
# v3-private: v3-fast plus BBS credentials and cooperative mix zones (unlinkability).
# v3 (the first evaluation): all ten mechanisms with fixed TESLA, kept for comparison.
PROFILES["v3"] = {**PROFILES["v2"], "bsm_auth": "tesla", "implicit_cert": True, "cluster_size": 2,
                  "batch_verify": True, "dr_bsm": True, "revocation_filter": True, "mix_zones": True,
                  "credential": "bbs", "trust_weighted": True, "ticket_period": 2.0}
PROFILES["v3-fast"] = {**PROFILES["v2"], "bsm_auth": "tesla", "adaptive_auth": True, "tesla_interval": 0.025,
                       "tesla_key_msgs": True, "implicit_cert": True, "cluster_size": 2, "batch_verify": True,
                       "dr_bsm": True, "revocation_filter": True, "trust_weighted": True, "ticket_period": 2.0,
                       "ticket_renewal": True, "rssi_check": True}
# (the learned detector, --detector-mode hybrid, is not in the profiles: trained on the grid it
#  reported honest vehicles on LuST; rules + the signal-strength check transfer across cities)
PROFILES["v3-private"] = {**PROFILES["v3-fast"], "credential": "bbs", "mix_zones": True}


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def _positive_float(text: str) -> float:
    value = float(text)
    if not value > 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return value


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_argument_group("scenario")
    g.add_argument("--vehicles", type=int, default=100, help="vehicles in the SUMO scenario (default 100)")
    g.add_argument("--duration", type=float, default=300.0, help="simulated seconds (default 300)")
    g.add_argument("--seed", type=int, default=1, help="random seed for SUMO, ns-3 and the apps")
    g.add_argument("--net", default="grid", help="'grid' or a SUMO .net.xml (e.g. an InTAS cut)")
    g.add_argument("--osm", default=None, help="OSM extract to convert instead of the grid")
    g.add_argument("--real", default=None,
                   help="cut from a real city scenario instead: lust:low (06:00, ~150 vehicles in the box), "
                        "lust:mid (14:00, ~260), lust:peak (08:00, ~525); --vehicles is then ignored "
                        "(mobility/real_scenario.py)")
    g.add_argument("--rsu-spacing", type=float, default=450.0, help="RSU grid spacing in m (default 450)")
    g.add_argument("--rsu-range", type=float, default=300.0, help="nominal RSU service range in m (default 300)")
    g.add_argument("--mobility", choices=["trace", "traci"], default="trace",
                   help="'trace': exported ns-2 file (default); 'traci': live SUMO coupling")
    g.add_argument("--traci-step", type=float, default=1.0, help="SUMO step in s for --mobility traci")
    g.add_argument("--mobility-step", type=_positive_float, default=1.0,
                   help="SUMO step and ns-2 waypoint period in s (default 1; 0.1 for smooth acceleration)")

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
    g.add_argument("--detector-mode", choices=["rules", "ml", "hybrid"], default="rules",
                   help="detection.detector: rule checks, the trained model, or both (flag if either does)")
    g.add_argument("--rssi-check", action="store_true",
                   help="RSUs give the detector a distance estimate from received power (signal-strength check)")
    g.add_argument("--detector-model", default=None,
                   help="model file for --detector-mode ml/hybrid (default detection/models/rf.joblib)")
    g.add_argument("--compute-times", default=None,
                   help="JSON {op: seconds} of processing delays (prove, verify, sign, ...); "
                        "default: experiments/compute_times_all.json or protocol/compute_times.json "
                        "if present, 'none' for zero delays")
    g.add_argument("--attacker-ratio", type=float, default=0.0, help="fraction of vehicles that lie in BSMs")
    g.add_argument("--attack", default="const_pos",
                   help="const_pos, random_pos, const_speed, random_speed, sudden_stop, flood")
    g.add_argument("--attack-start", type=float, default=30.0, help="s after which attackers start lying")

    g = ap.add_argument_group("real protocol options")
    g.add_argument("--bsm-ticket", choices=["full", "digest"], default="full",
                   help="'full': ticket in every BSM; 'digest': 8-byte ticket digest, full ticket "
                        "on a new ticket/handover/RSU and every --ticket-every BSMs")
    g.add_argument("--ticket-every", type=_positive_int, default=10, help="digest mode: full ticket every N-th BSM (default 10)")
    g.add_argument("--ticket-period", type=float, default=0.0,
                   help="digest mode: full ticket also at least every S seconds (0 = off; v3: 2)")
    g.add_argument("--compact-wire", action="store_true",
                   help="18-byte fixed-point BSM kinematics, 64-byte BIP340 BSM signatures, no key in RSU beacons")
    g.add_argument("--bsm-auth", choices=["sig", "mac", "tesla"], default="sig",
                   help="'sig': every BSM signed; 'mac': ticket digest + 8-byte HMAC tags for up to 3 RSUs "
                        "heard in the last 0.35 s (ECDH session keys), a signed anchor every --anchor-every BSMs; "
                        "'tesla': TESLA MACs any receiver can check once the key is disclosed, signed anchors")
    g.add_argument("--anchor-every", type=_positive_int, default=10,
                   help="mac mode: signed anchor every N-th BSM (default 10). Full-ticket BSMs are anchors "
                        "too, so the effective gap is min(N, --ticket-every); RSUs reject MAC BSMs after "
                        "4 such gaps without an anchor")
    g.add_argument("--adaptive-anchor", action="store_true",
                   help="mac mode: anchor period from the vehicle's CBR: N/2 (min 2) below 0.2, N up to 0.4, "
                        "2N above (0.02 hysteresis, at most one change per s; 2N needs --ticket-every >= 2N)")
    g.add_argument("--auth-timeout", type=_positive_float, default=1.0,
                   help="s a vehicle waits for AUTH_RESP before it retries on the next beacon (default 1.0)")
    g.add_argument("--handover-hysteresis", action="store_true",
                   help="current RSU lost after 1 s without beacons (not 0.35), hand over only to an RSU heard "
                        "3 times in the last 0.5 s, no handover for 1 s after one unless the RSU is lost; "
                        "handovers do not count as pseudonym sessions")
    g.add_argument("--fast-revocation", action="store_true",
                   help="RSUs send signed QUARANTINE notes of their reports to their neighbours and block a pid "
                        "locally once --report-k distinct RSUs reported it (30 s, or until the ledger revokes it)")
    g.add_argument("--profile", choices=sorted(PROFILES), default="baseline",
                   help="defaults for the options above: 'v2' = --bsm-ticket digest --compact-wire "
                        "--auth-timeout 0.2 --handover-hysteresis --fast-revocation; 'v2-mac' = v2 + "
                        "--bsm-auth mac --adaptive-anchor; 'v3' = v2 + --bsm-auth tesla --implicit-cert "
                        "--cluster-size 2 --batch-verify --dr-bsm --revocation-filter --mix-zones "
                        "--credential bbs --trust-weighted. Explicit options override it")

    g = ap.add_argument_group("v3 options (real protocol)")
    g.add_argument("--implicit-cert", action="store_true",
                   help="ECQV implicit-certificate tickets (~90 B instead of ~160 B)")
    g.add_argument("--tesla-interval", type=_positive_float, default=0.05, help="TESLA interval in s (default 0.05)")
    g.add_argument("--tesla-delay", type=_positive_int, default=2, help="TESLA disclosure delay in intervals (default 2)")
    g.add_argument("--cluster-size", type=int, default=0,
                   help="RSU clusters of N x N grid RSUs: no handover inside a cluster (0 = off)")
    g.add_argument("--batch-verify", action="store_true",
                   help="verify signed BSMs in batches (implies the CPU model at RSUs)")
    g.add_argument("--dr-bsm", action="store_true",
                   help="send a BSM only when dead reckoning from the last one is off by > --dr-threshold m, "
                        "speed changed > 0.5 m/s, heading > 4 deg, or after --dr-max-gap s")
    g.add_argument("--dr-threshold", type=_positive_float, default=1.0)
    g.add_argument("--dr-max-gap", type=_positive_float, default=1.0)
    g.add_argument("--revocation-filter", action="store_true",
                   help="Bloom filter of recently revoked pseudonyms in signed RSU beacons (2 Hz)")
    g.add_argument("--mix-zones", action="store_true",
                   help="change pseudonym only at junctions with >= 3 vehicles within 50 m, then 0.5 s silence")
    g.add_argument("--mix-k", type=int, default=3, help="mix zones: neighbours needed for a change (default 3)")
    g.add_argument("--mix-silent-max", type=_positive_float, default=5.0,
                   help="mix zones: longest silence after a change in s (default 5)")
    g.add_argument("--pseudonyms", type=int, default=0, help="pseudonyms per vehicle (0: real protocol 5, or 20 with --mix-zones; baselines 20)")
    g.add_argument("--credential", choices=["merkle", "bbs"], default="merkle",
                   help="'merkle': registered pseudonyms + Schnorr ZKP; 'bbs': BBS anonymous credential")
    g.add_argument("--bbs-j", type=_positive_int, default=32, help="BBS pseudonyms per credential and epoch")
    g.add_argument("--adaptive-auth", action="store_true",
                   help="with --bsm-auth tesla: sign every BSM while the vehicle's CBR is below 0.2-0.3, TESLA above")
    g.add_argument("--tesla-key-msgs", action="store_true",
                   help="send each TESLA key as soon as it may be disclosed (TESLA_KEY, ~35 B) instead of in the next BSM")
    g.add_argument("--ticket-renewal", action="store_true",
                   help="renew a ticket before it expires with one signed request (no new ZKP / BBS proof)")
    g.add_argument("--trust-weighted", action="store_true",
                   help="revocation needs report weight >= --report-k; the TA lowers the weight of RSUs "
                        "whose reports an investigation found wrong")
    g.add_argument("--faulty-rsus", type=float, default=0.0,
                   help="fraction of RSUs that report random honest pseudonyms (compromised RSUs)")

    g = ap.add_argument_group("measurement")
    g.add_argument("--rsu-cpu", action="store_true",
                   help="RSU crypto on one processor in arrival order: queueing in BSM acceptance latency")
    g.add_argument("--v2v-verify", action="store_true",
                   help="vehicles verify neighbours' BSMs within --v2v-radius on their own processor")
    g.add_argument("--v2v-radius", type=_positive_float, default=100.0)
    g.add_argument("--obu-scale", type=_positive_float, default=1.0,
                   help="vehicle processor is this many times slower than the measured times")
    g.add_argument("--detector-log", action="store_true",
                   help="write detector_log.npz: every BSM's detector features and ground truth (training data)")
    g.add_argument("--privacy-log", action="store_true",
                   help="write observed_bsms.csv (what a global eavesdropper hears) for experiments/tracker.py")

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
    g.add_argument("--live", action="store_true",
                   help="narrate the run in plain English while it runs (experiments/live.py)")
    g.add_argument("--live-all", action="store_true",
                   help="with --live: also every handover, renewal, pseudonym change and ledger write")
    g.add_argument("--live-pace", type=float, default=0.0,
                   help="with --live: simulated seconds per wall second (1 = real time, 0 = as fast as possible)")
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


def load_detector(spec: str, mode: str = "rules", model: str | None = None):
    # detection.detector reads these when it checks / loads its model
    os.environ["VANET_DETECTOR"] = mode
    if model:
        os.environ["VANET_MODEL"] = str(Path(model).resolve())
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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse once for --profile, then again with the profile's values as defaults."""
    ap = build_parser()
    ap.set_defaults(**PROFILES[ap.parse_args(argv).profile])
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> dict:
    a = parse_args(argv)
    if a.ledger.startswith(("http://", "https://")):
        try:
            check_gateway(a.ledger)      # before the (slow) scenario build
        except LedgerError as e:
            raise SystemExit(f"error: {e}")
    t_wall = time.time()
    if a.real:
        from mobility.real_scenario import ensure_real_scenario
        sc = ensure_real_scenario(a.real, a.duration, a.seed, a.mobility_step, a.rsu_spacing, a.rsu_range,
                                  quiet=a.quiet)
    else:
        sc = ensure_scenario(a.vehicles, a.duration, a.seed, a.net, a.osm, a.rsu_spacing, a.rsu_range,
                             quiet=a.quiet, step=a.mobility_step)
    vehicles = read_vehicles(sc["node_map"])
    rsus = [RsuSpec(r["node_id"], r["rsu_id"], r["x"], r["y"], r["range_m"]) for r in read_rsus(sc["rsus"])]

    backend_name = pick_backend(a.backend)
    tag = f"{Path(sc['dir']).name}_r{int(a.rsu_spacing)}_{backend_name}_{a.protocol.replace('.', '-')}"
    if a.profile != "baseline":
        tag += f"_{a.profile}"      # runs of different profiles must not overwrite each other
    if a.ledger.startswith(("http://", "https://")):
        tag += "_gw"      # runs against a gateway must not overwrite the in-memory ledger's runs
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
                         commit_ms=a.mock_commit_ms, seed=a.seed, identity_header=a.identity_header,
                         trust_weighted=a.trust_weighted)
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
              "net_file": str(sc["net"]),
              "radio": radio.as_table()}
    (out / "config.json").write_text(json.dumps(config, indent=2, default=str))

    scenario = Scenario(
        backend, vehicles, rsus, load_protocol(a.protocol), client, out,
        duration=a.duration, seed=a.seed, beacon_rate=a.beacon_rate, bsm_size=a.bsm_size,
        congestion_control=a.congestion_control, cbr_threshold=a.cbr_threshold,
        pdr_range=a.pdr_range, log_bsm=a.log_bsm, detector=load_detector(a.detector, a.detector_mode, a.detector_model),
        attacker_ratio=a.attacker_ratio, attack=a.attack, attack_start=a.attack_start,
        compute_times=compute_times, ledger_sync=a.ledger_sync, backbone_ms=a.backbone_ms, config=config,
    )
    narrator = None
    if a.live:
        from experiments.live import Narrator
        st = scenario.stats
        narrator = Narrator(a.live_all, pace=a.live_pace, counters=lambda: {"BSMs sent": st.sent_by_type.get("BSM", 0),
                                              "BSM bytes": st.bytes_by_type.get("BSM", 0)})
        scenario.metrics.listeners.append(narrator.feed)
    try:
        summary = scenario.run()
    finally:
        if live:
            live.close()
    if narrator:
        narrator.finish()
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
