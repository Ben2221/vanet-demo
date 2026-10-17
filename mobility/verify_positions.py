"""Check that the ns-2 mobility file reproduces SUMO's positions.

Reads the FCD output and the ns-2 file, and compares every vehicle position at
every FCD sample. With --ns3 it also loads the ns-2 file into ns-3's
Ns2MobilityHelper and prints a few positions from inside ns-3.

  python mobility/verify_positions.py mobility/out/grid5x5_250m_v100_d300_s1
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mobility.fcd_to_ns2 import read_fcd
from network import ns2_mobility


def compare(scenario: Path, show: int = 5) -> float:
    with (scenario / "node_map.csv").open() as f:
        node_of = {r["sumo_id"]: int(r["node_id"]) for r in csv.DictReader(f)}
    tracks = read_fcd(scenario / "fcd.xml")
    trajs = ns2_mobility.load(scenario / "trace.ns2")
    worst, count = 0.0, 0
    shown = 0
    for sid, tr in tracks.items():
        if sid not in node_of:
            continue
        nid = node_of[sid]
        for t, x, y, _, _ in tr.samples:
            px, py = trajs[nid].position(t)
            err = math.hypot(px - x, py - y)
            worst = max(worst, err)
            count += 1
        if shown < show:
            t, x, y, _, _ = tr.samples[len(tr.samples) // 2]
            px, py = trajs[nid].position(t)
            print(f"{sid:>8} node {nid:3d} t={t:6.1f}  SUMO ({x:8.2f},{y:8.2f})  ns-2 ({px:8.2f},{py:8.2f})")
            shown += 1
    print(f"compared {count} samples, max position error {worst:.3f} m")
    return worst


def ns3_check(scenario: Path, times=(10.0, 50.0, 100.0)) -> None:
    from ns import ns  # requires ns-3 Python bindings

    with (scenario / "node_map.csv").open() as f:
        rows = list(csv.DictReader(f))
    nodes = ns.NodeContainer()
    nodes.Create(len(rows))
    helper = ns.Ns2MobilityHelper(str(scenario / "trace.ns2"))
    helper.Install()
    ns.cppyy.cppdef("""
        #include "ns3/mobility-module.h"
        std::string vanet_pos(uint32_t id) {
            auto m = ns3::NodeList::GetNode(id)->GetObject<ns3::MobilityModel>();
            auto p = m->GetPosition();
            return std::to_string(ns3::Simulator::Now().GetSeconds()) + " node " + std::to_string(id)
                   + " (" + std::to_string(p.x) + "," + std::to_string(p.y) + ")";
        }
        void vanet_print(uint32_t id) { std::cout << "ns-3: " << vanet_pos(id) << std::endl; }
        void vanet_sched_print(double t, uint32_t id) { ns3::Simulator::Schedule(ns3::Seconds(t), &vanet_print, id); }
    """)
    for t in times:
        for nid in range(min(3, len(rows))):
            ns.cppyy.gbl.vanet_sched_print(t, nid)
    ns.Simulator.Stop(ns.Seconds(max(times) + 1))
    ns.Simulator.Run()
    ns.Simulator.Destroy()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", type=Path, help="folder made by build_scenario.py")
    ap.add_argument("--ns3", action="store_true")
    a = ap.parse_args()
    worst = compare(a.scenario)
    if a.ns3:
        ns3_check(a.scenario)
    sys.exit(0 if worst < 0.5 else 1)


if __name__ == "__main__":
    main()
