"""Isolated 250-vehicle presentation mobility; no protocol roles are registered here.

All vehicles depart at time zero at separated, seeded positions on square-block
loops. Colors are cosmetic: even the emergency type uses passenger permissions.
The parent must register roles by SUMO ID through node_map.csv (the existing
converter assigns node IDs lexicographically, not by the numeric veh suffix).
Generated files stay under experiments/results/dense_presentation_250/mobility;
the shared grid network is only read and copied, never edited.
"""

from __future__ import annotations

import json
import math
import random
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from mobility import fcd_to_ns2, place_rsus
from mobility.build_scenario import grid_net
from mobility.sumo_env import LANECHANGE_ARGS, binary

VEHICLES = 250
SPEED = 13.89
OUTPUT_ROOT = (
    Path(__file__).resolve().parent.parent
    / "experiments" / "results" / "dense_presentation_250" / "mobility"
)


def _write_xml(root: ET.Element, path: Path) -> None:
    ET.indent(root, space="  ")
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)


def _grid_loops(net: Path) -> tuple[dict[str, ET.Element], list[list[str]], set[tuple[str, str, int]]]:
    root = ET.parse(net).getroot()
    edges = {e.attrib["id"]: e for e in root.findall("edge") if "from" in e.attrib}
    junctions = {
        j.attrib["id"]: (float(j.attrib["x"]), float(j.attrib["y"]))
        for j in root.findall("junction") if j.attrib["id"][:1] != ":"
    }
    xs = sorted({x for x, _ in junctions.values()})
    ys = sorted({y for _, y in junctions.values()})
    if xs != [0, 250, 500, 750, 1000] or ys != xs or len(junctions) != 25:
        raise ValueError("Cached network must be a 5x5 junction grid with 250 m spacing")
    if len(edges) != 80 or any(len(e.findall("lane")) != 2 for e in edges.values()):
        raise ValueError("Cached network must have 80 directed edges, each with two lanes")
    for edge in edges.values():
        for lane in edge.findall("lane"):
            if not math.isclose(float(lane.attrib["speed"]), SPEED, abs_tol=0.01):
                raise ValueError("Cached network must have a nominal speed of 13.89 m/s")

    at = {xy: jid for jid, xy in junctions.items()}
    between = {(e.attrib["from"], e.attrib["to"]): eid for eid, e in edges.items()}
    connections = {
        (c.attrib["from"], c.attrib["to"], int(c.attrib["fromLane"]))
        for c in root.findall("connection") if c.attrib["from"] in edges
    }
    connected = {(a, b) for a, b, _ in connections}
    loops = []
    for x in xs[:-1]:
        for y in ys[:-1]:
            corners = [at[x, y], at[x + 250, y], at[x + 250, y + 250], at[x, y + 250]]
            for nodes in (corners, list(reversed(corners))):
                loop = [between[a, b] for a, b in zip(nodes, nodes[1:] + nodes[:1])]
                if not all((a, b) in connected for a, b in zip(loop, loop[1:] + loop[:1])):
                    raise ValueError(f"Square loop has a prohibited turn: {loop}")
                loops.append(loop)
    return edges, loops, connections


def _write_routes(net: Path, routes: Path, duration: float, seed: int) -> None:
    edges, loops, connections = _grid_loops(net)
    rng = random.Random(seed)
    slots = [
        (eid, int(lane.attrib["index"]), position)
        for eid, edge in sorted(edges.items())
        for lane in edge.findall("lane")
        for position in (40, 110, 180)
        if position + 10 < float(lane.attrib["length"])
    ]
    if len(slots) < VEHICLES:
        raise ValueError(f"Only {len(slots)} separated spawn slots available")
    rng.shuffle(slots)
    slots = slots[:VEHICLES]
    root = ET.Element("routes")
    for name, color, shape in (
        ("attacker", "1,0.5,0", "passenger"),
        ("emergency", "1,0,0", "emergency"),
        ("ordinary", "0,0,1", "passenger"),
    ):
        ET.SubElement(root, "vType", id=name, vClass="passenger", guiShape=shape,
                      color=color, maxSpeed=str(SPEED), speedFactor="1", speedDev="0",
                      length="5", minGap="2.5", accel="2.6", decel="4.5", sigma="0.5")

    # Insert the downstream slots first. A stopped departure needs only the
    # physical gap, rather than a speed-dependent braking gap, on both lanes.
    for index, (eid, lane, position) in sorted(
        enumerate(slots), key=lambda item: (item[1][0], -item[1][2], item[1][1])
    ):
        candidates = []
        for loop in loops:
            if eid in loop:
                start = loop.index(eid)
                candidates.append(loop[start:] + loop[:start])
        preferred = [loop for loop in candidates if (eid, loop[1], lane) in connections]
        loop = rng.choice(preferred or candidates)
        minimum_length = sum(
            min(float(l.attrib["length"]) for l in edges[e].findall("lane")) for e in loop
        )
        # Ignore junction lengths for a conservative bound, and allow an extra
        # lap for the initial partial edge. No vehicle can exhaust this route.
        repeats = math.ceil(duration * SPEED / minimum_length) + 2
        role = "attacker" if index < 25 else "emergency" if index < 50 else "ordinary"
        vehicle = ET.SubElement(
            root, "vehicle", id=f"veh{index}", type=role, depart="0",
            departLane=str(lane), departPos=str(position), departSpeed="0",
        )
        ET.SubElement(vehicle, "route", edges=" ".join(loop * repeats))
    _write_xml(root, routes)


def _population(fcd: Path, duration: float, step: float) -> tuple[int, int]:
    expected = {f"veh{i}" for i in range(VEHICLES)}
    count = 0
    minimum, maximum = VEHICLES, 0
    for _, elem in ET.iterparse(fcd, events=("end",)):
        if elem.tag != "timestep":
            continue
        time = float(elem.attrib["time"])
        vehicles = elem.findall("vehicle")
        ids = {v.attrib["id"] for v in vehicles}
        if not math.isclose(time, count * step, abs_tol=1e-6):
            raise RuntimeError(f"Missing or irregular FCD timestep at {count * step:g} s")
        if ids != expected or len(vehicles) != VEHICLES or any(not v.get("lane") for v in vehicles):
            missing = sorted(expected - ids)
            unexpected = sorted(ids - expected)
            raise RuntimeError(
                f"Population violation at {time:g} s: {len(vehicles)} on road; "
                f"missing={missing}, unexpected={unexpected}. Check build.log for insertion/teleport issues."
            )
        minimum = min(minimum, len(vehicles))
        maximum = max(maximum, len(vehicles))
        count += 1
        elem.clear()
    if count != round(duration / step):
        raise RuntimeError(f"Incomplete FCD: {count} timesteps, expected {round(duration / step)}")
    return minimum, maximum


def build_mobility(out: Path, duration: float = 30.0, seed: int = 1, step: float = 0.1) -> dict:
    """Build and validate a private scenario, returning Path objects and counts.

    ``out`` is a private mobility folder inside this demo's result tree. This presentation uses
    0.1 s steps; duration must be a positive whole number of steps. Existing
    generated outputs there are rebuilt, not trusted as a population cache.
    FCD covers [0, duration); the converter parks nodes at duration, as usual.
    """
    if not math.isfinite(step) or not math.isclose(step, 0.1, rel_tol=0, abs_tol=1e-12):
        raise ValueError("The dense presentation requires step=0.1 seconds")
    if (not math.isfinite(duration) or duration < step
            or not math.isclose(duration / step, round(duration / step), abs_tol=1e-7, rel_tol=0)):
        raise ValueError("duration must be positive and a whole number of 0.1 s steps")
    out = Path(out).resolve()
    if not out.is_relative_to(OUTPUT_ROOT.parent.resolve()):
        raise ValueError(f"out must be inside {OUTPUT_ROOT.parent}")
    out.mkdir(parents=True, exist_ok=True)
    net = out / "grid.net.xml"
    shutil.copyfile(grid_net(junctions=5, block=250.0, lanes=2), net)
    routes = out / "routes.rou.xml"
    _write_routes(net, routes, duration, seed)

    cfg = ET.Element("configuration")
    sections = {
        "input": {"net-file": net.name, "route-files": routes.name},
        "time": {"begin": "0", "end": f"{duration:g}", "step-length": f"{step:g}"},
        "random_number": {"seed": str(seed)},
        "processing": {"time-to-teleport": "-1", "eager-insert": "true"},
        "output": {"fcd-output": "fcd.xml", "fcd-output.geo": "false",
                   "summary-output": "summary.xml", "tripinfo-output": "tripinfo.xml"},
        "report": {"no-step-log": "true"},
    }
    # Include the shared smooth lane-change setting in the GUI config too.
    sections["processing"].update(
        (option.removeprefix("--"), value)
        for option, value in zip(LANECHANGE_ARGS[::2], LANECHANGE_ARGS[1::2])
    )
    for name, options in sections.items():
        section = ET.SubElement(cfg, name)
        for option, value in options.items():
            ET.SubElement(section, option, value=value)
    config = out / "scenario.sumocfg"
    _write_xml(cfg, config)
    command = [binary("sumo"), "-c", str(config), *LANECHANGE_ARGS]
    result = subprocess.run(command, cwd=out, capture_output=True, text=True, timeout=120)
    (out / "build.log").write_text(
        "$ " + " ".join(command) + "\n" + result.stdout + result.stderr, encoding="utf-8"
    )
    if result.returncode:
        raise RuntimeError(f"SUMO failed ({result.returncode}); see {out / 'build.log'}\n{result.stderr[-2000:]}")

    population_min, population_max = _population(out / "fcd.xml", duration, step)
    vehicles = fcd_to_ns2.convert(out / "fcd.xml", out, step=step, end_time=duration)
    if vehicles != VEHICLES:
        raise RuntimeError(f"Trace conversion produced {vehicles} vehicles, expected {VEHICLES}")
    rsus = out / "rsus.csv"
    place_rsus.write_csv(
        [(x, y) for y in (50, 500, 950) for x in (50, 500, 950)],
        rsus, range_m=300, first_node_id=VEHICLES,
    )
    meta = {
        "dir": out, "net": net, "trace": out / "trace.ns2", "node_map": out / "node_map.csv",
        "rsus": rsus, "vehicles": vehicles, "duration": duration, "seed": seed,
        "population_min": population_min, "population_max": population_max,
    }
    (out / "scenario.json").write_text(json.dumps(meta, default=str, indent=2) + "\n", encoding="utf-8")
    return meta
