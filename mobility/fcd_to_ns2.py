"""Convert SUMO floating-car data (FCD) to an ns-2 mobility file for ns-3.

Why not only traceExporter.py? SUMO's ``traceExporter.py --ns2mobility-output``
leaves a vehicle at its first position before it departs and at its last
position after it arrives, so "ghost" cars sit on the road and take part in
the radio channel. This converter writes the same ns-2 format that ns-3's
``Ns2MobilityHelper`` reads, but parks every vehicle 3 km outside the map
while it is not on the road.

Output:
  trace.ns2      ns-2 mobility file (node ids 0..N-1)
  node_map.csv   sumo_id,node_id,first_seen,last_seen
"""

from __future__ import annotations

import argparse
import csv
import math
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# Parked nodes wait at one point 3 km outside the map. SUMO network
# coordinates are never negative, so this is far beyond radio range (~400 m)
# of every road; parked nodes send nothing, so sharing a spot is harmless, and
# NetAnim's view stays close to the map.
PARK_X = -3_000.0
PARK_Y = -3_000.0


def park_position(node_id: int) -> tuple[float, float]:
    return PARK_X, PARK_Y


@dataclass
class Track:
    sumo_id: str
    samples: list[tuple[float, float, float, float, float]] = field(default_factory=list)
    # (time, x, y, speed, angle)


def read_fcd(fcd_path: Path, end_time: float | None = None) -> dict[str, Track]:
    tracks: dict[str, Track] = {}
    for _, elem in ET.iterparse(fcd_path, events=("end",)):
        if elem.tag != "timestep":
            continue
        t = float(elem.get("time"))
        if end_time is not None and t > end_time:
            elem.clear()
            break
        for veh in elem.findall("vehicle"):
            vid = veh.get("id")
            tr = tracks.get(vid)
            if tr is None:
                tr = tracks[vid] = Track(vid)
            tr.samples.append(
                (t, float(veh.get("x")), float(veh.get("y")),
                 float(veh.get("speed", 0.0)), float(veh.get("angle", 0.0)))
            )
        elem.clear()
    return tracks


def ordered_tracks(tracks: dict[str, Track]) -> list[Track]:
    """Node ids follow departure order, ties broken by SUMO id."""
    return sorted(tracks.values(), key=lambda tr: (tr.samples[0][0], tr.sumo_id))


def write_ns2(tracks: list[Track], out_path: Path, step: float) -> None:
    lines: list[str] = []
    for nid, tr in enumerate(tracks):
        px, py = park_position(nid)
        lines.append(f"$node_({nid}) set X_ {px:.2f}")
        lines.append(f"$node_({nid}) set Y_ {py:.2f}")
        lines.append(f"$node_({nid}) set Z_ 0.0")
    for nid, tr in enumerate(tracks):
        s = tr.samples
        t0, x0, y0 = s[0][0], s[0][1], s[0][2]
        # enter the map: teleport from the parking spot
        lines.append(f'$ns_ at {t0:.2f} "$node_({nid}) set X_ {x0:.2f}"')
        lines.append(f'$ns_ at {t0:.2f} "$node_({nid}) set Y_ {y0:.2f}"')
        for (ta, xa, ya, _, _), (tb, xb, yb, _, _) in zip(s, s[1:]):
            dist = math.hypot(xb - xa, yb - ya)
            dt = tb - ta
            if dist < 1e-3 or dt <= 0:
                continue  # standing still: the previous setdest already stopped the node
            if dt > step * 1.5:
                # gap in the trace (should not happen): jump instead of crawling
                lines.append(f'$ns_ at {tb:.2f} "$node_({nid}) set X_ {xb:.2f}"')
                lines.append(f'$ns_ at {tb:.2f} "$node_({nid}) set Y_ {yb:.2f}"')
                continue
            lines.append(
                f'$ns_ at {ta:.2f} "$node_({nid}) setdest {xb:.2f} {yb:.2f} {dist / dt:.3f}"'
            )
        # leave the map one step after the last sample: back to the parking spot
        t_out = s[-1][0] + step
        px, py = park_position(nid)
        lines.append(f'$ns_ at {t_out:.2f} "$node_({nid}) set X_ {px:.2f}"')
        lines.append(f'$ns_ at {t_out:.2f} "$node_({nid}) set Y_ {py:.2f}"')
    out_path.write_text("\n".join(lines) + "\n", encoding="ascii")


def write_node_map(tracks: list[Track], out_path: Path, step: float) -> None:
    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sumo_id", "node_id", "first_seen", "last_seen"])
        for nid, tr in enumerate(tracks):
            # last_seen is when the node leaves the map (one step after the last sample)
            w.writerow([tr.sumo_id, nid, f"{tr.samples[0][0]:.2f}", f"{tr.samples[-1][0] + step:.2f}"])


def convert(fcd_path: Path, out_dir: Path, step: float = 1.0,
            end_time: float | None = None, max_vehicles: int | None = None) -> int:
    tracks = ordered_tracks(read_fcd(fcd_path, end_time))
    if max_vehicles is not None:
        tracks = tracks[:max_vehicles]
    out_dir.mkdir(parents=True, exist_ok=True)
    write_ns2(tracks, out_dir / "trace.ns2", step)
    write_node_map(tracks, out_dir / "node_map.csv", step)
    return len(tracks)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fcd", type=Path, help="SUMO --fcd-output file")
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--step", type=float, default=1.0, help="FCD sampling period in s (default 1)")
    ap.add_argument("--end", type=float, default=None, help="ignore FCD after this time")
    ap.add_argument("--max-vehicles", type=int, default=None)
    a = ap.parse_args()
    n = convert(a.fcd, a.out_dir, a.step, a.end, a.max_vehicles)
    print(f"wrote {n} vehicles to {a.out_dir}")


if __name__ == "__main__":
    main()
