"""Place RSUs along roads on a regular grid.

A grid with the given spacing is laid over the network's bounding box. Each
grid point is snapped to the closest point on a road; points with no road
within half the spacing are dropped, and snapped points that end up closer
than half the spacing to an earlier RSU are merged.

Output: rsus.csv with columns rsu_id,node_id,x,y,range_m
(node_id = number of vehicles + index, because vehicles take ns-3 node ids
0..N-1 from the ns-2 mobility file).
"""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path

from mobility.sumo_env import add_tools_to_path


def place(net_file: Path, spacing: float,
          bounds: tuple[float, float, float, float] | None = None) -> list[tuple[float, float]]:
    """``bounds`` (xmin, ymin, xmax, ymax) limits the grid to part of the network
    (a box cut from a city scenario); default: the whole network."""
    add_tools_to_path()
    import sumolib
    from sumolib import geomhelper

    net = sumolib.net.readNet(str(net_file))
    xmin, ymin, xmax, ymax = bounds or net.getBoundary()
    nx = max(1, int(math.floor((xmax - xmin) / spacing)) + 1)
    ny = max(1, int(math.floor((ymax - ymin) / spacing)) + 1)
    # centre the grid on the map
    x0 = xmin + ((xmax - xmin) - (nx - 1) * spacing) / 2
    y0 = ymin + ((ymax - ymin) - (ny - 1) * spacing) / 2

    placed: list[tuple[float, float]] = []
    for j in range(ny):
        for i in range(nx):
            gx, gy = x0 + i * spacing, y0 + j * spacing
            lanes = net.getNeighboringLanes(gx, gy, spacing / 2)
            if not lanes:
                continue
            best = None
            for lane, _ in lanes:
                if not lane.allows("passenger"):
                    continue
                shape = lane.getShape()
                off = geomhelper.polygonOffsetWithMinimumDistanceToPoint((gx, gy), shape)
                px, py = geomhelper.positionAtShapeOffset(shape, off)
                d = math.hypot(px - gx, py - gy)
                if best is None or d < best[0]:
                    best = (d, px, py)
            if best is None:
                continue
            _, px, py = best
            if all(math.hypot(px - qx, py - qy) >= spacing / 2 for qx, qy in placed):
                placed.append((px, py))
    return placed


def write_csv(points: list[tuple[float, float]], out: Path, range_m: float, first_node_id: int) -> None:
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rsu_id", "node_id", "x", "y", "range_m"])
        for i, (x, y) in enumerate(points):
            w.writerow([f"rsu{i}", first_node_id + i, f"{x:.2f}", f"{y:.2f}", f"{range_m:.0f}"])


def read_csv(path: Path) -> list[dict]:
    with path.open() as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["node_id"] = int(r["node_id"])
        r["x"] = float(r["x"])
        r["y"] = float(r["y"])
        r["range_m"] = float(r["range_m"])
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("net", type=Path, help="SUMO .net.xml")
    ap.add_argument("out", type=Path, help="output rsus.csv")
    ap.add_argument("--spacing", type=float, default=450.0)
    ap.add_argument("--range", type=float, default=300.0, help="nominal RSU service range in m")
    ap.add_argument("--first-node-id", type=int, default=0, help="usually the number of vehicles")
    a = ap.parse_args()
    pts = place(a.net, a.spacing)
    write_csv(pts, a.out, a.range, a.first_node_id)
    print(f"placed {len(pts)} RSUs -> {a.out}")


if __name__ == "__main__":
    main()
