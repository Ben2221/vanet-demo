"""Node positions for the scenario: vehicles from the ns-2 file, RSUs fixed."""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np

from network import ns2_mobility


class ScenarioMobility:
    def __init__(self, trace: Path | None, n_vehicles: int, rsu_positions: list[tuple[float, float]],
                 end: float, grid_dt: float = 0.1) -> None:
        self.n_vehicles = n_vehicles
        self.n_nodes = n_vehicles + len(rsu_positions)
        self.trajs = ns2_mobility.load(trace) if trace is not None else {}
        self.static = {n_vehicles + i: p for i, p in enumerate(rsu_positions)}
        self.table = ns2_mobility.PositionTable(self.trajs, self.n_nodes, end, grid_dt, self.static)

    def add_static(self, node: int, pos: tuple[float, float]) -> None:
        self.static[node] = pos
        self.table.pos[:, node, :] = pos

    def position(self, node: int, t: float) -> tuple[float, float]:
        if node in self.static:
            return self.static[node]
        tr = self.trajs.get(node)
        return tr.position(t) if tr else (0.0, 0.0)

    def velocity(self, node: int, t: float) -> tuple[float, float]:
        if node in self.static:
            return 0.0, 0.0
        tr = self.trajs.get(node)
        return tr.velocity(t) if tr else (0.0, 0.0)

    def positions_at(self, t: float) -> np.ndarray:
        return self.table.at(t)


def heading_deg(vx: float, vy: float) -> float:
    """Compass-style heading: 0 = north (+y), 90 = east (+x), like SUMO's angle."""
    if vx == 0 and vy == 0:
        return 0.0
    return math.degrees(math.atan2(vx, vy)) % 360.0
