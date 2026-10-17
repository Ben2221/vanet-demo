"""Live SUMO coupling through TraCI (instead of the exported ns-2 trace).

SUMO runs alongside the network simulator and is stepped every --traci-step
seconds of simulated time. After each step every vehicle's position and
velocity are read and handed to the network backend; between steps a vehicle
moves in a straight line with its last velocity, as in ns-3's
ConstantVelocityMobilityModel. Vehicles not on the road are parked far away,
exactly as in the exported trace.

Vehicle node ids come from node_map.csv of the same scenario, so a TraCI run and
a trace run of one scenario use the same ids.
"""

from __future__ import annotations

import math

import numpy as np

from mobility.fcd_to_ns2 import park_position
from mobility.sumo_env import add_tools_to_path, binary


class TraciMobility:
    def __init__(self, sumocfg, node_of: dict[str, int], n_vehicles: int,
                 rsu_positions: list[tuple[float, float]], step: float = 1.0, seed: int = 1) -> None:
        add_tools_to_path()
        import traci

        self.traci = traci
        self.node_of = node_of
        self.n_vehicles = n_vehicles
        self.n_nodes = n_vehicles + len(rsu_positions)
        self.step = step
        self.static = {n_vehicles + i: p for i, p in enumerate(rsu_positions)}
        self.pos = np.zeros((self.n_nodes, 2))
        self.vel = np.zeros((self.n_nodes, 2))
        for n in range(n_vehicles):
            self.pos[n] = park_position(n)
        for n, p in self.static.items():
            self.pos[n] = p
        self.t_ref = -step            # time of the state we hold (none yet)
        self.on_road: set[int] = set()
        self.listeners = []           # fn(node, x, y, vx, vy) after each step (ns-3 backend)
        traci.start([binary("sumo"), "-c", str(sumocfg), "--step-length", str(step),
                     "--seed", str(seed), "--no-step-log", "true", "--no-warnings", "true"])
        self.advance(0.0)

    def _read(self) -> None:
        tc = self.traci
        seen = set()
        for vid in tc.vehicle.getIDList():
            n = self.node_of.get(vid)
            if n is None:
                continue
            x, y = tc.vehicle.getPosition(vid)
            speed = tc.vehicle.getSpeed(vid)
            ang = math.radians(tc.vehicle.getAngle(vid))      # 0 = north, clockwise
            self.pos[n] = (x, y)
            self.vel[n] = (speed * math.sin(ang), speed * math.cos(ang))
            seen.add(n)
        for n in self.on_road - seen:                        # left the map: park
            self.pos[n] = park_position(n)
            self.vel[n] = (0.0, 0.0)
        self.on_road = seen
        for fn in self.listeners:
            for n in range(self.n_vehicles):
                fn(n, *self.pos[n], *self.vel[n])

    def advance(self, t: float) -> None:
        """Step SUMO up to simulated time t."""
        while self.t_ref + self.step <= t + 1e-9:
            self.traci.simulationStep()
            # after a step, getTime() is the time of the NEXT step; the state we
            # read is the one SUMO's FCD output reports for the step just done
            self.t_ref = self.traci.simulation.getTime() - self.step
            self._read()

    def close(self) -> None:
        try:
            self.traci.close()
        except Exception:
            pass

    # same interface as ScenarioMobility
    def position(self, node: int, t: float) -> tuple[float, float]:
        dt = max(0.0, t - self.t_ref)
        return (float(self.pos[node, 0] + self.vel[node, 0] * dt),
                float(self.pos[node, 1] + self.vel[node, 1] * dt))

    def velocity(self, node: int, t: float) -> tuple[float, float]:
        return float(self.vel[node, 0]), float(self.vel[node, 1])

    def positions_at(self, t: float) -> np.ndarray:
        return self.pos + self.vel * max(0.0, t - self.t_ref)
