"""Reader for ns-2 mobility files, with the same semantics as ns-3's
Ns2MobilityHelper for the commands our exporter writes:

  $node_(i) set X_ x                          initial position
  $ns_ at t "$node_(i) set X_ x"              jump at time t
  $ns_ at t "$node_(i) setdest x y speed"     move in a straight line, stop on arrival

Used by the lite backend, by tests and by the position check against SUMO.
"""

from __future__ import annotations

import math
import re
from bisect import bisect_right
from pathlib import Path

import numpy as np

_INIT = re.compile(r'^\$node_\((\d+)\)\s+set\s+([XYZ])_\s+(\S+)')
_AT_SET = re.compile(r'^\$ns_\s+at\s+(\S+)\s+"\$node_\((\d+)\)\s+set\s+([XYZ])_\s+(\S+)"')
_AT_DEST = re.compile(r'^\$ns_\s+at\s+(\S+)\s+"\$node_\((\d+)\)\s+setdest\s+(\S+)\s+(\S+)\s+(\S+)"')


class Trajectory:
    """Piecewise-linear motion: knots (t, x, y) with straight lines between them."""

    def __init__(self) -> None:
        self.t: list[float] = []
        self.x: list[float] = []
        self.y: list[float] = []

    def add(self, t: float, x: float, y: float) -> None:
        if self.t and t < self.t[-1]:
            raise ValueError("trajectory knots must be in time order")
        self.t.append(t)
        self.x.append(x)
        self.y.append(y)

    def position(self, t: float) -> tuple[float, float]:
        i = bisect_right(self.t, t) - 1
        if i < 0:
            return self.x[0], self.y[0]
        if i >= len(self.t) - 1:
            return self.x[-1], self.y[-1]
        t0, t1 = self.t[i], self.t[i + 1]
        if t1 <= t0:
            return self.x[i + 1], self.y[i + 1]
        f = (t - t0) / (t1 - t0)
        return self.x[i] + f * (self.x[i + 1] - self.x[i]), self.y[i] + f * (self.y[i + 1] - self.y[i])

    def velocity(self, t: float) -> tuple[float, float]:
        i = bisect_right(self.t, t) - 1
        if i < 0 or i >= len(self.t) - 1:
            return 0.0, 0.0
        dt = self.t[i + 1] - self.t[i]
        if dt <= 0:
            return 0.0, 0.0
        return (self.x[i + 1] - self.x[i]) / dt, (self.y[i + 1] - self.y[i]) / dt


def load(path: str | Path) -> dict[int, Trajectory]:
    init: dict[int, dict[str, float]] = {}
    events: list[tuple[float, int, int, str, tuple]] = []   # (t, order, node, kind, args)
    order = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _AT_DEST.match(line)
            if m:
                t, n, x, y, s = m.groups()
                events.append((float(t), order, int(n), "dest", (float(x), float(y), float(s))))
                order += 1
                continue
            m = _AT_SET.match(line)
            if m:
                t, n, axis, v = m.groups()
                events.append((float(t), order, int(n), "set", (axis, float(v))))
                order += 1
                continue
            m = _INIT.match(line)
            if m:
                n, axis, v = m.groups()
                init.setdefault(int(n), {})[axis] = float(v)
    events.sort(key=lambda e: (e[0], e[1]))

    trajs: dict[int, Trajectory] = {}
    # per node motion state: position at time t_ref and active straight-line move
    state: dict[int, dict] = {}
    for n, xyz in init.items():
        tr = trajs[n] = Trajectory()
        tr.add(0.0, xyz.get("X", 0.0), xyz.get("Y", 0.0))
        state[n] = {"t": 0.0, "x": xyz.get("X", 0.0), "y": xyz.get("Y", 0.0), "move": None}

    def advance(st: dict, tr: Trajectory, t: float) -> None:
        """Bring the node's state forward to time t, adding the arrival knot if passed."""
        mv = st["move"]
        if mv is not None:
            t0, x0, y0, xd, yd, t_arr = mv
            if t >= t_arr:
                st.update(t=t_arr, x=xd, y=yd, move=None)
            else:
                f = (t - t0) / (t_arr - t0)
                st.update(t=t, x=x0 + f * (xd - x0), y=y0 + f * (yd - y0))
                st["move"] = (t, st["x"], st["y"], xd, yd, t_arr)
                return
        st["t"] = t

    for t, _, n, kind, args in events:
        if n not in trajs:
            trajs[n] = Trajectory()
            trajs[n].add(0.0, 0.0, 0.0)
            state[n] = {"t": 0.0, "x": 0.0, "y": 0.0, "move": None}
        tr, st = trajs[n], state[n]
        mv = st["move"]
        if mv is not None and mv[5] <= t:
            tr.add(mv[5], mv[3], mv[4])          # arrived before this event
        advance(st, tr, t)
        if tr.t[-1] < t:
            tr.add(t, st["x"], st["y"])          # hold position until now
        elif tr.t[-1] == t:
            tr.x[-1], tr.y[-1] = st["x"], st["y"]
        if kind == "set":
            axis, v = args
            if axis == "X":
                st["x"] = v
            elif axis == "Y":
                st["y"] = v
            st["move"] = None
            tr.add(t, st["x"], st["y"])          # zero-length segment = jump
        else:
            xd, yd, speed = args
            dist = math.hypot(xd - st["x"], yd - st["y"])
            if speed <= 0 or dist < 1e-9:
                st["move"] = None
                continue
            st["move"] = (t, st["x"], st["y"], xd, yd, t + dist / speed)
    for n, st in state.items():
        mv = st["move"]
        if mv is not None:
            trajs[n].add(mv[5], mv[3], mv[4])
    return trajs


MAX_SPEED = 100.0      # m/s; a faster move between two grid samples is a jump, not driving


class PositionTable:
    """All node positions sampled on a fixed grid, for fast vectorised lookups."""

    def __init__(self, trajs: dict[int, Trajectory], n_nodes: int, end: float, dt: float = 0.1,
                 static: dict[int, tuple[float, float]] | None = None) -> None:
        self.dt = dt
        steps = int(math.ceil(end / dt)) + 2
        self.pos = np.zeros((steps, n_nodes, 2))
        times = np.arange(steps) * dt
        for n in range(n_nodes):
            if static and n in static:
                self.pos[:, n, :] = static[n]
            elif n in trajs:
                tr = trajs[n]
                self.pos[:, n, 0] = np.interp(times, tr.t, tr.x)
                self.pos[:, n, 1] = np.interp(times, tr.t, tr.y)

    def at(self, t: float) -> np.ndarray:
        f = t / self.dt
        i = int(f)
        if i >= len(self.pos) - 1:
            return self.pos[-1]
        a = f - i
        step = self.pos[i + 1] - self.pos[i]
        # a jump (entering from / leaving to the parking spot) happens at a knot, i.e. at the
        # end of this grid step: hold the old position instead of sliding across the map
        jump = np.hypot(step[:, 0], step[:, 1]) > MAX_SPEED * self.dt
        step[jump] = 0.0
        return self.pos[i] + a * step
