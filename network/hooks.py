"""Node hooks (interface 3): the only way protocol code touches the network.

ns-3 (or the lite backend) calls the protocol's

    on_receive(node, data, sim_time)

and protocol code calls

    send(node, destination, data)        # destination: BROADCAST or a node id
    schedule(delay, callback)

Both are available as module functions (as agreed in docs/interfaces.md) and as
methods on the NodeHandle passed to the protocol. Protocol code never imports
ns-3.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Callable

from network.backend import BROADCAST
from network.mobility_model import heading_deg

if TYPE_CHECKING:
    from network.ledger_bridge import LedgerView
    from network.scenario import Scenario

__all__ = ["BROADCAST", "NodeHandle", "send", "schedule", "now"]

_current: "Scenario | None" = None


def _bind(scenario: "Scenario | None") -> None:
    global _current
    _current = scenario


def send(node: "NodeHandle", destination: int, data: bytes) -> None:
    node.send(destination, data)


def schedule(delay: float, callback: Callable, *args) -> None:
    if _current is None:
        raise RuntimeError("no scenario is running")
    _current.backend.schedule(delay, (lambda: callback(*args)) if args else callback)


def now() -> float:
    if _current is None:
        raise RuntimeError("no scenario is running")
    return _current.backend.now()


class NodeHandle:
    """One vehicle or RSU, as seen by protocol code.

    Attributes:
      id          ns-3 node id (also the network address used by send)
      name        SUMO vehicle id ("veh12") or RSU id ("rsu3")
      kind        "vehicle" or "rsu"
      ledger      LedgerView for RSUs (instant reads, async writes); None for vehicles
      detector    Person 4's check(bsm, history) or None
      is_attacker True for vehicles chosen as attackers (--attacker-ratio)
      last_sender node id of the sender of the message being handled; valid only
                  inside on_receive (read it there, or take on_receive's src argument,
                  before scheduling anything that replies later)
      env         the ScenarioEnv shared by all nodes
    """

    def __init__(self, scenario: "Scenario", node_id: int, name: str, kind: str) -> None:
        self._sc = scenario
        self.id = node_id
        self.name = name
        self.kind = kind
        self.ledger: "LedgerView | None" = None
        self.detector = None
        self.is_attacker = False
        self.last_sender: int | None = None
        self.app = None              # the protocol object for this node
        self.active = kind == "rsu"  # vehicles are active while on the road
        self.first_seen = 0.0
        self.last_seen = math.inf

    @property
    def env(self):
        return self._sc.env

    def __repr__(self) -> str:
        return f"<{self.kind} {self.name} node={self.id}>"

    # -------------------------------------------------------------- the hooks
    def send(self, destination: int | str, data: bytes, delay: float = 0.0) -> None:
        """Send bytes to a node id / RSU name, or BROADCAST. delay = processing time."""
        if isinstance(destination, str):
            destination = self._sc.node_by_name[destination].id
        if delay > 0:
            self._sc.backend.schedule(delay, lambda: self._sc.send(self, destination, data))
        else:
            self._sc.send(self, destination, data)

    def backbone_send(self, destination: int | str, data: bytes, delay: float = 0.0) -> None:
        """RSU only: send bytes to another RSU over the wired backbone (not the radio).
        Arrives at the destination's on_receive after delay + --backbone-ms."""
        if self.kind != "rsu":
            raise RuntimeError("only RSUs are on the backbone")
        if isinstance(destination, str):
            destination = self._sc.node_by_name[destination].id
        self._sc.backbone_send(self, destination, data, delay)

    def schedule(self, delay: float, callback: Callable, *args) -> None:
        self._sc.backend.schedule(delay, (lambda: callback(*args)) if args else callback)

    def now(self) -> float:
        return self._sc.backend.now()

    # -------------------------------------------------------------- helpers
    def position(self) -> tuple[float, float]:
        return self._sc.backend.position(self.id)

    def velocity(self) -> tuple[float, float]:
        return self._sc.backend.velocity(self.id)

    def speed(self) -> float:
        return math.hypot(*self.velocity())

    def heading(self) -> float:
        return heading_deg(*self.velocity())

    def nearby_rsus(self, radius: float | None = None) -> list[tuple["NodeHandle", float]]:
        """RSUs within radius (default: their service range), closest first.

        For make-before-break handover: start authenticating with the next RSU
        while the current one still covers the vehicle."""
        x, y = self.position()
        out = []
        for rsu in self._sc.rsus:
            rx, ry = self._sc.rsu_pos[rsu.id]
            d = math.hypot(rx - x, ry - y)
            if d <= (radius if radius is not None else self._sc.rsu_range[rsu.id]):
                out.append((rsu, d))
        out.sort(key=lambda p: p[1])
        return out

    def processing_delay(self, op: str) -> float:
        """Seconds of compute for an operation ('prove', 'verify', 'sign', ...),
        from --compute-times (Person 3's measurements). 0 if unknown."""
        return self._sc.compute_times.get(op, 0.0)

    def log(self, event: str, nbytes: int = 0, latency_ms: float | None = None, result: str = "") -> None:
        """Write one row to the shared metrics CSV."""
        self._sc.metrics.log(self.now(), self.name, event, nbytes, latency_ms, result)

    def channel_busy_ratio(self) -> float:
        return self._sc.cbr.get(self.id, 0.0)
