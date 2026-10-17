"""What the scenario needs from a network simulator.

Two implementations:
  backend_ns3.Ns3Backend    the real thing: ns-3 802.11p through its Python bindings
  backend_lite.LiteBackend  a small pure-Python 802.11p model with the same radio
                            parameters, for machines without ns-3 (e.g. Windows)
                            and for fast unit tests
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

BROADCAST = -1

# user priorities (802.1D) -> EDCA access category, as ns-3's QosUtilsMapTidToAc
PRIORITY_AC = {0: "AC_BE", 3: "AC_BE", 1: "AC_BK", 2: "AC_BK", 4: "AC_VI", 5: "AC_VI", 6: "AC_VO", 7: "AC_VO"}

# RxHandler(receiver_node, sender_node, payload, packet_uid, rx_time_s)
RxHandler = Callable[[int, int, bytes, int, float], None]


class Backend(ABC):
    name = "abstract"

    @abstractmethod
    def now(self) -> float: ...

    @abstractmethod
    def schedule(self, delay: float, fn: Callable[[], None]) -> None:
        """Run fn after delay seconds of simulated time."""

    @abstractmethod
    def send(self, src: int, dst: int, payload: bytes, priority: int = 0) -> int:
        """Send a UDP datagram (dst = node id or BROADCAST). Returns the packet uid."""

    @abstractmethod
    def set_rx_handler(self, handler: RxHandler) -> None: ...

    @abstractmethod
    def position(self, node: int) -> tuple[float, float]: ...

    @abstractmethod
    def velocity(self, node: int) -> tuple[float, float]: ...

    @abstractmethod
    def nodes_in_range(self, node: int, radius: float) -> list[tuple[int, float]]:
        """(node id, distance) of every other node within radius metres, now."""

    @abstractmethod
    def busy_time(self, node: int) -> float:
        """Cumulative time (s) node's PHY has seen the channel busy (TX, RX or CCA busy)."""

    @abstractmethod
    def run(self, until: float) -> None: ...

    def finish(self, out_dir) -> dict:
        """Write backend-specific outputs (FlowMonitor etc.); return summary stats."""
        return {}
