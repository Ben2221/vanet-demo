"""Echo protocol: the first app-layer test (plan step 5).

RSUs broadcast a beacon every 100 ms. A vehicle that hears a beacon answers
with a unicast ECHO back to that RSU at most once per second; the RSU logs
the round-trip time. No security at all.
"""

from __future__ import annotations

import struct

from network.hooks import BROADCAST

BEACON, ECHO = 1, 8
_HDR = struct.Struct("!BHd")       # type, rsu index, beacon send time
BEACON_SIZE = 100
ECHO_SIZE = 100


def message_type(data: bytes) -> str:
    return {BEACON: "BEACON", ECHO: "ECHO", 6: "BSM"}.get(data[0], f"T{data[0]}")


class Rsu:
    def __init__(self, node, env) -> None:
        self.index = int(node.name.removeprefix("rsu"))

    def on_start(self, node) -> None:
        node.schedule(node.env.rng.uniform(0, 0.1), self._beacon, node)

    def _beacon(self, node) -> None:
        data = _HDR.pack(BEACON, self.index, node.now())
        node.send(BROADCAST, data.ljust(BEACON_SIZE, b"\0"))
        node.schedule(0.1, self._beacon, node)

    def on_receive(self, node, data: bytes, sim_time: float) -> None:
        if data[0] == ECHO:
            _, idx, t_sent = _HDR.unpack_from(data)
            if idx == self.index:
                node.log("ECHO_RTT", len(data), (sim_time - t_sent) * 1000, f"from node {node.last_sender}")


class Vehicle:
    def __init__(self, node, env) -> None:
        self.last_echo: dict[int, float] = {}

    def on_receive(self, node, data: bytes, sim_time: float) -> None:
        if data[0] != BEACON:
            return
        _, idx, t_sent = _HDR.unpack_from(data)
        if sim_time - self.last_echo.get(idx, -1e9) >= 1.0:
            self.last_echo[idx] = sim_time
            node.send(node.last_sender, _HDR.pack(ECHO, idx, t_sent).ljust(ECHO_SIZE, b"\0"))


def create_vehicle(node, env):
    return Vehicle(node, env)


def create_rsu(node, env):
    return Rsu(node, env)
