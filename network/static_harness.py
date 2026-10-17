"""Static-node experiments on either backend (range test, density test).

Groups of nodes are placed 20 km apart so that they cannot hear each other;
that lets one simulation run hold every case of a sweep.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from network.backend import BROADCAST, Backend
from network.radio import RadioConfig

GROUP_SPACING = 20_000.0


def make_backend(kind: str, positions: list[tuple[float, float]], radio: RadioConfig,
                 duration: float, seed: int = 1) -> Backend:
    if kind == "auto":
        try:
            from ns import ns  # noqa: F401
            kind = "ns3"
        except ImportError:
            kind = "lite"
    if kind == "ns3":
        from network.backend_ns3 import Ns3Backend
        return Ns3Backend(None, 0, positions, radio, seed=seed, flowmon=False)
    from network.backend_lite import LiteBackend
    from network.mobility_model import ScenarioMobility
    return LiteBackend(ScenarioMobility(None, 0, positions, duration + 1), radio, seed=seed)


@dataclass
class Broadcaster:
    node: int
    rate_hz: float
    size: int
    start: float
    count: int


@dataclass
class Result:
    sent: dict[int, int] = field(default_factory=lambda: defaultdict(int))        # uid -> sender
    received: dict[int, set] = field(default_factory=lambda: defaultdict(set))    # uid -> receivers
    sent_at: dict[int, float] = field(default_factory=dict)
    delays_ms: list[float] = field(default_factory=list)
    rx_delay: dict[tuple[int, int], float] = field(default_factory=dict)


def run(backend: Backend, broadcasters: list[Broadcaster], duration: float, jitter_seed: int = 1) -> Result:
    import random

    rng = random.Random(jitter_seed)
    res = Result()

    def on_rx(node, src, data, uid, t):
        if uid in res.sent_at and node not in res.received[uid]:
            res.received[uid].add(node)
            d = (t - res.sent_at[uid]) * 1000
            res.delays_ms.append(d)
            res.rx_delay[(uid, node)] = d

    backend.set_rx_handler(on_rx)

    def start(b: Broadcaster):
        left = [b.count]

        def tick():
            if left[0] <= 0:
                return
            left[0] -= 1
            uid = backend.send(b.node, BROADCAST, bytes([6]) + bytes(b.size - 1), 6)
            res.sent[uid] = b.node
            res.sent_at[uid] = backend.now()
            backend.schedule((1.0 / b.rate_hz) * rng.uniform(0.95, 1.05), tick)

        backend.schedule(b.start, tick)

    for b in broadcasters:
        start(b)
    backend.run(duration)
    return res
