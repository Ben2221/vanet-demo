"""Safety-message (BSM) beaconing at 10 Hz from every vehicle on the road.

The network layer owns the timer and the vehicle's true kinematics. Each tick
it builds the *claimed* state (true state, or a falsified one for attacker
vehicles), and asks the protocol to turn it into bytes with
``app.make_bsm(node, sim_time, state)`` (Person 3 signs it and attaches the
ticket). The BSM goes on air after the signing time,
``node.processing_delay(app.bsm_sign_op)`` (default op "bsm_sign"). Without a
protocol BSM builder a plain unsigned BSM is used.

Congestion control (--congestion-control): every second the vehicle looks at
its own channel busy ratio; above the threshold (0.6) it halves its beacon
rate (down to 1 Hz), below 70 % of the threshold it steps back up.

Attacks for misbehaviour detection (--attacker-ratio / --attack), in the spirit
of VeReMi: const_pos, random_pos, const_speed, random_speed, sudden_stop, flood.
"""

from __future__ import annotations

import math
import random
import struct
from typing import TYPE_CHECKING

from network.backend import BROADCAST

if TYPE_CHECKING:
    from network.hooks import NodeHandle
    from network.scenario import Scenario

BSM_TYPE = 6
ATTACKS = ["const_pos", "random_pos", "const_speed", "random_speed", "sudden_stop", "flood"]

# plain BSM: type, sender name hash, seq, t, x, y, speed, heading, then padding
_PLAIN = struct.Struct("!B8sIdddff")


def plain_bsm(node: "NodeHandle", t: float, state: dict, size: int) -> bytes:
    pid = state.get("pid", node.name).encode()[:8].ljust(8, b"\0")
    body = _PLAIN.pack(BSM_TYPE, pid, state["seq"], t, state["x"], state["y"],
                       state["speed"], state["heading"])
    return body + b"\0" * max(0, size - len(body))


def parse_plain_bsm(data: bytes) -> dict | None:
    if len(data) < _PLAIN.size or data[0] != BSM_TYPE:
        return None
    _, pid, seq, t, x, y, speed, heading = _PLAIN.unpack_from(data)
    return {"pid": pid.rstrip(b"\0").decode(errors="replace"), "seq": seq, "t": t,
            "x": x, "y": y, "speed": speed, "heading": heading}


class Attack:
    """Falsifies the claimed state of one attacker vehicle."""

    def __init__(self, kind: str, rng: random.Random) -> None:
        if kind not in ATTACKS:
            raise ValueError(f"unknown attack {kind}; choose from {ATTACKS}")
        self.kind = kind
        self.rng = rng
        self.offset = (rng.uniform(150, 300) * rng.choice([-1, 1]), rng.uniform(150, 300) * rng.choice([-1, 1]))
        self.speed_offset = rng.uniform(10, 25)

    def apply(self, s: dict) -> dict:
        s = dict(s)
        k = self.kind
        if k == "const_pos":
            s["x"] += self.offset[0]
            s["y"] += self.offset[1]
        elif k == "random_pos":
            s["x"] += self.rng.uniform(-400, 400)
            s["y"] += self.rng.uniform(-400, 400)
        elif k == "const_speed":
            s["speed"] += self.speed_offset
        elif k == "random_speed":
            s["speed"] = self.rng.uniform(0, 50)
        elif k == "sudden_stop":
            s["speed"] = 0.0
        return s

    @property
    def rate_factor(self) -> float:
        return 10.0 if self.kind == "flood" else 1.0


class Beaconer:
    def __init__(self, sc: "Scenario", node: "NodeHandle", rate_hz: float, size: int,
                 congestion_control: bool, cbr_threshold: float, attack: Attack | None) -> None:
        self.sc = sc
        self.node = node
        self.nominal = rate_hz
        self.rate = rate_hz
        self.size = size
        self.cc = congestion_control
        self.cbr_threshold = cbr_threshold
        self.attack = attack
        self.seq = 0
        self.running = False

    def start(self) -> None:
        if self.running or self.nominal <= 0:
            return
        self.running = True
        # random phase so vehicles do not all beacon at the same instant
        self.node.schedule(self.sc.rng.uniform(0, 1.0 / self.nominal), self._tick)
        if self.cc:
            self.node.schedule(1.0, self._adapt)

    def stop(self) -> None:
        self.running = False

    def _state(self, t: float) -> dict:
        x, y = self.node.position()
        vx, vy = self.node.velocity()
        s = {"seq": self.seq, "t": t, "x": x, "y": y, "speed": math.hypot(vx, vy),
             "heading": self.node.heading(), "vx": vx, "vy": vy}
        return self.attack.apply(s) if self.attack else s

    def _tick(self) -> None:
        if not self.running or not self.node.active:
            return
        t = self.node.now()
        state = self._state(t)
        app = self.node.app
        delay = 0.0
        if app is not None and hasattr(app, "make_bsm"):
            data = app.make_bsm(self.node, t, state)
            # signing time before the BSM goes on air (app.bsm_sign_op names the operation)
            delay = self.node.processing_delay(getattr(app, "bsm_sign_op", "bsm_sign"))
        else:
            data = plain_bsm(self.node, t, state, self.size)
        if data:
            self.node.send(BROADCAST, data, delay=delay)
        self.seq += 1
        rate = self.rate * (self.attack.rate_factor if self.attack else 1.0)
        # +-5 % jitter, as real beaconing is not perfectly periodic
        self.node.schedule((1.0 / rate) * self.sc.rng.uniform(0.95, 1.05), self._tick)

    def _adapt(self) -> None:
        if not self.running:
            return
        cbr = self.node.channel_busy_ratio()
        old = self.rate
        if cbr > self.cbr_threshold:
            self.rate = max(1.0, self.rate / 2)
        elif cbr < 0.7 * self.cbr_threshold:
            self.rate = min(self.nominal, self.rate * 2)
        if self.rate != old:
            self.node.log("BEACON_RATE", result=f"{old:g}->{self.rate:g} Hz cbr={cbr:.2f}")
        self.node.schedule(1.0, self._adapt)
