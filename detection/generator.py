"""Labelled BSM streams for honest vehicles and attackers (Person 4).

Everything one RSU at (0, 0) would hear: vehicles drive on a street grid around
it, send BSMs at 10 Hz with some packet loss, and attackers start lying at
``attack_start``. Output messages use the same dict format as interface 5, plus
ground truth:

    label    0 honest message, 1 attack message
    ambiguous  True for the own (truthful) messages of a flood / replay / sybil
             attacker while it attacks: the sender is misbehaving, so flagging
             them is not counted as a false positive
    attack   "honest" or the attack name
    vehicle  the real sender (used to split train/test by vehicle)
    pid_owner  the vehicle the pseudonym really belongs to (differs from ``vehicle``
             for replayed copies)

Attacks: const_pos, random_pos, const_speed, random_speed, sudden_stop, replay,
flood, sybil. The first six mirror network/bsm.py and VeReMi.

Results on this generator are optimistic: it is simpler than real traffic. The
real VeReMi / NextGen test split is the one that counts (detection/loaders.py).
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

ATTACKS = ["const_pos", "random_pos", "const_speed", "random_speed", "sudden_stop",
           "replay", "flood", "sybil"]
BEACON_HZ = 10.0
RANGE = 400.0


@dataclass
class _Truth:
    x: float
    y: float
    vx: float
    vy: float


def _drive(rng: random.Random, duration: float, dt: float = 0.1) -> list[_Truth]:
    """True trajectory on a street grid, bounded around the RSU, 90 degree corners."""
    x, y = rng.uniform(-250, 250), rng.uniform(-250, 250)
    heading = rng.choice([(1, 0), (-1, 0), (0, 1), (0, -1)])
    v = rng.uniform(8, 18)
    out = []
    for _ in range(int(duration / dt)):
        hx, hy = heading
        outward = (x > 330 and hx > 0) or (x < -330 and hx < 0) or (y > 330 and hy > 0) or (y < -330 and hy < 0)
        if outward:                                                # turn 90 degrees toward the middle
            heading = (0, -1 if y > 0 else 1) if hx else (-1 if x > 0 else 1, 0)
        elif rng.random() < 0.004:                                 # random corner
            heading = rng.choice([(-hy, hx), (hy, -hx)])
        v = min(20.0, max(0.5, v + rng.uniform(-1.5, 1.5) * dt))
        x += heading[0] * v * dt
        y += heading[1] * v * dt
        out.append(_Truth(x, y, heading[0] * v, heading[1] * v))
    return out


def _state(tr: _Truth, seq: int, t: float) -> dict:
    return {"seq": seq, "t": t, "x": tr.x, "y": tr.y, "speed": math.hypot(tr.vx, tr.vy),
            "heading": math.degrees(math.atan2(tr.vx, tr.vy)) % 360.0}


def _msg(pid: str, st: dict, sender: int, vehicle: str, attack: str, rx: float) -> dict:
    return {"pid": pid, **st, "rsu_x": 0.0, "rsu_y": 0.0, "rx_time": rx, "sender": sender,
            "label": 0 if attack == "honest" else 1, "attack": attack, "vehicle": vehicle,
            "ambiguous": False, "pid_owner": vehicle}


def generate(n_vehicles: int = 60, attacker_ratio: float = 0.2, duration: float = 120.0,
             attack_start: float = 30.0, attacks: list[str] | None = None,
             loss: float = 0.1, seed: int = 1) -> list[dict]:
    """Stream sorted by reception time. Attack types are spread over the attackers."""
    rng = random.Random(seed)
    attacks = attacks or ATTACKS
    n_att = max(1, round(attacker_ratio * n_vehicles)) if attacker_ratio > 0 else 0
    kinds = {i: attacks[i % len(attacks)] for i in range(n_att)}
    tracks = [_drive(rng, duration) for _ in range(n_vehicles)]
    offsets = {i: (rng.uniform(150, 300) * rng.choice([-1, 1]), rng.uniform(150, 300) * rng.choice([-1, 1]))
               for i in kinds}
    spd_off = {i: rng.uniform(10, 25) for i in kinds}
    pids = [f"p{i:04d}" for i in range(n_vehicles)]
    log: list[dict] = []
    heard: list[dict] = []          # honest messages, for replay
    seqs = [0] * n_vehicles

    def send(m: dict, tr: _Truth) -> None:
        if rng.random() >= loss and math.hypot(tr.x, tr.y) < RANGE:
            log.append(m)

    steps = int(duration / 0.1)
    for k in range(steps):
        now = k * 0.1
        for i in range(n_vehicles):
            tr = tracks[i][k]
            kind = kinds.get(i)
            active = kind is not None and now >= attack_start
            if k % int(round(1 / (BEACON_HZ * 0.1))) != 0:
                continue
            jitter = rng.uniform(-0.005, 0.005)
            t = now + jitter
            st = _state(tr, seqs[i], t)
            seqs[i] += 1
            vehicle = f"veh{i}"
            if not active or kind in ("replay", "flood", "sybil"):
                m = _msg(pids[i], st, i, vehicle, "honest", t)
                m["ambiguous"] = active          # own messages of an active flood/replay/sybil attacker
                send(m, tr)
                if len(heard) < 3000 and rng.random() < 0.05:
                    heard.append(m)
            if not active:
                continue
            a = dict(st)
            if kind == "const_pos":
                a["x"] += offsets[i][0]
                a["y"] += offsets[i][1]
            elif kind == "random_pos":
                a["x"] += rng.uniform(-400, 400)
                a["y"] += rng.uniform(-400, 400)
            elif kind == "const_speed":
                a["speed"] += spd_off[i]
            elif kind == "random_speed":
                a["speed"] = rng.uniform(0, 50)
            elif kind == "sudden_stop":
                a["speed"] = 0.0
            if kind in ("const_pos", "random_pos", "const_speed", "random_speed", "sudden_stop"):
                send(_msg(pids[i], a, i, vehicle, kind, t), tr)
            elif kind == "flood":
                for j in range(1, 10):               # ten times the normal rate
                    fl = _state(tracks[i][min(k, steps - 1)], seqs[i], t + 0.01 * j)
                    seqs[i] += 1
                    send(_msg(pids[i], fl, i, vehicle, "flood", t + 0.01 * j), tr)
            elif kind == "replay" and heard:
                old = rng.choice([h for h in heard if h["vehicle"] != vehicle and h["t"] < t - 1.0] or heard)
                r = dict(old)
                r.update({"rx_time": t, "sender": i, "label": 1, "attack": "replay", "vehicle": vehicle,
                          "pid_owner": old["pid_owner"]})
                send(r, tr)
            elif kind == "sybil":
                for g in range(2):                    # two ghost vehicles near the attacker
                    shift = (g + 1) * 40.0 * (1 if g % 2 == 0 else -1)
                    ghost = _Truth(tr.x + shift, tr.y - shift * 0.5, tr.vx, tr.vy)
                    gs = _state(ghost, seqs[i] + 1000 * (g + 1), t)
                    send(_msg(f"g{i:04d}_{g}", gs, i, vehicle, "sybil", t), tr)
    log.sort(key=lambda m: m["rx_time"])
    return log
