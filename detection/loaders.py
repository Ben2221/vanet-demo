"""One loader for VeReMi, VeReMi Extension and VeReMi NextGen (Person 4).

Every source is turned into the same message dicts as the generator:

    pid, seq, t, x, y, speed, heading, rsu_x, rsu_y, rx_time, sender,
    label (0/1), attack ("honest" or the attack name), vehicle (true sender)

so ``detection.evaluate.run_detector`` works on all of them. In the datasets a
receiving *vehicle* plays the role of the RSU: ``rsu_x/rsu_y`` is the
receiver's own position when the message arrived.

!! Field names ---------------------------------------------------------------
VeReMi (classic) JSON-lines logs are handled from the published format:
type 2 = own GPS, type 3 = received BSM with sendTime, rcvTime, sender,
senderPseudo, messageID, pos, spd, hed, and groundtruth with attackerType.
VeReMi Extension (CSV) and VeReMi NextGen could not be checked against their
documentation while this was written, so column names are matched by a list of
aliases (ALIASES below). If a field is not found the loader raises an error
that names the columns it did see; add the real name to ALIASES. Do this once
you have the files, then run ``python -m detection.loaders --inspect <file>``.
Ground truth of NextGen (groundTruth.json) is a mapping you can pass with
``vehicle_attack={vehicle_id: attack_name}`` if the message records themselves
carry no label.
"""

from __future__ import annotations

import csv
import json
import math
from pathlib import Path
from typing import Iterable, Iterator

# attack-name normalisation: VeReMi numbers and NextGen names -> our names
VEREMI_TYPES = {0: "honest", 1: "const_pos", 2: "const_pos_offset", 4: "random_pos",
                8: "random_pos_offset", 16: "eventual_stop"}
NAME_MAP = {
    "constantpositionoffset": "const_pos", "constantposition": "const_pos",
    "randompositionoffset": "random_pos", "randomposition": "random_pos",
    "constantspeedoffset": "const_speed", "randomspeedoffset": "random_speed",
    "suddenstop": "sudden_stop", "eventualstop": "sudden_stop",
    "datareplay": "replay", "dosattack": "flood", "dos": "flood",
    "trafficcongestionsybil": "sybil", "datareplaysybil": "sybil", "dossybil": "sybil",
    "accelerationmultiplication": "accel_mult", "feignedbraking": "feigned_braking",
    "positionmirroring": "pos_mirror", "reversedheading": "reversed_heading",
    "suddenconstantspeed": "sudden_const_speed", "timedelayattack": "time_delay",
    "zerospeedreport": "zero_speed",
}

ALIASES = {
    "t": ["sendTime", "send_time", "t", "time", "timestamp"],
    "rx_time": ["rcvTime", "rcv_time", "rxTime", "rx_time", "receiveTime"],
    "sender": ["sender", "senderID", "sender_id", "senderId", "vehicle", "vehicleId"],
    "pid": ["senderPseudo", "senderPseudonym", "pseudonym", "pseudo", "pid"],
    "seq": ["messageID", "message_id", "msgId", "seq", "sequence"],
    "x": ["posx", "pos_x", "x", "posX"],
    "y": ["posy", "pos_y", "y", "posY"],
    "vx": ["spdx", "spd_x", "vx", "speedX"],
    "vy": ["spdy", "spd_y", "vy", "speedY"],
    "speed": ["speed"],
    "hx": ["hedx", "hed_x", "hx"],
    "hy": ["hedy", "hed_y", "hy"],
    "heading": ["heading", "hed_deg"],
    "rx": ["rcvPosX", "rx_x", "receiverPosX", "rsu_x", "rcv_x"],
    "ry": ["rcvPosY", "rx_y", "receiverPosY", "rsu_y", "rcv_y"],
    "attack": ["attackerType", "attacker_type", "attack", "attackType", "attack_type"],
    "label": ["label", "isAttack", "is_attack", "malicious"],
}


def normalise_attack(value) -> str:
    """'ConstantPositionOffset', 'constant_position_offset', 0, 1, ... -> our attack name."""
    if value is None or value == "":
        return "honest"
    if isinstance(value, (int, float)) or str(value).lstrip("-").isdigit():
        n = int(value)
        return "honest" if n == 0 else VEREMI_TYPES.get(n, f"attack_{n}")
    key = str(value).replace("_", "").replace("-", "").replace(" ", "").lower()
    if key in ("honest", "benign", "normal", "none", "genuine"):
        return "honest"
    return NAME_MAP.get(key, str(value))


def _first(rec: dict, name: str):
    for a in ALIASES[name]:
        if a in rec and rec[a] not in (None, "") and not isinstance(rec[a], (list, tuple, dict)):
            return rec[a]
    return None


def _vec(v) -> tuple[float, float] | None:
    if isinstance(v, (list, tuple)) and len(v) >= 2:
        return float(v[0]), float(v[1])
    return None


def from_record(rec: dict, own_pos: tuple[float, float] = (0.0, 0.0),
                vehicle_attack: dict | None = None) -> dict | None:
    """One raw record (CSV row or JSON object) -> message dict, or None if it is not a BSM."""
    if rec.get("type") not in (None, 3, "3"):         # VeReMi: type 2 is the receiver's own GPS
        return None
    pos, spd, hed = _vec(rec.get("pos")), _vec(rec.get("spd")), _vec(rec.get("hed"))
    x = pos[0] if pos else _first(rec, "x")
    y = pos[1] if pos else _first(rec, "y")
    t = _first(rec, "t")
    if x is None or y is None or t is None:
        raise KeyError(f"no position/time fields found; record columns are {sorted(rec)}; add them to ALIASES")
    vx, vy = (spd if spd else (_first(rec, "vx"), _first(rec, "vy")))
    speed = _first(rec, "speed")
    if speed is None:
        if vx is None:
            raise KeyError(f"no speed fields found; record columns are {sorted(rec)}; add them to ALIASES")
        speed = math.hypot(float(vx), float(vy))
    hx, hy = (hed if hed else (_first(rec, "hx"), _first(rec, "hy")))
    heading = _first(rec, "heading")
    if heading is None:
        heading = math.degrees(math.atan2(float(hx), float(hy))) % 360.0 if hx is not None else 0.0
    sender = _first(rec, "sender")
    pid = _first(rec, "pid")
    pid = str(pid if pid is not None else sender)
    rx_time = _first(rec, "rx_time")
    rx_time = float(rx_time) if rx_time is not None else float(t)
    attack = rec.get("attackerType", None)
    if attack is None and isinstance(rec.get("groundtruth"), dict):
        attack = rec["groundtruth"].get("attackerType")
    if attack is None:
        attack = _first(rec, "attack")
    if attack is None and vehicle_attack is not None:
        attack = vehicle_attack.get(str(sender))
    name = normalise_attack(attack)
    rx, ry = _first(rec, "rx"), _first(rec, "ry")
    rsu = (float(rx), float(ry)) if rx is not None and ry is not None else own_pos
    return {"pid": pid, "seq": int(float(_first(rec, "seq") or 0)), "t": float(t), "x": float(x),
            "y": float(y), "speed": float(speed), "heading": float(heading), "rsu_x": rsu[0],
            "rsu_y": rsu[1], "rx_time": rx_time, "sender": sender, "label": 0 if name == "honest" else 1,
            "attack": name, "vehicle": str(sender), "ambiguous": False}


def load_jsonl(path: str | Path, vehicle_attack: dict | None = None) -> Iterator[dict]:
    """VeReMi-style log of one receiver: JSON lines, type 2 = own GPS, type 3 = BSM."""
    own = (0.0, 0.0)
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("type") == 2:
                p = _vec(rec.get("pos"))
                if p:
                    own = p
                continue
            m = from_record(rec, own, vehicle_attack)
            if m:
                yield m


def load_csv(path: str | Path, vehicle_attack: dict | None = None) -> Iterator[dict]:
    """VeReMi Extension style: one CSV row per received message."""
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            m = from_record(row, (0.0, 0.0), vehicle_attack)
            if m:
                yield m


def load_json(path: str | Path, vehicle_attack: dict | None = None) -> Iterator[dict]:
    """A JSON file holding a list of records (or {"messages": [...]})."""
    with open(path) as f:
        data = json.load(f)
    for rec in data["messages"] if isinstance(data, dict) and "messages" in data else data:
        m = from_record(rec, (0.0, 0.0), vehicle_attack)
        if m:
            yield m


def load(path: str | Path, vehicle_attack: dict | None = None) -> list[dict]:
    """Pick the reader from the file name; a folder loads every .json/.jsonl/.csv inside it."""
    p = Path(path)
    if p.is_dir():
        out: list[dict] = []
        for q in sorted(p.rglob("*")):
            if q.suffix in (".json", ".jsonl", ".csv") and q.name.lower() != "groundtruth.json":
                out += load(q, vehicle_attack)
        return out
    if p.suffix == ".csv":
        return list(load_csv(p, vehicle_attack))
    if p.suffix == ".json":
        try:
            return list(load_json(p, vehicle_attack))
        except json.JSONDecodeError:
            return list(load_jsonl(p, vehicle_attack))
    return list(load_jsonl(p, vehicle_attack))


def split_by_vehicle(messages: Iterable[dict], test_fraction: float = 0.3, seed: int = 1):
    """Train/test split by *sender vehicle*, never by message (a split by message
    puts the same vehicle on both sides and inflates every score)."""
    import random

    msgs = list(messages)
    vehicles = sorted({m["vehicle"] for m in msgs})
    random.Random(seed).shuffle(vehicles)
    test_v = set(vehicles[: max(1, int(len(vehicles) * test_fraction))])
    return [m for m in msgs if m["vehicle"] not in test_v], [m for m in msgs if m["vehicle"] in test_v]


if __name__ == "__main__":
    import argparse
    from collections import Counter

    ap = argparse.ArgumentParser(description="Inspect a VeReMi / NextGen file or folder")
    ap.add_argument("path")
    ap.add_argument("--inspect", action="store_true", help="print the first raw records and the parsed result")
    a = ap.parse_args()
    if a.inspect and Path(a.path).is_file():
        with open(a.path) as f:
            print("first lines:", [f.readline().strip()[:300] for _ in range(3)])
    msgs = load(a.path)
    print(f"{len(msgs)} messages, {len({m['vehicle'] for m in msgs})} senders")
    print(Counter(m["attack"] for m in msgs).most_common())
