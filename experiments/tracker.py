"""Tracking attack on pseudonym changes (unlinkability, Person 4).

A global passive eavesdropper hears every BSM (worst case: a receiver at every
corner). It sees tracks: the BSMs of one pseudonym. When a track ends and another
starts shortly after near where the first vehicle should be by now, it links them.

    python experiments/tracker.py <run dir>        # needs observed_bsms.csv (--privacy-log)

Linking rule (the usual dead-reckoning tracker):
  - a track ending at time t1 (last position p1, velocity v1 from its last BSMs) can be
    continued by a track starting at t2 in (t1, t1 + MAX_GAP] whose first position is
    within GATE m of p1 + v1 * (t2 - t1);
  - cost = prediction error + SPEED_WEIGHT * |speed difference|; pairs are linked
    greedily, cheapest first, each track at most once in each direction.

Ground truth (the ``vehicle`` column, never used by the attacker) scores it:
  tracking_success     linked correctly / pseudonym changes (every pair of consecutive
                       pseudonyms of one vehicle; a gap above MAX_GAP is never linked)
  anonymity_set_mean   candidate tracks inside the gate per real change (1 = obvious)
  traceable_fraction   share of each vehicle's observed time the attacker follows it as
                       one chain from its first pseudonym (mean over vehicles)
"""
from __future__ import annotations

import csv
import math
import sys
from collections import defaultdict
from pathlib import Path

MAX_GAP = 10.0         # s (mix-zone silence lasts at most 5 s)
GATE = 50.0            # m
SPEED_WEIGHT = 2.0     # m per m/s


def _tracks(path: Path) -> dict[str, dict]:
    by_pid: dict[str, list] = defaultdict(list)
    with path.open(newline="") as f:
        for r in csv.DictReader(f):
            by_pid[r["pid"]].append((float(r["t"]), float(r["x"]), float(r["y"]), float(r["speed"]),
                                     float(r["heading"]), r["vehicle"]))
    tracks = {}
    for pid, rows in by_pid.items():
        rows.sort()
        t1, x1, y1, s1, h1, veh = rows[-1]
        rad = math.radians(h1)
        vx, vy = s1 * math.sin(rad), s1 * math.cos(rad)
        if len(rows) > 1 and rows[-1][0] - rows[-2][0] > 1e-6:
            t0, x0, y0 = rows[-2][:3]
            vx, vy = (x1 - x0) / (t1 - t0), (y1 - y0) / (t1 - t0)
        tracks[pid] = {"start": rows[0][0], "first": rows[0][1:3], "speed0": rows[0][3],
                       "end": t1, "last": (x1, y1), "vel": (vx, vy), "speed1": s1, "vehicle": veh}
    return tracks


def analyse(path: str | Path) -> dict:
    path = Path(path)
    if path.is_dir():
        path = path / "observed_bsms.csv"
    tracks = _tracks(path)
    starts = sorted(tracks, key=lambda p: tracks[p]["start"])
    # candidate links (the attacker's view only)
    cands = []
    per_end = defaultdict(int)
    for a, ta in tracks.items():
        for b in starts:
            tb = tracks[b]
            dt = tb["start"] - ta["end"]
            if dt <= 0:
                continue
            if dt > MAX_GAP:
                break                       # starts are sorted: every later one is too late
            px, py = ta["last"][0] + ta["vel"][0] * dt, ta["last"][1] + ta["vel"][1] * dt
            err = math.hypot(tb["first"][0] - px, tb["first"][1] - py)
            if err <= GATE:
                per_end[a] += 1
                cands.append((err + SPEED_WEIGHT * abs(tb["speed0"] - ta["speed1"]), a, b))
    cands.sort()
    link, used_b = {}, set()
    for _, a, b in cands:
        if a not in link and b not in used_b:
            link[a] = b
            used_b.add(b)
    # ground truth: consecutive pseudonyms of a vehicle
    by_vehicle: dict[str, list[str]] = defaultdict(list)
    for pid in starts:
        by_vehicle[tracks[pid]["vehicle"]].append(pid)
    changes = [(a, b) for pids in by_vehicle.values() for a, b in zip(pids, pids[1:])]
    correct = sum(link.get(a) == b for a, b in changes)
    fractions = []
    for veh, pids in by_vehicle.items():
        total = tracks[pids[-1]]["end"] - tracks[pids[0]]["start"]
        if total <= 0:
            continue
        cur, followed = pids[0], 0.0
        while True:
            followed = tracks[cur]["end"] - tracks[pids[0]]["start"]
            nxt = link.get(cur)
            if nxt is None or tracks[nxt]["vehicle"] != veh:
                break
            cur = nxt
        fractions.append(min(1.0, followed / total))
    return {
        "pseudonyms_seen": len(tracks),
        "pseudonym_changes": len(changes),
        "tracking_success": correct / len(changes) if changes else None,
        "anonymity_set_mean": (sum(per_end[a] for a, _ in changes) / len(changes)) if changes else None,
        "traceable_fraction": sum(fractions) / len(fractions) if fractions else None,
        "pseudonyms_per_vehicle": len(tracks) / len(by_vehicle) if by_vehicle else None,
    }


if __name__ == "__main__":
    for d in sys.argv[1:] or ["."]:
        print(d, analyse(d))
