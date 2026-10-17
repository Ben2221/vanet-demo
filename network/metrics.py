"""Shared metrics log (interface 6) and network statistics.

metrics.csv: one row per event, columns
    sim_time, node, event, bytes, latency_ms, result
Everyone logs through MetricsLog.log(); Person 4's runner reads the CSV.

Network-level statistics collected here:
  - per-message delay (send -> receive, simulated time), per message type
  - packet delivery ratio of broadcasts: a broadcast counts as expected at every
    node within --pdr-range of the sender when it was sent, also split by distance
  - unicast delivery ratio
  - channel busy ratio per RSU (from the PHY busy time), sampled every second
"""

from __future__ import annotations

import csv
import math
from collections import defaultdict
from pathlib import Path

COLUMNS = ["sim_time", "node", "event", "bytes", "latency_ms", "result"]
DIST_BINS = [0, 50, 100, 150, 200, 250, 300, 350, 400, 450, 500]


class MetricsLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._f = path.open("w", newline="")
        self._w = csv.writer(self._f)
        self._w.writerow(COLUMNS)
        self.rows = 0

    def log(self, sim_time: float, node: str, event: str, nbytes: int = 0,
            latency_ms: float | None = None, result: str = "") -> None:
        self._w.writerow([f"{sim_time:.6f}", node, event, nbytes,
                          "" if latency_ms is None else f"{latency_ms:.3f}", result])
        self.rows += 1

    def close(self) -> None:
        self._f.close()


def _pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p
    lo, hi = math.floor(k), math.ceil(k)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _summ(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    return {"n": len(values), "mean": sum(values) / len(values), "median": _pct(values, 0.5),
            "p95": _pct(values, 0.95), "max": max(values)}


class NetStats:
    """Packet tracking keyed by the backend's packet uid."""

    def __init__(self, pdr_range: float) -> None:
        self.pdr_range = pdr_range
        # uid -> [src, t_sent, msg_type, size, expected: dict node->distance or None, got: set]
        self.inflight: dict[int, list] = {}
        self.delay_ms: dict[str, list[float]] = defaultdict(list)
        self.bcast_expected = 0
        self.bcast_delivered = 0
        self.bin_expected = [0] * (len(DIST_BINS) - 1)
        self.bin_delivered = [0] * (len(DIST_BINS) - 1)
        self.ucast_sent = 0
        self.ucast_delivered = 0
        self.sent_by_type: dict[str, int] = defaultdict(int)
        self.bytes_by_type: dict[str, int] = defaultdict(int)
        self.cbr_samples: dict[str, list[float]] = defaultdict(list)

    @staticmethod
    def _bin(d: float) -> int | None:
        for i in range(len(DIST_BINS) - 1):
            if DIST_BINS[i] <= d < DIST_BINS[i + 1]:
                return i
        return None

    def on_send(self, uid: int, src: int, t: float, mtype: str, size: int,
                expected: dict[int, float] | None) -> None:
        self.sent_by_type[mtype] += 1
        self.bytes_by_type[mtype] += size
        if expected is None:
            self.ucast_sent += 1
        self.inflight[uid] = [src, t, mtype, size, expected, set()]

    def on_receive(self, uid: int, node: int, t: float, unicast_dst: bool) -> float | None:
        """Returns the delay in ms if the packet is known, else None."""
        rec = self.inflight.get(uid)
        if rec is None:
            return None
        src, t0, mtype, _, expected, got = rec
        if node in got:
            return None                      # duplicate
        got.add(node)
        d_ms = (t - t0) * 1000.0
        self.delay_ms[mtype].append(d_ms)
        if expected is None:
            if unicast_dst:
                self.ucast_delivered += 1
        return d_ms

    def flush(self, now: float, horizon: float = 1.0) -> None:
        """Close broadcasts older than horizon s and add them to the PDR counts."""
        done = [uid for uid, r in self.inflight.items() if now - r[1] > horizon]
        for uid in done:
            self._close(self.inflight.pop(uid))

    def _close(self, rec: list) -> None:
        _, _, _, _, expected, got = rec
        if expected is None:
            return
        for node, dist in expected.items():
            b = self._bin(dist)
            self.bcast_expected += 1
            if b is not None:
                self.bin_expected[b] += 1
            if node in got:
                self.bcast_delivered += 1
                if b is not None:
                    self.bin_delivered[b] += 1

    def summary(self) -> dict:
        for rec in self.inflight.values():
            self._close(rec)
        self.inflight.clear()
        by_dist = []
        for i in range(len(DIST_BINS) - 1):
            e = self.bin_expected[i]
            by_dist.append({"from_m": DIST_BINS[i], "to_m": DIST_BINS[i + 1], "expected": e,
                            "pdr": self.bin_delivered[i] / e if e else None})
        all_cbr = [v for vals in self.cbr_samples.values() for v in vals]
        return {
            "broadcast_pdr": self.bcast_delivered / self.bcast_expected if self.bcast_expected else None,
            "broadcast_expected": self.bcast_expected,
            "broadcast_delivered": self.bcast_delivered,
            "pdr_range_m": self.pdr_range,
            "pdr_by_distance": by_dist,
            "unicast_sent": self.ucast_sent,
            "unicast_delivered": self.ucast_delivered,
            "unicast_pdr": self.ucast_delivered / self.ucast_sent if self.ucast_sent else None,
            "delay_ms": {k: _summ(v) for k, v in self.delay_ms.items()},
            "sent_by_type": dict(self.sent_by_type),
            "bytes_by_type": dict(self.bytes_by_type),
            "cbr_rsu": {k: {"mean": sum(v) / len(v), "max": max(v)} for k, v in self.cbr_samples.items() if v},
            "cbr_rsu_mean": sum(all_cbr) / len(all_cbr) if all_cbr else None,
        }
