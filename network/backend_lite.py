"""A small discrete-event 802.11p model in pure Python.

Not a replacement for ns-3: it exists so the whole system (protocol, ledger
bridge, metrics, experiments) can be developed and tested on any machine, and
so unit tests run in seconds. The final results come from the ns-3 backend.

What it models:
  - log-distance path loss with the same exponent and reference loss as the
    ns-3 setup, optional Nakagami fading
  - frame airtime of 802.11p OFDM at 10 MHz (40 us preamble, 8 us symbols)
  - EDCA-like channel access: AIFS + random backoff, deferral while the channel
    is sensed busy, per-node FIFO queue
  - receptions decided by SINR with all overlapping frames as interference,
    preamble locking (a receiver busy with an earlier frame misses a new one)
    and half duplex
  - unicast ACKs and up to 7 retransmissions with binary exponential backoff
  - channel busy time per node, for the channel busy ratio

Simplifications: no frame capture, no propagation delay, perfect ACKs.
"""

from __future__ import annotations

import heapq
import itertools
import math
from collections import deque
from dataclasses import dataclass
from typing import Callable

import numpy as np

from network.backend import BROADCAST, PRIORITY_AC, Backend, RxHandler
from network.mobility_model import ScenarioMobility
from network.radio import EDCA, SIFS_S, SLOT_S, RadioConfig

RETRY_LIMIT = 7
# a transmission that started less than this long ago cannot be sensed yet
# (CCA detection + propagation), so nodes whose backoff ends in the same slot collide
CCA_DELAY_S = 5e-6


@dataclass
class _Frame:
    uid: int
    src: int
    dst: int
    payload: bytes
    ac: str
    retries: int = 0


@dataclass
class _Tx:
    start: float
    end: float
    src: int
    power_mw: np.ndarray      # received power at every node, linear mW
    frame: _Frame | None      # None for an ACK


class LiteBackend(Backend):
    name = "lite"

    def __init__(self, mobility: ScenarioMobility, radio: RadioConfig, seed: int = 1) -> None:
        self.mob = mobility
        self.radio = radio
        self.n = mobility.n_nodes
        self.rng = np.random.default_rng(seed)
        self._t = 0.0
        self._queue: list = []
        self._seq = itertools.count()
        self._uid = itertools.count(1)
        self._rx: RxHandler | None = None
        self._sens_mw = 10 ** (radio.rx_sensitivity_dbm / 10)
        self._noise_mw = 10 ** (radio.noise_dbm / 10)
        self._sinr_min = 10 ** (radio.sinr_min_db / 10)
        self._txs: deque[_Tx] = deque()         # recent and ongoing transmissions
        self._macq: list[deque[_Frame]] = [deque() for _ in range(self.n)]
        self._mac_busy = [False] * self.n       # a frame is in service
        self._tx_until = np.zeros(self.n)       # end of the node's own transmission
        self._busy_until = np.zeros(self.n)
        self._busy_total = np.zeros(self.n)
        self.stats = {"tx": 0, "acks": 0, "retries": 0, "drops_retry": 0}

    # ------------------------------------------------------------- core events
    def now(self) -> float:
        return self._t

    def schedule(self, delay: float, fn: Callable[[], None]) -> None:
        heapq.heappush(self._queue, (self._t + max(0.0, delay), next(self._seq), fn))

    def run(self, until: float) -> None:
        q = self._queue
        while q and q[0][0] <= until:
            t, _, fn = heapq.heappop(q)
            self._t = t
            fn()
        self._t = until

    def set_rx_handler(self, handler: RxHandler) -> None:
        self._rx = handler

    # --------------------------------------------------------------- mobility
    def position(self, node: int) -> tuple[float, float]:
        return self.mob.position(node, self._t)

    def velocity(self, node: int) -> tuple[float, float]:
        return self.mob.velocity(node, self._t)

    def nodes_in_range(self, node: int, radius: float) -> list[tuple[int, float]]:
        pos = self.mob.positions_at(self._t)
        d = np.hypot(*(pos - pos[node]).T)
        idx = np.nonzero(d <= radius)[0]
        return [(int(i), float(d[i])) for i in idx if i != node]

    def busy_time(self, node: int) -> float:
        # busy_total already includes the whole current busy period; count only
        # the part that has elapsed
        over = self._busy_until[node] - self._t
        return float(self._busy_total[node] - max(0.0, over))

    # -------------------------------------------------------------------- MAC
    def send(self, src: int, dst: int, payload: bytes, priority: int = 0) -> int:
        uid = next(self._uid)
        self._macq[src].append(_Frame(uid, src, dst, payload, PRIORITY_AC.get(priority, "AC_BE")))
        if not self._mac_busy[src]:
            self._mac_busy[src] = True
            self._access(src)
        return uid

    def _cw(self, frame: _Frame) -> int:
        _, cwmin, cwmax = EDCA[frame.ac]
        return min(cwmax, (cwmin + 1) * (2 ** frame.retries) - 1)

    def _access(self, node: int) -> None:
        frame = self._macq[node][0]
        aifsn = EDCA[frame.ac][0]
        wait = SIFS_S + aifsn * SLOT_S + int(self.rng.integers(0, self._cw(frame) + 1)) * SLOT_S
        self.schedule(wait, lambda: self._attempt(node))

    def _sensed_busy_until(self, node: int) -> float:
        """End of the latest ongoing transmission this node can sense, or 0."""
        t = self._t
        latest = 0.0
        for tx in self._txs:
            if tx.end > t and (tx.src == node or (t - tx.start >= CCA_DELAY_S
                                                   and tx.power_mw[node] >= self._sens_mw)):
                latest = max(latest, tx.end)
        return latest

    def _attempt(self, node: int) -> None:
        busy = self._sensed_busy_until(node)
        if busy > self._t:
            frame = self._macq[node][0]
            aifsn = EDCA[frame.ac][0]
            wait = (busy - self._t) + SIFS_S + aifsn * SLOT_S + \
                int(self.rng.integers(0, self._cw(frame) + 1)) * SLOT_S
            self.schedule(wait, lambda: self._attempt(node))
            return
        self._transmit(node, self._macq[node][0])

    def _rx_powers(self, src: int) -> np.ndarray:
        pos = self.mob.positions_at(self._t)
        d = np.maximum(np.hypot(*(pos - pos[src]).T), 1.0)
        r = self.radio
        p_dbm = r.tx_power_dbm - r.reference_loss_db - 10 * r.path_loss_exponent * np.log10(d)
        p_mw = 10 ** (p_dbm / 10)
        if r.fading == "nakagami":
            p_mw = p_mw * self.rng.gamma(r.nakagami_m, 1.0 / r.nakagami_m, size=self.n)
        p_mw[src] = 0.0
        return p_mw

    def _occupy(self, tx: _Tx) -> None:
        self._txs.append(tx)
        # prune transmissions that cannot overlap anything new any more
        while self._txs and self._txs[0].end < self._t - 0.05:
            self._txs.popleft()
        sensed = tx.power_mw >= self._sens_mw
        sensed[tx.src] = True
        start = np.maximum(tx.start, self._busy_until)
        add = np.where(sensed, np.maximum(0.0, tx.end - start), 0.0)
        self._busy_total += add
        self._busy_until = np.where(sensed, np.maximum(self._busy_until, tx.end), self._busy_until)
        self._tx_until[tx.src] = tx.end

    def _transmit(self, node: int, frame: _Frame) -> None:
        dur = self.radio.airtime(len(frame.payload))
        tx = _Tx(self._t, self._t + dur, node, self._rx_powers(node), frame)
        self._occupy(tx)
        self.stats["tx"] += 1
        self.schedule(dur, lambda: self._tx_end(tx))

    def _received_mask(self, tx: _Tx) -> np.ndarray:
        """Which nodes decode tx: above sensitivity, SINR high enough counting every
        overlapping frame as interference, not locked on an earlier frame, not
        transmitting themselves (half duplex)."""
        p = tx.power_mw
        ok = p >= self._sens_mw
        if not ok.any():
            return ok
        interference = np.zeros(self.n)
        for other in self._txs:
            if other is tx or other.end <= tx.start or other.start >= tx.end:
                continue
            interference += other.power_mw
            if other.start < tx.start:
                ok &= other.power_mw < self._sens_mw      # busy receiving the earlier frame
            ok[other.src] = False                         # half duplex
        ok &= p >= self._sinr_min * (self._noise_mw + interference)
        ok[tx.src] = False
        return ok

    def _tx_end(self, tx: _Tx) -> None:
        frame = tx.frame
        src = tx.src
        if frame.dst == BROADCAST:
            for j in np.nonzero(self._received_mask(tx))[0]:
                self._deliver(int(j), frame)
            self._next_frame(src)
            return
        ok = bool(self._received_mask(tx)[frame.dst])
        if ok:
            self._deliver(frame.dst, frame)
            ack_start = self._t + SIFS_S

            def send_ack() -> None:
                ack = _Tx(self._t, self._t + self.radio.ack_airtime(), frame.dst,
                          self._rx_powers(frame.dst), None)
                self._occupy(ack)
                self.stats["acks"] += 1
                self.schedule(self.radio.ack_airtime(), lambda: self._next_frame(src))

            self.schedule(ack_start - self._t, send_ack)
            return
        if frame.retries < RETRY_LIMIT:
            frame.retries += 1
            self.stats["retries"] += 1
            self._access(src)
        else:
            self.stats["drops_retry"] += 1
            self._next_frame(src)

    def _next_frame(self, node: int) -> None:
        self._macq[node].popleft()
        if self._macq[node]:
            self._access(node)
        else:
            self._mac_busy[node] = False

    def _deliver(self, j: int, frame: _Frame) -> None:
        if self._rx is not None:
            self._rx(j, frame.src, frame.payload, frame.uid, self._t)

    def finish(self, out_dir) -> dict:
        return {"backend": "lite", **self.stats}
