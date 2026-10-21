"""TESLA broadcast authentication of BSMs (--bsm-auth tesla).

Session-MAC BSMs (--bsm-auth mac) are cheap but only the addressed RSUs can check
them. TESLA keeps the MAC cost and lets *every* receiver (RSUs and vehicles) check
every BSM, at the price of a short delay before a BSM is accepted:

- per ticket the vehicle draws a one-way key chain K_L -> ... -> K_0 with
  K_j = H(K_{j+1}); time is cut into intervals of ``interval`` s starting at the
  ticket's ``issued_at`` (interval i covers [t0 + (i-1)*interval, t0 + i*interval));
- a BSM sent in interval i carries ``ti`` = i and an 8-byte HMAC under H'(K_i), and
  discloses ``kd`` = K_{m-d} for the current interval m (``delay`` = d intervals);
- a signed anchor BSM commits to the chain with ``tc`` = [j, K_j] (an already
  disclosed key) inside its signed payload, so a receiver that joins later can
  authenticate every later key by hashing it down to K_j;
- a receiver accepts a MAC of interval i only if it arrived before the sender could
  have disclosed K_i: rx_time + skew < t0 + (i + d - 1) * interval ("tesla_late"
  otherwise). It buffers the BSM until a disclosed key K_m with m >= i hashes down to
  the committed key, then checks the MAC with H^{m-i}(K_m).

Trade-offs: a BSM is accepted one to two beacon periods after it was sent (urgent
messages are signed anchors, accepted at once); clocks must be synchronised to
``skew`` (GNSS time); after disclosure anyone can compute old MACs, so a TESLA BSM
is not evidence for a third party. Anchors stay the evidence for misbehaviour
reports, as in mac mode.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from collections import OrderedDict
from dataclasses import dataclass, field

KEY_BYTES = 16
TAG_BYTES = 8
DEFAULT_INTERVAL = 0.05
DEFAULT_DELAY = 2
DEFAULT_SKEW = 0.002
MAX_PENDING_S = 2.0          # buffered BSMs whose key never comes are dropped after this


def chain_step(key: bytes) -> bytes:
    return hashlib.sha256(b"VANET-TESLA-chain" + key).digest()[:KEY_BYTES]


def mac_key(key: bytes) -> bytes:
    return hashlib.sha256(b"VANET-TESLA-mac" + key).digest()[:KEY_BYTES]


def tag(key: bytes, message: bytes) -> str:
    return hmac.new(mac_key(key), message, hashlib.sha256).digest()[:TAG_BYTES].hex()


def interval_of(t: float, t0: float, interval: float) -> int:
    """Interval index of time t (1 for the first interval after t0)."""
    return int(math.floor((t - t0) / interval)) + 1


class Sender:
    """One key chain, for one ticket. ``t0`` is the ticket's issued_at."""

    def __init__(self, t0: float, length: int, interval: float = DEFAULT_INTERVAL,
                 delay: int = DEFAULT_DELAY) -> None:
        if length < 2 or interval <= 0 or delay < 1:
            raise ValueError("invalid TESLA parameters")
        self.t0, self.interval, self.delay = float(t0), float(interval), int(delay)
        keys = [secrets.token_bytes(KEY_BYTES)]
        for _ in range(length):
            keys.append(chain_step(keys[-1]))
        self.keys = keys[::-1]                    # keys[j] = K_j, keys[0] is the commitment
        self.length = length

    def index(self, t: float) -> int:
        return interval_of(t, self.t0, self.interval)

    def usable(self, t: float) -> bool:
        return 1 <= self.index(t) <= self.length

    def key(self, j: int) -> bytes:
        return self.keys[j]

    def disclosable(self, t: float) -> int:
        """Highest key index that may be published at time t (0: only the commitment)."""
        return max(0, min(self.length, self.index(t) - self.delay))

    def commitment(self, t: float) -> list:
        """[j, K_j] for a signed anchor: the newest key that is already public."""
        j = self.disclosable(t)
        return [j, self.keys[j].hex()]

    def mac(self, t: float, message: bytes) -> tuple[int, str]:
        i = self.index(t)
        return i, tag(self.keys[i], message)


@dataclass
class _Chain:
    t0: float
    known_j: int = -1
    known_key: bytes = b""
    pending: dict = field(default_factory=dict)       # interval -> [(tag, data, rx_time, item)]


class Receiver:
    """TESLA state of one verifier (an RSU or a vehicle) for many senders.

    Chains are keyed by (pid, ticket digest); at most ``capacity`` are kept (LRU)."""

    def __init__(self, interval: float = DEFAULT_INTERVAL, delay: int = DEFAULT_DELAY,
                 skew: float = DEFAULT_SKEW, capacity: int = 5000) -> None:
        self.interval, self.delay, self.skew = interval, delay, skew
        self.capacity = capacity
        self.chains: OrderedDict[tuple[str, str], _Chain] = OrderedDict()

    def _chain(self, key: tuple[str, str], t0: float) -> _Chain:
        c = self.chains.get(key)
        if c is None:
            c = self.chains[key] = _Chain(t0=float(t0))
            while len(self.chains) > self.capacity:
                self.chains.popitem(last=False)
        else:
            self.chains.move_to_end(key)
        return c

    def anchor(self, pid: str, digest: str, t0: float, commitment) -> list:
        """A signed anchor's [j, K_j] (already authenticated by the caller). Returns released items."""
        try:
            j, key = int(commitment[0]), bytes.fromhex(str(commitment[1]))
        except (TypeError, ValueError, IndexError):
            return []
        if j < 0 or len(key) != KEY_BYTES:
            return []
        c = self._chain((pid, digest), t0)
        if j > c.known_j or (j == c.known_j and key != c.known_key):
            c.known_j, c.known_key = j, key
        return self._release(c)

    def receive_verified(self, pid: str, digest: str, t0: float, i: int, rx_time: float, item=None) -> list:
        """A message of interval i that is already authentic (a signed anchor). It is
        released at once unless earlier TESLA BSMs of the sender are still waiting for
        their key; then it waits behind them, so a consumer sees the sender's messages
        in order (the misbehaviour detector needs that)."""
        c = self._chain((pid, digest), t0)
        if not any(x <= i for x in c.pending):
            return [(item, True, rx_time)]
        c.pending.setdefault(i, []).append((None, b"", rx_time, item))
        return []

    def too_late(self, t0: float, i: int, rx_time: float) -> bool:
        return rx_time + self.skew >= t0 + (i + self.delay - 1) * self.interval

    def receive(self, pid: str, digest: str, t0: float, i: int, mac: str, data: bytes,
                disclosed: str | None, rx_time: float, item=None) -> tuple[str, list]:
        """One TESLA BSM. Returns (status, released): status is "buffered", "tesla_late" or
        "malformed"; released = [(item, ok, rx_time)] for buffered BSMs decided now."""
        if not isinstance(i, int) or i < 1 or not isinstance(mac, str):
            return "malformed", []
        c = self._chain((pid, digest), t0)
        if self.too_late(c.t0, i, rx_time):
            released = self.disclose(pid, digest, t0, i - self.delay, disclosed, rx_time)
            return "tesla_late", released
        c.pending.setdefault(i, []).append((mac, data, rx_time, item))
        return "buffered", self.disclose(pid, digest, t0, i - self.delay, disclosed, rx_time)

    def disclose(self, pid: str, digest: str, t0: float, m: int, key_hex: str | None,
                 now: float | None = None) -> list:
        """A disclosed key K_m (from a BSM or a key message). Returns released items."""
        c = self._chain((pid, digest), t0)
        out = self._expire(c, now) if now is not None else []
        if key_hex is None or m < 1 or c.known_j < 0 or m <= c.known_j:
            return out
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            return out
        if len(key) != KEY_BYTES:
            return out
        k = key
        for _ in range(m - c.known_j):
            k = chain_step(k)
        if k != c.known_key:
            return out                         # not on the committed chain
        c.known_j, c.known_key = m, key
        return out + self._release(c)

    def _release(self, c: _Chain) -> list:
        out = []
        if c.known_j >= 1:
            for i in sorted(x for x in c.pending if x <= c.known_j):
                k = c.known_key
                for _ in range(c.known_j - i):
                    k = chain_step(k)
                for mac, data, rx, item in c.pending.pop(i):
                    ok = True if mac is None else hmac.compare_digest(tag(k, data), mac)
                    out.append((item, ok, rx))
        return out + self._release_verified_head(c)

    @staticmethod
    def _release_verified_head(c: _Chain) -> list:
        """Already authentic messages at the front of the queue go out in order."""
        out = []
        while c.pending:
            i = min(c.pending)
            if any(mac is not None for mac, _, _, _ in c.pending[i]):
                break
            out += [(item, True, rx) for _, _, rx, item in c.pending.pop(i)]
        return out

    def _expire(self, c: _Chain, now: float) -> list:
        out = []
        for i in sorted(x for x, items in c.pending.items() if items and now - items[0][2] > MAX_PENDING_S):
            out += [(item, True if mac is None else None, rx) for mac, _, rx, item in c.pending.pop(i)]
        return out + (self._release_verified_head(c) if out else [])

    def pending_count(self) -> int:
        return sum(len(v) for c in self.chains.values() for v in c.pending.values())
