"""Stand-in authentication protocol for integration before Person 3's
protocol/ package is ready.

It follows the message flow of the real design with realistic message sizes,
but NO real cryptography (proofs and signatures are random bytes of the right
length). It exercises every part of the integration:

  - RSU beacons with fresh nonces (every 100 ms) and revocation hints
  - full authentication: AUTH_REQ (proof + Merkle path) -> AUTH_RESP (ticket),
    then RecordAuth on the ledger without making the vehicle wait
  - handover: HANDOVER_REQ checked against the shared authorization record,
    make-before-break using nearby_rsus()
  - pseudonym change after N sessions
  - misbehaviour detection on BSMs at RSUs (Person 4's detector if present,
    otherwise simple plausibility checks), K-of-W reporting rule,
    ReportMisbehaviour -> revocation by the ledger after 2 RSU reports
  - revoked pseudonyms: authentication rejected, BSMs dropped by vehicles
  - conditional traceability: RequestTrace, ApproveTrace by every RSU,
    reveal + Revoke(all pseudonyms) by the TA once the threshold is reached

Replace with --protocol real once protocol/ exists; the hooks are the same.
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
from collections import deque

from network.bsm import _PLAIN as PLAIN_BSM
from network.hooks import BROADCAST

BEACON, AUTH_REQ, AUTH_RESP, HANDOVER_REQ, PREAUTH, BSM = 1, 2, 3, 4, 5, 6
NAMES = {1: "BEACON", 2: "AUTH_REQ", 3: "AUTH_RESP", 4: "HANDOVER_REQ", 5: "PREAUTH", 6: "BSM"}

SIG = 64            # Schnorr signature (R || s)
PROOF = 64          # Schnorr proof (commitment || response)
TICKET = 32
MERKLE_DEPTH = 12   # enough for 4096 pseudonyms per epoch

_BEACON = struct.Struct("!BH8sdB")             # type, rsu, nonce, t, n_revoked_hints
_AUTH_REQ = struct.Struct("!B8sH8sdBB")        # type, pid, rsu, nonce, t, service, class
_AUTH_RESP = struct.Struct("!B8sHBBd")         # type, pid, rsu, ok, handover, t_req
_HO_REQ = struct.Struct("!B8sH8sd")            # type, pid, rsu, nonce, t

PSEUDONYMS_PER_VEHICLE = 5
SESSIONS_PER_PSEUDONYM = 3
REPORT_K, REPORT_W = 3, 10      # report after K flagged BSMs out of the last W
NONCE_WINDOW = 1.0               # a beacon nonce is valid for 1 s
AUTH_TTL = 300.0
SERVICE, CLASS = "safety", "car"


def message_type(data: bytes) -> str:
    return NAMES.get(data[0], f"T{data[0]}") if data else "EMPTY"


def _pad(b: bytes, extra: int) -> bytes:
    return b + os.urandom(extra)


# ---------------------------------------------------------------- detector
def builtin_check(bsm: dict, history: list[dict]) -> tuple[bool, dict]:
    """Simple plausibility checks, used only when Person 4's detector is absent."""
    f = {"range": 0, "jump": 0, "speed_cons": 0, "decel": 0}
    d_rsu = math.hypot(bsm["x"] - bsm["rsu_x"], bsm["y"] - bsm["rsu_y"])
    if d_rsu > 450:
        f["range"] = 1
    if history:
        prev = history[-1]
        dt = bsm["t"] - prev["t"]
        if dt > 0:
            moved = math.hypot(bsm["x"] - prev["x"], bsm["y"] - prev["y"])
            implied = moved / dt
            if implied > 60:
                f["jump"] = 1
            if dt >= 0.5 and abs(implied - bsm["speed"]) > 12:
                f["speed_cons"] = 1
            if (prev["speed"] - bsm["speed"]) / dt > 9.0:
                f["decel"] = 1
    return any(f.values()), f


# -------------------------------------------------------------------- setup
def setup(env) -> None:
    """TA registration: every vehicle gets K pseudonyms, the TA publishes one
    Merkle root (here: a hash over the shuffled pseudonyms) and the policy."""
    owner: dict[str, str] = {}
    leaves = []
    for v in env.vehicles:
        pids = [os.urandom(8) for _ in range(PSEUDONYMS_PER_VEHICLE)]
        v.app.pids = pids
        for p in pids:
            owner[p.hex()] = v.name     # escrowed identity, never on the ledger
            leaves.append(p)
    env.rng.shuffle(leaves)
    root = hashlib.sha256(b"".join(leaves)).hexdigest()
    env.shared["registered"] = {p.hex() for p in leaves}
    env.shared["pid_owner"] = owner
    env.shared["trace_opened"] = set()
    env.shared["trace_done"] = set()
    env.bridge.preload("TA", "register_root", epoch=1, merkle_root=root, valid_until=1e9)
    env.bridge.preload("TA", "set_policy", service=SERVICE, classes=["car", "truck", "emergency"])
    # the TA acts on approved traces once per second
    if env.rsus:
        env.rsus[0].schedule(1.0, _ta_loop, env)


def _ta_loop(env) -> None:
    ta = env.ta_ledger
    for req_id, tr in env.ta_ledger.traces().items():
        if tr.get("approved") and req_id not in env.shared["trace_done"]:
            env.shared["trace_done"].add(req_id)
            owner = env.shared["pid_owner"].get(tr["pid"], "?")
            node = env.node(owner) if owner != "?" else None
            env.rsus[0].log("IDENTITY_REVEALED", 0, None, f"{tr['pid']} -> {owner} "
                            f"after {len(tr.get('approvals', []))} approvals")
            if node is not None:
                ta.revoke([p.hex() for p in node.app.pids], f"trace {req_id}")
    env.rsus[0].schedule(1.0, _ta_loop, env)


# ------------------------------------------------------------------- RSU
class Rsu:
    def __init__(self, node, env) -> None:
        self.index = int(node.name.removeprefix("rsu"))
        self.nonces: deque[tuple[bytes, float]] = deque()
        self.used: set[tuple[bytes, bytes]] = set()
        self.history: dict[str, deque] = {}
        self.flags: dict[str, deque] = {}
        self.reported: set[str] = set()
        self.approved: set[str] = set()
        self.detector = env.detector or builtin_check

    def on_start(self, node) -> None:
        node.schedule(node.env.rng.uniform(0, 0.1), self._beacon, node)

    def _beacon(self, node) -> None:
        t = node.now()
        nonce = os.urandom(8)
        self.nonces.append((nonce, t))
        while self.nonces and t - self.nonces[0][1] > NONCE_WINDOW:
            self.nonces.popleft()
        revoked = list(node.ledger.revoked())[-4:]
        data = _BEACON.pack(BEACON, self.index, nonce, t, len(revoked))
        data += b"".join(bytes.fromhex(p) for p in revoked)
        node.send(BROADCAST, _pad(data, SIG))
        self._ledger_duties(node)
        node.schedule(0.1, self._beacon, node)

    def _ledger_duties(self, node) -> None:
        env = node.env
        for pid in self.reported:
            if node.ledger.is_revoked(pid) and pid not in env.shared["trace_opened"]:
                env.shared["trace_opened"].add(pid)
                node.ledger.request_trace(f"trace-{pid}", pid, "misbehaviour")
        for req_id, tr in node.ledger.traces().items():
            if req_id not in self.approved and not tr.get("approved"):
                self.approved.add(req_id)
                node.ledger.approve_trace(req_id)

    def _fresh(self, nonce: bytes) -> bool:
        return any(n == nonce for n, _ in self.nonces)

    def on_receive(self, node, data: bytes, sim_time: float) -> None:
        kind = data[0]
        if kind == AUTH_REQ:
            self._auth(node, data, sim_time)
        elif kind == HANDOVER_REQ:
            self._handover(node, data, sim_time)
        elif kind == BSM:
            self._bsm(node, data, sim_time)

    def _reply(self, node, dst, pid: bytes, ok: bool, handover: bool, t_req: float, delay: float) -> None:
        resp = _AUTH_RESP.pack(AUTH_RESP, pid, self.index, int(ok), int(handover), t_req)
        node.send(dst, _pad(resp, TICKET + SIG), delay=delay)

    def _auth(self, node, data: bytes, sim_time: float) -> None:
        _, pid, rsu, nonce, t_req, _, _ = _AUTH_REQ.unpack_from(data)
        if rsu != self.index:
            return
        pid_hex = pid.hex()
        verify = node.processing_delay("verify") + node.processing_delay("merkle_check")
        reason = None
        if not self._fresh(nonce) or (pid, nonce) in self.used:
            reason = "stale_or_replayed_nonce"
        elif pid_hex not in node.env.shared["registered"]:
            reason = "unregistered"
        elif node.ledger.is_revoked(pid_hex):
            reason = "revoked"
        elif CLASS not in (node.ledger.get_policy(SERVICE) or []):
            reason = "policy"
        self.used.add((pid, nonce))
        if reason:
            node.log("AUTH_REJECT", len(data), None, f"{pid_hex}:{reason}")
            self._reply(node, node.last_sender, pid, False, False, t_req, verify)
            return
        node.log("AUTH_VERIFY", len(data), verify * 1000, pid_hex)
        self._reply(node, node.last_sender, pid, True, False, t_req, verify + node.processing_delay("sign"))
        node.ledger.record_auth(pid_hex, SERVICE, CLASS, sim_time + AUTH_TTL)

    def _handover(self, node, data: bytes, sim_time: float) -> None:
        _, pid, rsu, nonce, t_req = _HO_REQ.unpack_from(data)
        if rsu != self.index:
            return
        pid_hex = pid.hex()
        rec = node.ledger.get_auth(pid_hex)
        ok = (rec is not None and rec["expiry"] > sim_time and self._fresh(nonce)
              and not node.ledger.is_revoked(pid_hex))
        delay = node.processing_delay("verify_sig")
        node.log("HANDOVER_CHECK", len(data), None, f"{pid_hex}:{'ok' if ok else 'no_record'}")
        self._reply(node, node.last_sender, pid, ok, True, t_req, delay + node.processing_delay("sign"))

    def _bsm(self, node, data: bytes, sim_time: float) -> None:
        _, pid, seq, t, x, y, speed, heading = PLAIN_BSM.unpack_from(data)
        pid_hex = pid.hex()
        if node.ledger.is_revoked(pid_hex):
            return
        rx, ry = node.position()
        bsm = {"pid": pid_hex, "seq": seq, "t": t, "x": x, "y": y, "speed": speed, "heading": heading,
               "rsu_x": rx, "rsu_y": ry, "rx_time": sim_time, "sender": node.last_sender}
        hist = self.history.setdefault(pid_hex, deque(maxlen=20))
        flagged, _ = self.detector(bsm, list(hist))
        hist.append(bsm)
        win = self.flags.setdefault(pid_hex, deque(maxlen=REPORT_W))
        win.append(bool(flagged))
        if flagged and sum(win) == 1:
            node.log("DETECT_FLAG", len(data), None, pid_hex)
        if sum(win) >= REPORT_K and pid_hex not in self.reported:
            self.reported.add(pid_hex)
            evidence = hashlib.sha256(data).hexdigest()
            node.log("REPORT", 0, None, pid_hex)
            node.ledger.report_misbehaviour(pid_hex, evidence)


# --------------------------------------------------------------- vehicle
class Vehicle:
    def __init__(self, node, env) -> None:
        self.pids: list[bytes] = []
        self.pid_idx = 0
        self.sessions = 0
        self.ticket = False
        self.current: int | None = None
        self.pending: tuple[int, float, str] | None = None   # rsu, t_req, kind
        self.heard: dict[int, float] = {}
        self.revoked_seen: set[str] = set()
        self.dropped: set[str] = set()
        self.retry_after = 0.0

    @property
    def pid(self) -> bytes:
        return self.pids[self.pid_idx % len(self.pids)]

    def _rotate(self, node, why: str) -> None:
        self.pid_idx += 1
        self.sessions = 0
        self.ticket = False
        self.current = None
        node.log("PSEUDONYM_CHANGE", 0, None, f"{why} -> {self.pid.hex()}")

    def on_stop(self, node) -> None:
        self.pending = None

    def make_bsm(self, node, sim_time: float, state: dict) -> bytes:
        body = PLAIN_BSM.pack(BSM, self.pid, state["seq"], sim_time, state["x"], state["y"],
                              state["speed"], state["heading"])
        return _pad(body, TICKET + SIG)

    def on_receive(self, node, data: bytes, sim_time: float) -> None:
        kind = data[0]
        if kind == BEACON:
            self._beacon(node, data, sim_time)
        elif kind == AUTH_RESP:
            self._resp(node, data, sim_time)
        elif kind == BSM:
            pid = data[1:9].hex()
            if pid in self.revoked_seen and pid not in self.dropped:
                self.dropped.add(pid)
                node.log("BSM_DROP_REVOKED", len(data), None, pid)

    def _beacon(self, node, data: bytes, sim_time: float) -> None:
        _, rsu, nonce, _, n_rev = _BEACON.unpack_from(data)
        off = _BEACON.size
        for i in range(n_rev):
            self.revoked_seen.add(data[off + 8 * i: off + 8 * i + 8].hex())
        self.heard[rsu] = sim_time
        if self.pending and sim_time - self.pending[1] > 1.0:
            node.log("AUTH_TIMEOUT", 0, None, self.pending[2])
            self.pending = None
        if self.pending or sim_time < self.retry_after:
            return
        if not self.ticket:
            self._send_auth(node, rsu, nonce, sim_time)
        elif rsu != self.current and self._should_handover(node, rsu, sim_time):
            ho = _HO_REQ.pack(HANDOVER_REQ, self.pid, rsu, nonce, sim_time)
            self.pending = (rsu, sim_time, "handover")
            node.send(node.last_sender, _pad(ho, TICKET + SIG), delay=node.processing_delay("sign"))

    def _should_handover(self, node, rsu: int, now: float) -> bool:
        if self.current is None or now - self.heard.get(self.current, -1e9) > 0.35:
            return True                                 # lost the current RSU
        near = node.nearby_rsus(radius=1e9)
        dist = {int(h.name.removeprefix("rsu")): d for h, d in near}
        cur, new = dist.get(self.current, math.inf), dist.get(rsu, math.inf)
        rng = node.env.config.get("rsu_range", 300.0)
        return cur > 0.8 * rng and new < cur            # make-before-break

    def _send_auth(self, node, rsu: int, nonce: bytes, sim_time: float) -> None:
        req = _AUTH_REQ.pack(AUTH_REQ, self.pid, rsu, nonce, sim_time, 1, 1)
        self.pending = (rsu, sim_time, "auth")
        node.send(node.last_sender, _pad(req, PROOF + 32 * MERKLE_DEPTH),
                  delay=node.processing_delay("prove"))

    def _resp(self, node, data: bytes, sim_time: float) -> None:
        _, pid, rsu, ok, handover, t_req = _AUTH_RESP.unpack_from(data)
        if pid != self.pid or not self.pending or self.pending[0] != rsu:
            return
        kind = self.pending[2]
        self.pending = None
        latency = (sim_time - t_req) * 1000
        if ok:
            self.ticket = True
            self.current = rsu
            self.sessions += 1
            node.log("HANDOVER_OK" if handover else "AUTH_OK", len(data), latency, f"rsu{rsu}")
            if self.sessions >= SESSIONS_PER_PSEUDONYM:
                self._rotate(node, "sessions")
        elif kind == "handover":
            node.log("HANDOVER_FALLBACK", len(data), latency, f"rsu{rsu}")
            self.ticket = False                         # do a full authentication next beacon
        else:
            node.log("AUTH_REJECTED", len(data), latency, f"rsu{rsu}")
            self._rotate(node, "rejected")
            self.retry_after = sim_time + 2.0


def create_vehicle(node, env):
    return Vehicle(node, env)


def create_rsu(node, env):
    return Rsu(node, env)
