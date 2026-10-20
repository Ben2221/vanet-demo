"""Glue between the protocol classes and the network simulator.

Implements the node hooks of docs/interfaces.md, section 3, on top of the
pure-Python Vehicle and RSU classes:

  - setup(env): TA registration (pseudonyms, Merkle root, policy) and identity
    escrow with key shares for every RSU organization
  - RSUs beacon every 100 ms, authenticate (AUTH_REQ -> AUTH_RESP with ticket),
    pre-authorize the vehicle at neighbouring RSUs over the backbone (PREAUTH),
    accept handovers, verify every BSM and run the detector, report misbehaviour
  - vehicles authenticate on the first beacon they hear, renew the ticket before
    it expires, do make-before-break handover, change pseudonym every few
    sessions, and sign every BSM with the current pseudonym
  - revoked pseudonym -> trace request -> RSU approvals -> threshold reveal of
    the escrowed identity -> the TA revokes all of that vehicle's pseudonyms

All protocol times are simulated time (node.now). Compute costs come from
--compute-times through node.processing_delay(op).
"""

from __future__ import annotations

import math

from network.hooks import BROADCAST
from network.protocols.stub_auth import builtin_check

from .crypto import keygen
from .escrow import RSUEscrowAgent, ThresholdIdentityEscrow
from .messages import Message, make_message, message_type
from .registration import create_pseudonyms, register_pseudonyms
from .rsu import RSU
from .vehicle import Vehicle

SERVICE, CLASS = "road_access", "car"
EPOCH = 1
PSEUDONYMS_PER_VEHICLE = 5
SESSIONS_PER_PSEUDONYM = 3
BEACON_INTERVAL = 0.1
TICKET_SECONDS = 30.0
RENEW_BEFORE = 2.0           # renew the ticket this many seconds before it expires
AUTH_TIMEOUT = 1.0
REPORT_K, REPORT_W = 3, 10   # report after K flagged BSMs out of the last W
HANDOVER_EDGE = 0.8          # start make-before-break at 80 % of the current RSU's range
LOST_RSU_AFTER = 0.35        # no beacon from the current RSU for this long -> hand over

__all__ = ["setup", "create_vehicle", "create_rsu", "message_type"]

# detector checks named in DETECT_FLAG rows (detection.detector HARD + WEAK)
_CHECKS = {"range", "speed_range", "pos_jump", "speed_cons", "pos_speed", "heading",
           "msg_rate", "replay", "sybil", "sudden_appear", "overlap"}


def _fields(data: bytes) -> dict | None:
    try:
        return Message.from_bytes(data).fields
    except ValueError:
        return None


# -------------------------------------------------------------------- setup
class _RootPublisher:
    """register_pseudonyms() publishes the root through this; visible at t = 0."""

    def __init__(self, bridge) -> None:
        self.bridge = bridge

    def register_root(self, epoch, merkle_root, valid_until) -> None:
        self.bridge.preload("TA", "register_root", epoch=epoch, merkle_root=merkle_root, valid_until=valid_until)


def setup(env) -> None:
    """TA registration before the run. Real identities never reach the ledger:
    only the Merkle root is published, and the identity records are escrowed
    with the RSU organizations (t-of-n key shares, t = 2f+1)."""
    pseudonyms = [p for v in env.vehicles for p in v.app.vehicle.pseudonyms]
    if pseudonyms:
        register_pseudonyms(pseudonyms, _RootPublisher(env.bridge), valid_until=1e9)
    env.bridge.preload("TA", "set_policy", service=SERVICE, classes=["car", "truck", "emergency"])
    ta = env.shared["ta"] = {"records": {}, "record_of_pid": {}, "done": set(), "revealed": set(), "escrow": None}
    if not env.rsus:
        return
    rsu_names = [r.name for r in env.rsus]
    threshold = int(env.config.get("trace_threshold") or 2 * ((len(rsu_names) - 1) // 3) + 1)
    escrow = ta["escrow"] = ThresholdIdentityEscrow(threshold=min(threshold, len(rsu_names)), rsu_orgs=rsu_names)
    by_name = {r.name: r for r in env.rsus}
    for v in env.vehicles:
        pids = [p.pid for p in v.app.vehicle.pseudonyms]
        record, shares = escrow.escrow_vehicle_identity({"vehicle": v.name, "node_id": v.id, "pids": pids})
        rec_id = f"rec{v.id}"
        ta["records"][rec_id] = record
        for pid in pids:
            ta["record_of_pid"][pid] = rec_id
        for rsu_name, share in shares.items():
            node = by_name[rsu_name]
            node.app.escrow[rec_id] = RSUEscrowAgent(rsu_name, share, node.ledger)
    env.rsus[0].schedule(1.0, _ta_loop, env)


def _ta_loop(env) -> None:
    """The TA acts on approved traces: collect t key shares, unmask, revoke all pseudonyms."""
    ta = env.shared["ta"]
    for req_id, tr in env.ta_ledger.traces().items():
        if not tr.get("approved") or req_id in ta["done"]:
            continue
        ta["done"].add(req_id)
        rec_id = ta["record_of_pid"].get(tr["pid"])
        if rec_id is None or rec_id in ta["revealed"]:
            continue                    # another pseudonym of an already revealed vehicle
        ta["revealed"].add(rec_id)
        shares = []
        for rsu in env.rsus:
            try:
                shares.append(rsu.app.escrow[rec_id].release_share(req_id))
            except PermissionError:
                continue
            if len(shares) == ta["escrow"].threshold:
                break
        try:
            identity = ta["escrow"].unmask(ta["records"][rec_id], shares)
        except ValueError as e:
            env.rsus[0].log("IDENTITY_REVEAL_FAILED", 0, None, f"{tr['pid']}: {e}")
            continue
        env.rsus[0].log("IDENTITY_REVEALED", 0, None,
                        f"{tr['pid']} -> {identity['vehicle']} with {len(shares)} shares")
        env.ta_ledger.revoke(identity["pids"], f"trace {req_id}", req_id=req_id)
    env.rsus[0].schedule(1.0, _ta_loop, env)


# ---------------------------------------------------------------------- RSU
class RsuApp:
    def __init__(self, node, env) -> None:
        sk, pk = keygen()
        keys = env.shared.setdefault("rsu_keys", {})
        keys[node.name] = pk
        self.rsu = RSU(node.name, node.ledger, sk, pk, ticket_seconds=TICKET_SECONDS,
                       trusted_rsu_keys=keys, detector=env.detector or builtin_check,
                       detector_k=REPORT_K, detector_w=REPORT_W, clock=node.now)
        self.escrow: dict[str, RSUEscrowAgent] = {}
        self.neighbours: list[str] = []
        self.flag_logged: set[str] = set()
        self.reject_logged: set[tuple[str, str]] = set()
        self.trace_opened: set[str] = set()
        self.approved: set[str] = set()

    def on_start(self, node) -> None:
        x, y = node.position()
        reach = 2.5 * node.env.config.get("rsu_range", 300.0)
        self.neighbours = [r.name for r in node.env.rsus
                           if r is not node and math.hypot(r.position()[0] - x, r.position()[1] - y) <= reach]
        node.schedule(node.env.rng.uniform(0, BEACON_INTERVAL), self._beacon, node)

    def _beacon(self, node) -> None:
        data = make_message("BEACON", **self.rsu.beacon()).to_bytes()
        node.send(BROADCAST, data)
        self._ledger_duties(node)
        node.schedule(BEACON_INTERVAL, self._beacon, node)

    def _ledger_duties(self, node) -> None:
        """Open a trace for pseudonyms this RSU reported once the ledger revoked them,
        and approve open trace requests (the RSU organizations' vote)."""
        for pid in self.rsu.reported:
            if node.ledger.is_revoked(pid) and pid not in self.trace_opened:
                self.trace_opened.add(pid)
                opened = node.env.shared.setdefault("trace_opened", set())
                if pid not in opened:
                    opened.add(pid)
                    node.ledger.request_trace(f"trace-{pid}", pid, "misbehaviour")
        for req_id, tr in node.ledger.traces().items():
            if req_id not in self.approved and not tr.get("approved"):
                self.approved.add(req_id)
                node.ledger.approve_trace(req_id)

    def on_receive(self, node, data: bytes, sim_time: float, src: int | None = None) -> None:
        # dispatch on the type byte: a BSM is decoded once, inside verify_bsm
        kind = message_type(data)
        if kind == "BSM":
            self._bsm(node, data, sim_time, src)
        elif kind == "AUTH_REQ":
            f = _fields(data)
            if f is not None and f.get("rsu_id") == node.name:
                self._auth(node, data, src)
        elif kind == "HANDOVER_REQ":
            f = _fields(data)
            if f is not None and f.get("next_rsu_id") == node.name:
                self._handover(node, data, src)
        elif kind == "PREAUTH":
            res = self.rsu.receive_preauth(data)
            node.log("PREAUTH_OK" if res["ok"] else "PREAUTH_REJECT", len(data),
                     node.processing_delay("verify_sig") * 2000, res.get("pid", res["reason"]))

    def _auth(self, node, data: bytes, sender: int) -> None:
        """ZKP authentication. RSU cost: Merkle membership + ZKP verification, then the ticket signature."""
        res = self.rsu.authenticate(data)
        pid = res.get("pid", "")
        delay = node.processing_delay("merkle_check") + node.processing_delay("verify")
        if res["ok"]:
            node.log("AUTH_VERIFY", len(data), delay * 1000, pid)
            delay += node.processing_delay("sign")
        else:
            node.log("AUTH_REJECT", len(data), delay * 1000, f"{pid}:{res['reason']}")
        resp = make_message("AUTH_RESP", ok=res["ok"], reason=res["reason"], pid=pid,
                            rsu_id=node.name, handover=False, ticket=res.get("ticket"))
        node.send(sender, resp.to_bytes(), delay=delay)
        if res["ok"]:
            # signed pre-authorization to the neighbours: a handover works before the ledger commit lands
            for i, name in enumerate(self.neighbours, 1):
                pre = self.rsu.preauthorize_neighbour(name, res["ticket"])
                node.backbone_send(name, pre, delay=delay + i * node.processing_delay("sign"))

    def _handover(self, node, data: bytes, sender: int) -> None:
        """Handover: ticket signature + request signature, then the shared authorization (ledger or PREAUTH)."""
        res = self.rsu.handover(data)
        delay = node.processing_delay("verify_sig") * 2
        # result names where the shared authorization came from: the ledger record or the PREAUTH note
        how = f":{res['via']}" if res.get("via") else ""
        node.log("HANDOVER_CHECK", len(data), delay * 1000, f"{res.get('pid', '')}:{res['reason']}{how}")
        resp = make_message("AUTH_RESP", ok=res["ok"], reason=res["reason"], pid=res.get("pid", ""),
                            rsu_id=node.name, handover=True)
        node.send(sender, resp.to_bytes(), delay=delay)

    def _bsm(self, node, data: bytes, sim_time: float, sender: int) -> None:
        res = self.rsu.verify_bsm(data, rx_time=sim_time, rsu_pos=node.position(), sender=sender)
        pid = res.get("pid", "")
        if not res["ok"] and res["reason"] == "unknown_ticket_ref":
            return                      # not seen this ticket yet: the full one comes within a second
        if not res["ok"]:
            if (pid, res["reason"]) not in self.reject_logged:
                self.reject_logged.add((pid, res["reason"]))
                node.log("BSM_REJECT", len(data), None, f"{pid}:{res['reason']}")
            return
        if res["flagged"] and pid not in self.flag_logged:
            self.flag_logged.add(pid)
            # which checks fired: explains every flag (and every false flag) in the results
            fired = [k for k, v in (res.get("features") or {}).items() if k in _CHECKS and v]
            node.log("DETECT_FLAG", len(data), None, f"{pid}:{'+'.join(fired)}" if fired else pid)
        if res["reported"]:
            node.log("REPORT", 0, None, pid)


# ------------------------------------------------------------------ vehicle
class VehicleApp:
    def __init__(self, node, env) -> None:
        self.vehicle = Vehicle(create_pseudonyms(PSEUDONYMS_PER_VEHICLE, EPOCH, CLASS), CLASS,
                               trusted_rsu_keys=env.shared.setdefault("rsu_keys", {}),
                               pseudonym_switch_after=SESSIONS_PER_PSEUDONYM,
                               full_ticket_every=int(env.config.get("full_ticket_every") or 1),
                               clock=node.now)
        self.pending: tuple[str, float, str] | None = None   # rsu, t_sent, "auth" / "handover"
        self.heard: dict[str, float] = {}
        self.retry_after = 0.0
        self.assigned: set[str] = set()
        self.revoked_in_a_row = 0

    def _log_pid(self, node) -> None:
        """Ground truth for evaluation only (metrics CSV, never sent): which vehicle uses which pseudonym."""
        pid = self.vehicle.current.pid
        if pid not in self.assigned:
            self.assigned.add(pid)
            node.log("PID_ASSIGN", 0, None, pid)

    def on_start(self, node) -> None:
        self._log_pid(node)

    def on_stop(self, node) -> None:
        self.pending = None

    def make_bsm(self, node, sim_time: float, state: dict) -> bytes:
        if not self.vehicle.ticket_valid():
            return b""          # no authenticated BSM before the first ticket
        return self.vehicle.make_bsm(seq=state["seq"], t=sim_time, x=state["x"], y=state["y"],
                                     speed=state["speed"], heading=state["heading"])

    def on_receive(self, node, data: bytes, sim_time: float, src: int | None = None) -> None:
        # vehicles act only on beacons and answers; BSMs of other vehicles are not decoded
        kind = message_type(data)
        if kind not in ("BEACON", "AUTH_RESP"):
            return
        f = _fields(data)
        if f is None:
            return
        if kind == "BEACON":
            self._beacon(node, f, sim_time, src)
        elif f.get("pid") == self.vehicle.current.pid:
            self._resp(node, f, len(data), sim_time)

    def _beacon(self, node, beacon: dict, sim_time: float, rsu_node: int) -> None:
        rsu = str(beacon.get("payload", {}).get("rsu_id", ""))
        self.heard[rsu] = sim_time
        if self.pending and sim_time - self.pending[1] > AUTH_TIMEOUT:
            node.log("AUTH_TIMEOUT", 0, None, f"{self.pending[2]}:{self.pending[0]}")
            self.pending = None
        if self.pending or sim_time < self.retry_after:
            return
        v = self.vehicle
        if not v.ticket_valid(margin=RENEW_BEFORE):
            self._send_auth(node, rsu, beacon, sim_time, rsu_node)
        elif rsu != v.current_rsu_id and self._should_handover(node, rsu, sim_time):
            try:
                req = v.make_before_break_handover(rsu, beacon)
            except ValueError:
                node.log("BEACON_REJECT", 0, None, rsu)
                return
            self.pending = (rsu, sim_time, "handover")
            # vehicle cost: check the target RSU beacon signature, sign the request
            delay = node.processing_delay("verify_sig") + node.processing_delay("sign")
            node.send(rsu_node, req, delay=delay)

    def _should_handover(self, node, rsu: str, now: float) -> bool:
        cur = self.vehicle.current_rsu_id
        if cur is None or now - self.heard.get(cur, -1e9) > LOST_RSU_AFTER:
            return True                                 # lost the current RSU
        dist = {h.name: d for h, d in node.nearby_rsus(radius=1e9)}
        d_cur, d_new = dist.get(cur, math.inf), dist.get(rsu, math.inf)
        return d_cur > HANDOVER_EDGE * node.env.config.get("rsu_range", 300.0) and d_new < d_cur

    def _send_auth(self, node, rsu: str, beacon: dict, sim_time: float, rsu_node: int) -> None:
        before = self.vehicle.current.pid
        try:
            req = self.vehicle.make_auth_request(beacon, SERVICE)
        except ValueError:
            node.log("BEACON_REJECT", 0, None, rsu)
            return
        if self.vehicle.current.pid != before:
            node.log("PSEUDONYM_CHANGE", 0, None, f"sessions -> {self.vehicle.current.pid}")
            self._log_pid(node)
        self.pending = (rsu, sim_time, "auth")
        # vehicle cost: check the beacon signature, then the ZKP (commitment g^r precomputed while idle)
        delay = node.processing_delay("verify_sig") + node.processing_delay("prove")
        node.send(rsu_node, req, delay=delay)

    def _resp(self, node, f: dict, nbytes: int, sim_time: float) -> None:
        if not self.pending or self.pending[0] != f.get("rsu_id"):
            return
        rsu, t_sent, kind = self.pending
        self.pending = None
        latency = (sim_time - t_sent) * 1000
        v = self.vehicle
        if f.get("ok"):
            self.revoked_in_a_row = 0
        if f.get("ok") and kind == "auth":
            key = v.trusted_rsu_keys.get(rsu)
            if key and v.accept_ticket(f.get("ticket") or {}, key):
                node.log("AUTH_OK", nbytes, latency, rsu)
            else:
                node.log("TICKET_REJECT", nbytes, latency, rsu)
        elif f.get("ok"):
            v.handover_accepted(rsu)
            node.log("HANDOVER_OK", nbytes, latency, rsu)
        elif kind == "handover":
            node.log("HANDOVER_FALLBACK", nbytes, latency, f"{rsu}:{f.get('reason')}")
            v.ticket = None                             # full authentication on the next beacon
        else:
            node.log("AUTH_REJECTED", nbytes, latency, f"{rsu}:{f.get('reason')}")
            self.revoked_in_a_row = self.revoked_in_a_row + 1 if f.get("reason") == "revoked" else 0
            if self.revoked_in_a_row >= len(v.pseudonyms):
                node.log("ALL_PSEUDONYMS_REVOKED", 0, None, "")
                self.retry_after = math.inf          # every pseudonym is revoked: stop trying
                return
            v.change_pseudonym()
            node.log("PSEUDONYM_CHANGE", 0, None, f"rejected -> {v.current.pid}")
            self._log_pid(node)
            self.retry_after = sim_time + 2.0


def create_vehicle(node, env):
    return VehicleApp(node, env)


def create_rsu(node, env):
    return RsuApp(node, env)
