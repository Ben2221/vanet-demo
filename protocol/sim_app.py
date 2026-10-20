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
  - --fast-revocation: a report also goes to the neighbours as a signed QUARANTINE
    note; K distinct reporters block the pid locally until the ledger revokes it
  - revoked pseudonym -> trace request -> RSU approvals -> threshold reveal of
    the escrowed identity -> the TA revokes all of that vehicle's pseudonyms

v3 options (docs/interfaces.md, "v3 options"; all off by default):

  --rsu-cpu             RSU crypto runs on one processor in arrival order (CpuQueue):
                        BSM acceptance latency includes queueing, overload drops BSMs
  --batch-verify        signed BSMs are verified in batches (protocol/batch.py cost model)
  --v2v-verify          vehicles verify neighbours' BSMs within --v2v-radius (protocol/v2v.py)
                        on their own processor (--obu-scale x the measured times)
  --bsm-auth tesla      TESLA BSMs (protocol/tesla.py); urgent BSMs are signed at once
  --implicit-cert       ECQV tickets (protocol/ecqv.py)
  --cluster-size N      RSU clusters of N x N grid RSUs: no handover inside a cluster
  --dr-bsm              send a BSM only when dead reckoning from the last one is off
  --revocation-filter   RSU beacons carry a Bloom filter of recently revoked pseudonyms
  --mix-zones           cooperative pseudonym change at junctions: a vehicle with >= MIX_K
                        neighbours triggers it and every neighbour in the zone with a
                        pseudonym older than MIX_MIN_AGE / 2 changes with it; each goes
                        silent until it has left the zone and at least a random
                        SILENT_MIN..SILENT_MAX s (at most SILENT_CAP s). --privacy-log writes
                        what a global eavesdropper hears (experiments/tracker.py links it)
  --credential bbs      BBS anonymous credentials instead of registered pseudonyms
  --adaptive-auth       with --bsm-auth tesla: sign every BSM (accepted at once) while the
                        channel is quiet, TESLA only when the vehicle's CBR exceeds ADAPT_HIGH
  --tesla-key-msgs      send each TESLA key the moment it may be disclosed (TESLA_KEY)
  --ticket-renewal      renew a ticket with one signed request instead of a new ZKP / BBS proof
  --trust-weighted      the TA investigates each traced pseudonym and lowers the report
                        weight of RSUs whose reports were wrong (--faulty-rsus F makes a
                        fraction F of the RSUs report random honest pseudonyms)

Statistics that are not single events (acceptance latencies, CPU load, awareness
error, V2V results) go to <out>/protocol_stats.json at the end of the run.

All protocol times are simulated time (node.now). Compute costs come from
--compute-times through node.processing_delay(op).
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import math
import xml.etree.ElementTree as ET
from collections import Counter, deque

from network.hooks import BROADCAST
from network.protocols.stub_auth import builtin_check

from . import bloom
from .batch import batch_cost
from .crypto import keygen
from .escrow import RSUEscrowAgent, ThresholdIdentityEscrow
from .messages import Message, enable_decode_cache, make_message, message_type, unpack_kinematics
from .registration import create_pseudonyms, register_pseudonyms
from .rsu import RSU
from .tesla import DEFAULT_DELAY, DEFAULT_INTERVAL, DEFAULT_SKEW, Receiver
from .v2v import V2VVerifier
from .vehicle import Vehicle, adaptive_anchor_period, bbs_pseudonyms

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
NEW_RSU_AFTER = 1.0          # digest mode: full ticket in the next BSM after a beacon from an RSU unheard this long
TICKET_DIGEST_CACHE = 5000   # digest mode: tickets each RSU remembers by digest
MAC_RUN_ANCHORS = 4          # mac mode: an RSU takes at most this many anchor gaps of MAC BSMs without an anchor
ANCHOR_HOLD = 1.0            # --adaptive-anchor: s between two anchor period changes
BEACON_REVERIFY = 0.2        # digest/mac mode: s before a heard RSU's beacon is verified again
HYST_LOST_RSU_AFTER = 1.0    # --handover-hysteresis: LOST_RSU_AFTER
HYST_BEACONS, HYST_WINDOW = 3, 0.5   # --handover-hysteresis: target beacons heard in the last HYST_WINDOW s
HYST_HOLD = 1.0              # --handover-hysteresis: s after a handover without another (unless lost)
QUARANTINE_TTL = 30.0        # --fast-revocation: s a quarantined pid stays blocked without a ledger revocation
CPU_MAX_WAIT = 0.1           # --rsu-cpu / --v2v-verify: a BSM waiting longer for the processor is dropped
BATCH_MAX = 32               # --batch-verify: at most this many signatures in one batch
RF_EVERY = 5                 # --revocation-filter: filter in every 5th beacon (2 Hz)
RF_WINDOW = TICKET_SECONDS + 5.0      # revocations older than a ticket lifetime need no filter entry
V2V_RADIUS = 100.0           # --v2v-verify: vehicles verify BSMs of senders within this many metres
FULL_TICKET_BSM_BYTES = 150  # a BSM this large carries a full ticket (learned from beyond the radius)
URGENT_DECEL = 3.0           # m/s^2: a BSM after such a deceleration is urgent (signed, sent at once)
DR_THRESHOLD, DR_SPEED, DR_HEADING, DR_MAX_GAP = 1.0, 0.5, 4.0, 1.0   # --dr-bsm triggers (m, m/s, deg, s)
MIX_RADIUS, MIX_K, MIX_RANGE = 30.0, 3, 50.0   # --mix-zones: within 30 m of a junction, >= 3 vehicles within 50 m
MIX_MIN_AGE, MIX_MAX_AGE = 20.0, 120.0
SILENT_MIN, SILENT_MAX = 0.5, 1.5    # --mix-zones: random silent period after a change ...
SILENT_CAP = 5.0                     # ... extended until the vehicle has left the zone, at most this long
PSEUDONYMS_MIX = 20          # --mix-zones: pseudonyms per vehicle (Merkle mode)
BBS_J = 32                   # --credential bbs: pseudonyms per credential and epoch
FAULTY_START, FAULTY_PERIOD = 10.0, 5.0   # --faulty-rsus: a false report every 5 s from t = 10 s
RSSI_SHADOW_DB = 4.0         # log-normal shadowing of the modelled received power (dB, 1 sigma)
ADAPT_HIGH, ADAPT_LOW, ADAPT_HOLD = 0.30, 0.20, 1.0   # --adaptive-auth: TESLA above 0.30 CBR, sign below 0.20

__all__ = ["setup", "teardown", "create_vehicle", "create_rsu", "message_type"]


def _fields(data: bytes) -> dict | None:
    try:
        return Message.from_bytes(data).fields
    except ValueError:
        return None


def _stats(env) -> dict:
    st = env.shared.get("stats")
    if st is None:
        st = env.shared["stats"] = {
            "rsu": {"rx": 0, "accepted": 0, "dropped": 0, "rejected": Counter(), "lat": []},
            "v2v": {"rx": 0, "accepted": 0, "dropped": 0, "rejected": Counter(), "lat": [],
                    "from_revoked": 0, "revoked_accepted": 0, "filter_true": 0, "filter_fp": 0,
                    "filter_attacker": 0, "filter_honest": 0, "learned": 0},
            "awareness": [], "bsm_tx": 0, "dr_skipped": 0, "urgent": 0, "tesla_keys": 0,
            "mix_changes": 0, "forced_changes": 0, "cluster_switches": 0, "faulty_reports": 0,
            "trust_updates": 0, "filter_bytes": [], "signed_bsms": 0, "tesla_bsms": 0,
            "mode_changes": 0, "renewals": 0, "silent_s": 0.0,
        }
    return st


def _send_time(payload: dict, rx: float) -> float | None:
    f = payload.get("fields")
    if isinstance(f, dict) and "t" in f:
        return float(f["t"])
    if "k" in payload:
        return unpack_kinematics(str(payload["k"]), rx)["t"]
    return None


def cluster_of(x: float, y: float, cfg: dict) -> int | None:
    """--cluster-size N: the N x N block of the RSU grid an RSU at (x, y) belongs to."""
    size = int(cfg.get("cluster_size") or 0)
    if size <= 0:
        return None
    sp = float(cfg.get("rsu_spacing") or 450.0)
    return int(round(x / sp)) // size * 1000 + int(round(y / sp)) // size


def _junctions(path) -> list[tuple[float, float]]:
    """Junction positions of a SUMO network (mix zones)."""
    if not path:
        return []
    try:
        opener = gzip.open if str(path).endswith(".gz") else open
        with opener(path, "rb") as f:
            root = ET.parse(f).getroot()
    except (OSError, ET.ParseError):
        return []
    return [(float(j.get("x")), float(j.get("y"))) for j in root.iter("junction")
            if j.get("type") not in ("internal", "dead_end")]


class CpuQueue:
    """One processor doing a node's cryptography in arrival order (--rsu-cpu, --v2v-verify).

    Work waits while the processor is busy, so latency includes queueing; a BSM that would
    wait more than CPU_MAX_WAIT is dropped (too old for safety use). With ``batch``
    (--batch-verify) batching is load-triggered: a signature that finds the processor idle is
    verified at once; signatures that arrive while it is busy are collected and verified as
    one batch (at most BATCH_MAX) the moment it is free, priced with protocol.batch.batch_cost
    and the speedups measured by protocol/measure.py. There is no timer, so an idle processor
    adds no waiting. Costs are the measured times times ``scale``."""

    def __init__(self, node, scale: float = 1.0, batch: bool = False, speedup: dict | None = None) -> None:
        self.node, self.scale, self.batch = node, scale, batch
        self.speedup = speedup or {}
        self.free_at, self.busy, self.dropped = 0.0, 0.0, 0
        self.pending: list = []
        self.flush_at: float | None = None
        self.batches: list[int] = []

    def backlog(self) -> float:
        return max(0.0, self.free_at - self.node.now())

    def run(self, cost: float) -> float:
        """Queue ``cost`` s of work; returns the sim time it is done."""
        cost *= self.scale
        start = max(self.node.now(), self.free_at)
        self.free_at = start + cost
        self.busy += cost
        return self.free_at

    def add_signature(self, single: float, invalid: bool, done) -> None:
        if not self.pending and self.backlog() <= 0:
            self.batches.append(1)
            done(self.run(single))                  # idle: no reason to wait for company
            return
        self.pending.append((single, invalid, done))
        if len(self.pending) >= BATCH_MAX:
            self._flush()
        elif self.flush_at is None:
            self.flush_at = self.free_at
            self.node.schedule(max(0.0, self.free_at - self.node.now()), self._flush)

    def _flush(self) -> None:
        self.flush_at = None
        if not self.pending:
            return
        items, self.pending = self.pending, []
        single = sum(c for c, _, _ in items) / len(items)
        end = self.run(batch_cost(len(items), single, self.speedup, sum(1 for _, bad, _ in items if bad)))
        self.batches.append(len(items))
        for _, _, done in items:
            done(end)


def _speedup(env) -> dict[int, float]:
    ct = env.config.get("compute_times_used") or {}
    return {int(k.rsplit("_", 1)[1]): float(v) for k, v in ct.items() if k.startswith("batch_speedup_")}


def _verify_with_cpu(node, cpu: CpuQueue | None, ops: list[str], done) -> None:
    """Charge the operations of one received BSM; ``done(t)`` gets the time it is decided."""
    if cpu is None:
        done(node.now())
        return
    sig = node.processing_delay("bsm_verify_one") if "bsm_verify_one" in ops else 0.0
    other = sum(node.processing_delay(op) for op in ops if op != "bsm_verify_one")
    if cpu.batch and sig:
        if other:
            cpu.run(other)
        cpu.add_signature(sig, False, done)
    else:
        done(cpu.run(sig + other))


# -------------------------------------------------------------------- setup
class _RootPublisher:
    """register_pseudonyms() publishes the root through this; visible at t = 0."""

    def __init__(self, bridge) -> None:
        self.bridge = bridge

    def register_root(self, epoch, merkle_root, valid_until) -> None:
        self.bridge.preload("TA", "register_root", epoch=epoch, merkle_root=merkle_root, valid_until=valid_until)


def setup(env) -> None:
    """TA registration before the run. Real identities never reach the ledger:
    only the Merkle root (or, with --credential bbs, the TA's BBS public key) is
    published, and the identity records are escrowed with the RSU organizations
    (t-of-n key shares, t = 2f+1)."""
    cfg = env.config
    _stats(env)
    enable_decode_cache()               # every broadcast is decoded once, not once per receiver
    if cfg.get("credential") == "bbs":
        issuer = env.shared.get("bbs_issuer")
        if issuer is not None:
            env.bridge.preload("TA", "register_root", epoch=EPOCH, merkle_root=issuer.pk_hex, valid_until=1e9)
    else:
        pseudonyms = [p for v in env.vehicles for p in v.app.vehicle.pseudonyms]
        if pseudonyms:
            register_pseudonyms(pseudonyms, _RootPublisher(env.bridge), valid_until=1e9)
    env.bridge.preload("TA", "set_policy", service=SERVICE, classes=["car", "truck", "emergency"])
    env.shared["junctions"] = _junctions(cfg.get("net_file")) if cfg.get("mix_zones") else []
    env.shared["attackers"] = {v.name for v in env.vehicles if v.is_attacker}
    n_faulty = int(round(float(cfg.get("faulty_rsus") or 0) * len(env.rsus)))
    env.shared["faulty_rsus"] = set(env.rng.sample(sorted(r.name for r in env.rsus), n_faulty)) if n_faulty else set()
    if cfg.get("detector_log"):
        env.shared["detector_log"] = []
    if cfg.get("privacy_log"):
        f = (env.out_dir / "observed_bsms.csv").open("w", newline="")
        env.shared["privacy_file"] = f
        env.shared["privacy_writer"] = w = csv.writer(f)
        w.writerow(["t", "pid", "x", "y", "speed", "heading", "vehicle"])
    ta = env.shared["ta"] = {"records": {}, "record_of_pid": {}, "done": set(), "revealed": set(),
                             "escrow": None, "trust": {}}
    if not env.rsus:
        return
    rsu_names = [r.name for r in env.rsus]
    threshold = int(cfg.get("trace_threshold") or 2 * ((len(rsu_names) - 1) // 3) + 1)
    escrow = ta["escrow"] = ThresholdIdentityEscrow(threshold=min(threshold, len(rsu_names)), rsu_orgs=rsu_names)
    by_name = {r.name: r for r in env.rsus}
    for v in env.vehicles:
        # BBS mode: the record lists every pid the credential can produce this epoch
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


def teardown(env) -> None:
    """Write protocol_stats.json (numbers that are not one event each)."""
    enable_decode_cache(False)
    f = env.shared.pop("privacy_file", None)
    if f is not None:
        f.close()
    log = env.shared.pop("detector_log", None)
    if log:
        import numpy as np
        from detection import detector as det
        np.savez_compressed(env.out_dir / "detector_log.npz",
                            X=np.array([det.feature_vector(r[0]) for r in log], np.float32),
                            y=np.array([r[1] for r in log], np.int8), attack=np.array([r[2] for r in log]),
                            vehicle=np.array([r[3] for r in log]), pid=np.array([r[4] for r in log]),
                            t=np.array([r[5] for r in log]), features=np.array(det.FEATURES))
    st = _stats(env)
    duration = float(env.config.get("duration") or 1.0)

    def summ(vals: list[float], scale: float = 1.0) -> dict:
        if not vals:
            return {"n": 0}
        s = sorted(v * scale for v in vals)
        pick = lambda q: s[min(len(s) - 1, int(q * (len(s) - 1) + 0.5))]  # noqa: E731
        return {"n": len(s), "mean": sum(s) / len(s), "p50": pick(0.5), "p95": pick(0.95),
                "p99": pick(0.99), "max": s[-1],
                "quantiles": [pick(q / 100) for q in range(0, 101, 5)]}      # for CDF plots

    def cpu_summary(kind: str) -> dict:
        cpus = [c for k, _, c in env.shared.get("cpus", []) if k == kind]
        if not cpus:
            return {}
        util = [c.busy / duration for c in cpus]
        sizes = [n for c in cpus for n in c.batches]
        return {"nodes": len(cpus), "util_mean": sum(util) / len(util), "util_max": max(util),
                "dropped": sum(c.dropped for c in cpus),
                "batch_mean": sum(sizes) / len(sizes) if sizes else None, "batches": len(sizes)}

    rsu, v2v = st["rsu"], st["v2v"]
    out = {
        "rsu_bsm": {"received": rsu["rx"], "accepted": rsu["accepted"], "dropped": rsu["dropped"],
                    "rejected": dict(rsu["rejected"]), "accept_latency_ms": summ(rsu["lat"], 1000)},
        "rsu_cpu": cpu_summary("rsu"),
        "v2v": {"received": v2v["rx"], "accepted": v2v["accepted"], "dropped": v2v["dropped"],
                "rejected": dict(v2v["rejected"]), "accept_latency_ms": summ(v2v["lat"], 1000),
                "from_revoked": v2v["from_revoked"], "revoked_accepted": v2v["revoked_accepted"],
                "filter_revoked": v2v["filter_true"], "filter_not_revoked": v2v["filter_fp"],
                "filter_drops_attacker": v2v["filter_attacker"], "filter_drops_honest": v2v["filter_honest"],
                "tickets_learned_beyond_radius": v2v["learned"]},
        "obu_cpu": cpu_summary("vehicle"),
        "awareness_error_m": summ(st["awareness"]),
        "bsm_sent": st["bsm_tx"], "bsm_suppressed_dr": st["dr_skipped"], "urgent_bsms": st["urgent"],
        "tesla_key_msgs": st["tesla_keys"], "mix_changes": st["mix_changes"],
        "forced_changes": st["forced_changes"], "cluster_switches": st["cluster_switches"],
        "faulty_reports": st["faulty_reports"], "trust_updates": st["trust_updates"],
        "signed_bsms": st["signed_bsms"], "tesla_bsms": st["tesla_bsms"], "auth_mode_changes": st["mode_changes"],
        "renewals": st["renewals"], "mix_silent_s": st["silent_s"],
        "faulty_rsus": sorted(env.shared.get("faulty_rsus", ())),
        "trust_weights": {r: w for r, (_, _, w) in env.shared.get("ta", {}).get("trust", {}).items()},
        "filter_bytes": summ(st["filter_bytes"]),
    }
    (env.out_dir / "protocol_stats.json").write_text(json.dumps(out, indent=2))


def _investigate(env, pid: str, guilty: bool) -> None:
    """--trust-weighted: the outcome of the investigation of a traced pseudonym updates the
    report weight of every RSU that reported it, w = min(1, 2 (tp + 1) / (tp + fp + 2)):
    1.0 until an RSU has more wrong than right reports, then falling towards 0."""
    ta = env.shared["ta"]
    try:
        reporters = env.ta_ledger.get_reports(pid)
    except Exception:
        return
    for rsu in reporters:
        tp, fp, _ = ta["trust"].get(rsu, (0, 0, 1.0))
        tp, fp = (tp + 1, fp) if guilty else (tp, fp + 1)
        w = min(1.0, 2 * (tp + 1) / (tp + fp + 2))
        ta["trust"][rsu] = (tp, fp, w)
        env.ta_ledger.set_weight(rsu, w)
        _stats(env)["trust_updates"] += 1
        env.rsus[0].log("TRUST_UPDATE", 0, None, f"{rsu}:{w:.2f}")


def _ta_loop(env) -> None:
    """The TA acts on approved traces: collect t key shares, unmask, revoke all pseudonyms."""
    ta = env.shared["ta"]
    for req_id, tr in env.ta_ledger.traces().items():
        if not tr.get("approved") or req_id in ta["done"]:
            continue
        ta["done"].add(req_id)
        rec_id = ta["record_of_pid"].get(tr["pid"])
        if rec_id is None:
            continue
        if rec_id in ta["revealed"]:
            # another pseudonym of an already revealed vehicle: no new reveal, but with
            # --trust-weighted its reporters are judged by the known outcome all the same
            if env.config.get("trust_weighted") and rec_id in ta.get("guilty", {}):
                _investigate(env, tr["pid"], ta["guilty"][rec_id])
            continue
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
        if env.config.get("trust_weighted"):
            # investigation (simulation: ground truth of attackers.csv decides it)
            guilty = identity["vehicle"] in env.shared.get("attackers", set())
            ta.setdefault("guilty", {})[rec_id] = guilty
            _investigate(env, tr["pid"], guilty)
            if not guilty:
                env.rsus[0].log("INVESTIGATION_HONEST", 0, None, tr["pid"])
                continue                # the vehicle keeps its other pseudonyms
        env.ta_ledger.revoke(identity["pids"], f"trace {req_id}")
    env.rsus[0].schedule(1.0, _ta_loop, env)


# ---------------------------------------------------------------------- RSU
class RsuApp:
    def __init__(self, node, env) -> None:
        sk, pk = keygen()
        keys = env.shared.setdefault("rsu_keys", {})
        keys[node.name] = pk
        cfg = env.config
        auth = cfg.get("bsm_auth", "sig")
        nonsig = auth in ("mac", "tesla")
        gap = int(cfg.get("anchor_every", 10)) * (2 if cfg.get("adaptive_anchor") else 1)
        gap = min(gap, int(cfg.get("ticket_every", 10)))      # full-ticket BSMs are anchors too
        x, y = node.position()
        self.cluster = cluster_of(x, y, cfg)
        env.shared.setdefault("rsu_cluster", {})[node.name] = self.cluster
        tesla = Receiver(float(cfg.get("tesla_interval") or DEFAULT_INTERVAL),
                         int(cfg.get("tesla_delay") or DEFAULT_DELAY), DEFAULT_SKEW) if auth == "tesla" else None
        self.rsu = RSU(node.name, node.ledger, sk, pk, ticket_seconds=TICKET_SECONDS,
                       trusted_rsu_keys=keys, detector=env.detector or builtin_check,
                       detector_k=REPORT_K, detector_w=REPORT_W, clock=node.now,
                       ticket_digest_cache=TICKET_DIGEST_CACHE
                       if cfg.get("bsm_ticket") == "digest" or nonsig else 0,
                       beacon_public_key=not cfg.get("compact_wire", False),
                       mac_run_limit=MAC_RUN_ANCHORS * gap,
                       pid_state_cache=TICKET_DIGEST_CACHE if nonsig else 0,
                       quarantine_k=int(cfg.get("report_k", 2)) if cfg.get("fast_revocation") else 0,
                       quarantine_ttl=QUARANTINE_TTL,
                       implicit_cert=bool(cfg.get("implicit_cert")), tesla=tesla, cluster=self.cluster,
                       bbs_j_max=int(cfg.get("bbs_j") or BBS_J) if cfg.get("credential") == "bbs" else 0)
        self.fast_revocation = bool(cfg.get("fast_revocation", False))
        self.block_logged: set[str] = set()
        self.escrow: dict[str, RSUEscrowAgent] = {}
        self.neighbours: list[str] = []
        self.preauth_targets: list[str] = []
        self.flag_logged: set[str] = set()
        self.reject_logged: set[tuple[str, str]] = set()
        self.trace_opened: set[str] = set()
        self.approved: set[str] = set()
        batch = bool(cfg.get("batch_verify"))
        self.cpu = CpuQueue(node, 1.0, batch, _speedup(env)) if cfg.get("rsu_cpu") or batch else None
        if self.cpu is not None:
            env.shared.setdefault("cpus", []).append(("rsu", node.name, self.cpu))
        self.rf = bool(cfg.get("revocation_filter"))
        self.beacons = 0
        self.recent_pids: deque[str] = deque(maxlen=200)
        radio = cfg.get("radio") or {}
        self.path_loss_n = radio.get("path_loss_exponent") if cfg.get("rssi_check") else None
        import random
        self.rng = random.Random(f"{cfg.get('seed', 1)}:{node.name}:rssi")

    def on_start(self, node) -> None:
        x, y = node.position()
        reach = 2.5 * node.env.config.get("rsu_range", 300.0)
        self.neighbours = [r.name for r in node.env.rsus
                           if r is not node and math.hypot(r.position()[0] - x, r.position()[1] - y) <= reach]
        clusters = node.env.shared.get("rsu_cluster", {})
        # --cluster-size: inside the cluster nobody hands over, so PREAUTH only crosses clusters
        self.preauth_targets = [n for n in self.neighbours
                                if self.cluster is None or clusters.get(n) != self.cluster]
        node.schedule(node.env.rng.uniform(0, BEACON_INTERVAL), self._beacon, node)
        if node.name in node.env.shared.get("faulty_rsus", ()):
            node.schedule(FAULTY_START, self._faulty, node)

    def _beacon(self, node) -> None:
        extra = None
        if self.rf and self.beacons % RF_EVERY == 0:
            extra = {"rf": self._filter(node)}
            _stats(node.env)["filter_bytes"].append(len(extra["rf"]) // 2)
        self.beacons += 1
        data = make_message("BEACON", **self.rsu.beacon(extra)).to_bytes()
        node.send(BROADCAST, data)
        self._ledger_duties(node)
        node.schedule(BEACON_INTERVAL, self._beacon, node)

    def _filter(self, node) -> str:
        """--revocation-filter: pseudonyms revoked or quarantined within a ticket lifetime."""
        now = node.now()
        pids = set(node.ledger.revoked_since(now - RF_WINDOW))
        pids |= {p for p, until in self.rsu.quarantine_until.items() if until > now}
        return bloom.build(pids)

    def _faulty(self, node) -> None:
        """--faulty-rsus: a compromised RSU reports a random pseudonym it heard recently."""
        cands = sorted({p for p in self.recent_pids if p not in self.rsu.reported and not node.ledger.is_revoked(p)})
        if cands:
            pid = node.env.rng.choice(cands)
            self.rsu.reported.add(pid)
            node.ledger.report_misbehaviour(pid, hashlib.sha256(f"{node.name}:{pid}".encode()).hexdigest())
            node.log("REPORT", 0, None, pid)
            node.log("FAULTY_REPORT", 0, None, pid)
            _stats(node.env)["faulty_reports"] += 1
            if self.fast_revocation:
                note = self.rsu.make_quarantine(pid, "00" * 32)
                for name in self.neighbours:
                    node.backbone_send(name, note)
                if self.rsu._add_reporter(pid, node.name):
                    self._log_block(node, pid)
        node.schedule(FAULTY_PERIOD, self._faulty, node)

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
        # dispatch on the type byte: a BSM is decoded once, inside receive_bsm
        kind = message_type(data)
        if kind in ("BSM", "TESLA_KEY"):
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
        elif kind == "QUARANTINE" and self.fast_revocation:
            res = self.rsu.receive_quarantine(data)
            if not res["ok"]:
                node.log("QUARANTINE_REJECT", len(data), node.processing_delay("verify_sig") * 1000, res["reason"])
            elif res["blocked"]:
                self._log_block(node, res["pid"])

    def _log_block(self, node, pid: str) -> None:
        if pid not in self.block_logged:
            self.block_logged.add(pid)
            node.log("QUARANTINE_BLOCK", 0, None, pid)

    def _cost(self, node, ops: list[str]) -> float:
        return sum(node.processing_delay(op) for op in ops)

    def _auth(self, node, data: bytes, sender: int) -> None:
        """ZKP authentication. RSU cost: Merkle membership + ZKP verification (or the BBS proof),
        then the ticket signature (or the ECQV certificate)."""
        res = self.rsu.authenticate(data)
        pid = res.get("pid", "")
        ops = list(self.rsu.ops)
        issue = [o for o in ops if o in ("sign", "ecqv_issue", "ecqv_reconstruct")]
        verify_cost = self._cost(node, [o for o in ops if o not in issue])
        delay = verify_cost
        if self.cpu is not None:
            delay = self.cpu.run(verify_cost) - node.now()
        if res["ok"]:
            node.log("AUTH_VERIFY", len(data), delay * 1000, pid)
            delay = (self.cpu.run(self._cost(node, issue)) - node.now()) if self.cpu else delay + self._cost(node, issue)
        else:
            node.log("AUTH_REJECT", len(data), delay * 1000, f"{pid}:{res['reason']}")
        extra = {"r": res["r"]} if res.get("r") else {}
        resp = make_message("AUTH_RESP", ok=res["ok"], reason=res["reason"], pid=pid,
                            rsu_id=node.name, handover=False, ticket=res.get("ticket"), **extra)
        node.send(sender, resp.to_bytes(), delay=delay)
        if res["ok"]:
            # signed pre-authorization to the neighbours: a handover works before the ledger commit lands
            for i, name in enumerate(self.preauth_targets, 1):
                pre = self.rsu.preauthorize_neighbour(name, res["ticket"])
                node.backbone_send(name, pre, delay=delay + i * node.processing_delay("sign"))

    def _handover(self, node, data: bytes, sender: int) -> None:
        """Handover: ticket signature + request signature, then the shared authorization (ledger or PREAUTH)."""
        res = self.rsu.handover(data)
        if self.cpu is None and not res.get("ticket"):
            delay = node.processing_delay("verify_sig") * 2
        else:
            cost = self._cost(node, self.rsu.ops)
            delay = (self.cpu.run(cost) - node.now()) if self.cpu else cost
        # result names where the shared authorization came from: the ledger record or the PREAUTH note
        how = f":{res['via']}" if res.get("via") else ""
        node.log("HANDOVER_CHECK", len(data), delay * 1000, f"{res.get('pid', '')}:{res['reason']}{how}")
        extra = {k: res[k] for k in ("ticket", "r") if res.get(k)}
        resp = make_message("AUTH_RESP", ok=res["ok"], reason=res["reason"], pid=res.get("pid", ""),
                            rsu_id=node.name, handover=True, **extra)
        node.send(sender, resp.to_bytes(), delay=delay)
        if res.get("ticket"):
            for i, name in enumerate(self.preauth_targets, 1):
                pre = self.rsu.preauthorize_neighbour(name, res["ticket"])
                node.backbone_send(name, pre, delay=delay + i * node.processing_delay("sign"))

    def _bsm(self, node, data: bytes, sim_time: float, sender: int) -> None:
        st = _stats(node.env)["rsu"]
        st["rx"] += data[:1] == b"\x06"            # BSMs only (TESLA_KEY messages are not counted)
        if self.cpu is not None and self.cpu.backlog() > CPU_MAX_WAIT:
            self.cpu.dropped += 1
            st["dropped"] += 1
            return
        results = self.rsu.receive_bsm(data, rx_time=sim_time, rsu_pos=node.position(), sender=sender,
                                       rssi_d=self._rssi_distance(node, sender))

        def done(t_end: float, results=results) -> None:
            for res in results:
                if res["ok"]:
                    st["accepted"] += 1
                    t_sent = _send_time(res["payload"], res.get("rx_time", sim_time))
                    if t_sent is not None:
                        st["lat"].append(t_end - t_sent)
                else:
                    st["rejected"][res.get("reason", "?")] += 1

        _verify_with_cpu(node, self.cpu, list(self.rsu.ops), done)
        for res in results:
            self._handle(node, data, res)

    def _rssi_distance(self, node, sender) -> tuple[float, float] | None:
        """(distance, sigma of its log) this RSU would estimate from the received power of
        ``sender``'s packet: the scenario's log-distance path loss plus log-normal shadowing
        (RSSI_SHADOW_DB), inverted with the same model. Modelled here, not read from the ns-3 PHY."""
        if sender is None or self.path_loss_n is None:
            return None
        sx, sy = node.peer_position(sender)
        x, y = node.position()
        d = max(1.0, math.hypot(sx - x, sy - y))
        sigma = RSSI_SHADOW_DB * math.log(10) / (10 * self.path_loss_n)
        return d * 10 ** (self.rng.gauss(0.0, RSSI_SHADOW_DB) / (10 * self.path_loss_n)), sigma

    def _handle(self, node, data: bytes, res: dict) -> None:
        pid = res.get("pid", "")
        if not res["ok"]:
            if (pid, res["reason"]) not in self.reject_logged:
                self.reject_logged.add((pid, res["reason"]))
                node.log("BSM_REJECT", len(data), None, f"{pid}:{res['reason']}")
            return
        self.recent_pids.append(pid)
        log = node.env.shared.get("detector_log")
        if log is not None and res.get("features") and not res["features"].get("error"):
            # --detector-log: features and ground truth, to train the simulator's detector model
            snd = node.env.node_by_id(node.last_sender) if node.last_sender is not None else None
            attacker = bool(snd is not None and snd.is_attacker and node.now() >= node.env.config.get("attack_start", 0))
            log.append((res["features"], attacker, node.env.config.get("attack", ""),
                        snd.name if snd is not None else "", pid, node.now()))
        if res["flagged"] and pid not in self.flag_logged:
            self.flag_logged.add(pid)
            node.log("DETECT_FLAG", len(data), None, pid)
        if res["reported"]:
            node.log("REPORT", 0, None, pid)
            if self.fast_revocation:
                note = self.rsu.make_quarantine(pid, res["evidence"])
                for name in self.neighbours:
                    node.backbone_send(name, note, delay=node.processing_delay("sign"))
                node.log("QUARANTINE_SENT", len(note), None, f"{pid}:{len(self.neighbours)}")
        if res.get("blocked"):
            self._log_block(node, pid)


# ------------------------------------------------------------------ vehicle
class VehicleApp:
    def __init__(self, node, env) -> None:
        cfg = env.config
        self.mix = bool(cfg.get("mix_zones"))
        credential, index = None, None
        if cfg.get("credential") == "bbs":
            from . import bbs
            issuer = env.shared.get("bbs_issuer")
            if issuer is None:
                issuer = env.shared["bbs_issuer"] = bbs.IssuerKey.generate()
            credential = bbs.enroll(issuer, CLASS, EPOCH)
            pseudonyms, index = bbs_pseudonyms(credential, int(cfg.get("bbs_j") or BBS_J))
        else:
            count = int(cfg.get("pseudonyms") or (PSEUDONYMS_MIX if self.mix else PSEUDONYMS_PER_VEHICLE))
            pseudonyms = create_pseudonyms(count, EPOCH, CLASS)
        self.vehicle = Vehicle(pseudonyms, CLASS,
                               trusted_rsu_keys=env.shared.setdefault("rsu_keys", {}),
                               pseudonym_switch_after=10 ** 9 if self.mix else SESSIONS_PER_PSEUDONYM,
                               clock=node.now,
                               bsm_ticket=cfg.get("bsm_ticket", "full"),
                               ticket_every=int(cfg.get("ticket_every", 10)),
                               compact_wire=bool(cfg.get("compact_wire", False)),
                               bsm_auth=cfg.get("bsm_auth", "sig"),
                               anchor_every=int(cfg.get("anchor_every", 10)),
                               handover_sessions=not cfg.get("handover_hysteresis", False),
                               implicit_cert=bool(cfg.get("implicit_cert")),
                               tesla_interval=float(cfg.get("tesla_interval") or DEFAULT_INTERVAL),
                               tesla_delay=int(cfg.get("tesla_delay") or DEFAULT_DELAY),
                               credential=credential, bbs_index=index,
                               ticket_period=float(cfg.get("ticket_period") or 0.0))
        self.auth_timeout = float(cfg.get("auth_timeout", AUTH_TIMEOUT))
        self.hysteresis = bool(cfg.get("handover_hysteresis", False))
        self.lost_after = HYST_LOST_RSU_AFTER if self.hysteresis else LOST_RSU_AFTER
        self.beacon_times: dict[str, deque[float]] = {}      # --handover-hysteresis: last beacons per RSU
        self.hold_until = -math.inf
        self.mac = self.vehicle.bsm_auth == "mac"
        self.tesla = self.vehicle.bsm_auth == "tesla"
        self.adaptive_anchor = self.mac and bool(cfg.get("adaptive_anchor", False))
        self.base_anchor = self.vehicle.anchor_every
        self.anchor_changed = -math.inf
        self.verified_heard: dict[str, float] = {}           # digest/mac mode: RSUs with a verified beacon
        self.pending: tuple[str, float, str] | None = None   # rsu, t_sent, "auth" / "handover"
        self.heard: dict[str, float] = {}
        self.retry_after = 0.0
        self.assigned: set[str] = set()
        self.revoked_in_a_row = 0
        # v3
        self.dr = bool(cfg.get("dr_bsm"))
        self.dr_threshold = float(cfg.get("dr_threshold") or DR_THRESHOLD)
        self.dr_max_gap = float(cfg.get("dr_max_gap") or DR_MAX_GAP)
        self.last_sent: tuple | None = None                  # (t, x, y, vx, vy, speed, heading) of the last BSM
        self.prev_speed: tuple[float, float] | None = None
        self.cluster_mode = int(cfg.get("cluster_size") or 0) > 0
        self.rf = bool(cfg.get("revocation_filter"))
        self.pid_since = 0.0
        self.silent_until = -math.inf
        self.silent_cap = -math.inf
        self.silent_from: float | None = None
        self.mix_k = int(cfg.get("mix_k") or MIX_K)
        self.silent_cap_s = float(cfg.get("mix_silent_max") or SILENT_CAP)
        self.renewal = bool(cfg.get("ticket_renewal"))
        self.adaptive_auth = self.tesla and bool(cfg.get("adaptive_auth"))
        self.sign_mode, self.mode_changed, self.signed_count = True, -math.inf, 0
        self.key_msgs = self.tesla and (bool(cfg.get("tesla_key_msgs")) or self.dr)
        self.v2v = None
        self.cpu = None
        if cfg.get("v2v_verify"):
            tesla = Receiver(self.vehicle.tesla_interval, self.vehicle.tesla_delay, DEFAULT_SKEW) if self.tesla else None
            self.v2v = V2VVerifier(self.vehicle.trusted_rsu_keys, node.now, tesla)
            self.v2v_radius = float(cfg.get("v2v_radius") or V2V_RADIUS)
            self.cpu = CpuQueue(node, float(cfg.get("obu_scale") or 1.0), bool(cfg.get("batch_verify")), _speedup(env))
            env.shared.setdefault("cpus", []).append(("vehicle", node.name, self.cpu))

    def _log_pid(self, node) -> None:
        """Ground truth for evaluation only (metrics CSV, never sent): which vehicle uses which pseudonym."""
        pid = self.vehicle.current.pid
        if pid not in self.assigned:
            self.assigned.add(pid)
            self.pid_since = node.now()
            node.log("PID_ASSIGN", 0, None, pid)

    def on_start(self, node) -> None:
        self._log_pid(node)

    def on_stop(self, node) -> None:
        self.pending = None

    # ------------------------------------------------------------- sending
    def make_bsm(self, node, sim_time: float, state: dict) -> bytes:
        v = self.vehicle
        if self.mix:
            self._mix_check(node, sim_time)
        if self._silent(node, sim_time) or not v.ticket_valid():
            return b""          # no authenticated BSM before the first ticket (or while silent)
        st = _stats(node.env)
        urgent = self._urgent(state, sim_time)
        err = self._prediction_error(state, sim_time)
        if err is not None and not node.is_attacker:
            st["awareness"].append(err)
        if self.dr and not urgent and not self._dr_due(state, sim_time, err):
            st["dr_skipped"] += 1
            return b""
        st["urgent"] += urgent
        kin = dict(seq=state["seq"], t=sim_time, x=state["x"], y=state["y"],
                   speed=state["speed"], heading=state["heading"])
        if self.tesla:
            sign = urgent
            if self.adaptive_auth:
                self._update_mode(node, sim_time)
                sign = sign or self.sign_mode
            # in sign mode the chain commitment rides on every anchor_every-th BSM only
            commit = not (self.adaptive_auth and self.sign_mode) or self.signed_count % self.base_anchor == 0
            data = v.make_bsm(urgent=sign, commit=commit, **kin)
            if v.last_bsm_anchor:
                self.signed_count += 1
            st["signed_bsms" if v.last_bsm_anchor else "tesla_bsms"] += 1
        elif not self.mac:
            data = v.make_bsm(urgent=urgent, **kin)
        else:
            if self.adaptive_anchor:
                cbr = node.channel_busy_ratio()
                n = adaptive_anchor_period(cbr, self.base_anchor, v.anchor_every)
                if n != v.anchor_every and sim_time - self.anchor_changed >= ANCHOR_HOLD:
                    node.log("ANCHOR_PERIOD", 0, None, f"{v.anchor_every}->{n} cbr={cbr:.2f}")
                    v.anchor_every, self.anchor_changed = n, sim_time
            # heard in the last LOST_RSU_AFTER s, with a beacon verified at most BEACON_REVERIFY s before that
            recent = sorted((t, r) for r, t in self.heard.items() if sim_time - t <= LOST_RSU_AFTER
                            and sim_time - self.verified_heard.get(r, -math.inf) <= LOST_RSU_AFTER + BEACON_REVERIFY)
            data = v.make_bsm(mac_rsus=[r for _, r in reversed(recent)], urgent=urgent, **kin)
        self.last_sent = (sim_time, state["x"], state["y"], state.get("vx", 0.0), state.get("vy", 0.0),
                          state["speed"], state["heading"])
        st["bsm_tx"] += 1
        writer = node.env.shared.get("privacy_writer")
        if writer is not None:
            writer.writerow([f"{sim_time:.3f}", v.current.pid, f"{state['x']:.2f}", f"{state['y']:.2f}",
                             f"{state['speed']:.2f}", f"{state['heading']:.1f}", node.name])
        if self.key_msgs and not v.last_bsm_anchor and v.tesla is not None and v.last_tesla:
            i = v.last_tesla[0]
            due = v.tesla.t0 + (i + v.tesla.delay - 1) * v.tesla.interval + 0.001 - sim_time
            node.schedule(max(0.0, due), self._disclose, node, i)
        # network/bsm.py signing delay
        self.bsm_sign_op = "bsm_sign" if v.last_bsm_anchor else ("tesla_mac" if self.tesla else "bsm_mac")
        return data

    def _update_mode(self, node, t: float) -> None:
        """--adaptive-auth: TESLA (cheap, ~1-2 intervals delay) only when the channel is busy."""
        if t - self.mode_changed < ADAPT_HOLD:
            return
        cbr = node.channel_busy_ratio()
        new = False if cbr > ADAPT_HIGH else True if cbr < ADAPT_LOW else self.sign_mode
        if new != self.sign_mode:
            self.sign_mode, self.mode_changed = new, t
            _stats(node.env)["mode_changes"] += 1
            node.log("AUTH_MODE", 0, None, f"{'sign' if new else 'tesla'} cbr={cbr:.2f}")

    def _disclose(self, node, i: int) -> None:
        """--tesla-key-msgs (or --dr-bsm): no BSM disclosed K_i yet, send it on its own."""
        v = self.vehicle
        if v.tesla is None or not node.active or (v.last_tesla and v.last_tesla[1] >= i):
            return
        data = v.make_tesla_key()
        if data:
            node.send(BROADCAST, data)
            _stats(node.env)["tesla_keys"] += 1

    def _urgent(self, state: dict, t: float) -> bool:
        prev, self.prev_speed = self.prev_speed, (t, state["speed"])
        if prev is None or t <= prev[0]:
            return False
        return (prev[1] - state["speed"]) / (t - prev[0]) > URGENT_DECEL

    def _prediction_error(self, state: dict, t: float) -> float | None:
        """Distance between where the vehicle is and where receivers dead-reckon it from its last BSM."""
        if self.last_sent is None:
            return None
        t0, x0, y0, vx0, vy0, _, _ = self.last_sent
        dt = t - t0
        return math.hypot(state["x"] - (x0 + vx0 * dt), state["y"] - (y0 + vy0 * dt))

    def _dr_due(self, state: dict, t: float, err: float | None) -> bool:
        """--dr-bsm: send when dead reckoning drifts, speed or heading changed, or after DR_MAX_GAP."""
        if self.last_sent is None or err is None:
            return True
        t0, _, _, _, _, sp0, hd0 = self.last_sent
        # half a beacon period of slack: the next tick would already be past the maximum gap
        return (t - t0 + BEACON_INTERVAL / 2 >= self.dr_max_gap or err > self.dr_threshold
                or abs(state["speed"] - sp0) > DR_SPEED
                or abs((state["heading"] - hd0 + 180.0) % 360.0 - 180.0) > DR_HEADING)

    def _mix_check(self, node, t: float) -> None:
        """--mix-zones: at a junction with >= MIX_K vehicles around, this vehicle and every
        neighbour that can join (in the zone, pseudonym older than MIX_MIN_AGE / 2) change
        pseudonym together; a lone change would be trivially linked. (The trigger stands for a
        one-bit "change now" flag in the BSM; it adds no message.)"""
        v = self.vehicle
        if v.ticket is None or t < self.silent_until:
            return
        age = t - self.pid_since
        if age < MIX_MIN_AGE:
            return
        if age >= MIX_MAX_AGE:
            self._change(node, t, "forced")
            return
        if not self._in_zone(node):
            return
        x, y = node.position()
        near = []
        for o in node.env.vehicles:
            if o is not node and o.active:
                ox, oy = o.position()
                if math.hypot(ox - x, oy - y) <= MIX_RANGE:
                    near.append(o)
        if len(near) < self.mix_k:
            return
        group = [o for o in near if isinstance(o.app, VehicleApp) and o.app._can_join(t)]
        self._change(node, t, f"mix n={len(near)} group={len(group) + 1}")
        for o in group:
            o.app._change(o, t, "mix joined")

    def _in_zone(self, node) -> bool:
        x, y = node.position()
        junctions = node.env.shared.get("junctions") or []
        return bool(junctions) and min(math.hypot(x - jx, y - jy) for jx, jy in junctions) <= MIX_RADIUS

    def _silent(self, node, t: float) -> bool:
        """--mix-zones: silent after a change until out of the zone (and the random minimum)."""
        if t < self.silent_until:
            return True
        if t < self.silent_cap and self._in_zone(node):
            return True
        if self.silent_from is not None:            # silence over: account it (safety cost)
            _stats(node.env)["silent_s"] += t - self.silent_from
            self.silent_from = None
        self.silent_cap = -math.inf
        return False

    def _can_join(self, t: float) -> bool:
        return (self.mix and self.vehicle.ticket is not None and t >= self.silent_until
                and t - self.pid_since >= MIX_MIN_AGE / 2)

    def _change(self, node, t: float, why: str) -> None:
        v = self.vehicle
        v.change_pseudonym()
        self.pending, self.last_sent = None, None
        self.silent_until = t + node.env.rng.uniform(SILENT_MIN, min(SILENT_MAX, self.silent_cap_s))
        self.silent_cap = t + self.silent_cap_s
        self.silent_from = t
        st = _stats(node.env)
        st["forced_changes" if why == "forced" else "mix_changes"] += 1
        node.log("PSEUDONYM_CHANGE", 0, None, f"{why} -> {v.current.pid}")
        self._log_pid(node)

    # ----------------------------------------------------------- receiving
    def on_receive(self, node, data: bytes, sim_time: float, src: int | None = None) -> None:
        kind = message_type(data)
        if kind in ("BSM", "TESLA_KEY"):
            if self.v2v is not None and src is not None:
                self._v2v(node, data, sim_time, src)
            return
        # otherwise vehicles act only on beacons and answers
        if kind not in ("BEACON", "AUTH_RESP"):
            return
        f = _fields(data)
        if f is None:
            return
        if kind == "BEACON":
            self._beacon(node, f, sim_time, src)
        elif f.get("pid") == self.vehicle.current.pid:
            self._resp(node, f, len(data), sim_time)

    def _v2v(self, node, data: bytes, sim_time: float, src: int) -> None:
        """--v2v-verify: check a neighbour's BSM (only senders within v2v_radius matter for safety)."""
        px, py = node.peer_position(src)
        x, y = node.position()
        st = _stats(node.env)["v2v"]
        if math.hypot(px - x, py - y) > self.v2v_radius:
            if len(data) > FULL_TICKET_BSM_BYTES and self.cpu.backlog() <= CPU_MAX_WAIT:
                self.v2v.learn(data)                       # ticket of a sender that may come closer
                if self.v2v.ops:
                    st["learned"] += 1
                    self.cpu.run(sum(node.processing_delay(op) for op in self.v2v.ops))
            return
        st["rx"] += data[:1] == b"\x06"            # BSMs only (TESLA_KEY messages are not counted)
        if self.cpu.backlog() > CPU_MAX_WAIT:
            self.cpu.dropped += 1
            st["dropped"] += 1
            return
        results = self.v2v.receive(data, sim_time)
        ledger = node.env.ta_ledger
        attacker = node.env.node_by_id(src).is_attacker if hasattr(node.env, "node_by_id") else False

        def done(t_end: float, results=results) -> None:
            for res in results:
                pid = res.get("pid", "")
                revoked = bool(pid) and ledger.is_revoked(pid)
                if res["ok"] or res.get("reason") == "revoked_filter":
                    st["from_revoked"] += revoked
                if res["ok"]:
                    st["accepted"] += 1
                    st["revoked_accepted"] += revoked
                    t_sent = _send_time(res["payload"], res.get("rx_time", sim_time))
                    if t_sent is not None:
                        st["lat"].append(t_end - t_sent)
                else:
                    reason = res.get("reason", "?")
                    st["rejected"][reason] += 1
                    if reason == "revoked_filter":
                        st["filter_true" if revoked else "filter_fp"] += 1
                        st["filter_attacker" if attacker else "filter_honest"] += 1

        _verify_with_cpu(node, self.cpu, list(self.v2v.ops), done)

    def _beacon(self, node, beacon: dict, sim_time: float, rsu_node: int) -> None:
        payload = beacon.get("payload", {})
        rsu = str(payload.get("rsu_id", ""))
        if self.rf and self.v2v is not None and "rf" in payload:
            if self.cpu is not None:
                self.cpu.run(node.processing_delay("verify_sig"))
            if self.vehicle.verify_beacon(beacon):
                self.v2v.set_filter(str(payload["rf"]), float(payload["timestamp"]))
        if self.vehicle.bsm_ticket == "digest":
            self._verified_beacon(rsu, beacon, sim_time)
        self.heard[rsu] = sim_time
        if self.hysteresis:
            self.beacon_times.setdefault(rsu, deque(maxlen=HYST_BEACONS)).append(sim_time)
        if self.pending and sim_time - self.pending[1] > self.auth_timeout:
            node.log("AUTH_TIMEOUT", 0, None, f"{self.pending[2]}:{self.pending[0]}")
            self.pending = None
        if self.pending or sim_time < self.retry_after or self._silent(node, sim_time):
            return
        v = self.vehicle
        if not v.ticket_valid(margin=RENEW_BEFORE):
            if self.renewal and v.ticket_valid() and v.sessions_on_current < v.pseudonym_switch_after:
                self._send_renew(node, rsu, beacon, sim_time, rsu_node)
            else:
                self._send_auth(node, rsu, beacon, sim_time, rsu_node)
        elif rsu != v.current_rsu_id and self._should_handover(node, rsu, sim_time):
            clusters = node.env.shared.get("rsu_cluster", {})
            if self.cluster_mode and v.ticket_cluster is not None and clusters.get(rsu) == v.ticket_cluster:
                # same cluster: the ticket is valid here already, no handover messages
                v.current_rsu_id = rsu
                v.send_full_ticket()
                node.log("CLUSTER_SWITCH", 0, 0.0, rsu)
                _stats(node.env)["cluster_switches"] += 1
                if self.hysteresis:
                    self.hold_until = sim_time + HYST_HOLD
                return
            try:
                req = v.make_before_break_handover(rsu, beacon, new_cert=self.cluster_mode and v.implicit_cert)
            except ValueError:
                node.log("BEACON_REJECT", 0, None, rsu)
                return
            self.pending = (rsu, sim_time, "handover")
            # vehicle cost: check the target RSU beacon signature, sign the request
            delay = node.processing_delay("verify_sig") + node.processing_delay("sign")
            node.send(rsu_node, req, delay=delay)

    def _verified_beacon(self, rsu: str, beacon: dict, sim_time: float) -> None:
        """Digest/mac mode: only a verified beacon picks MAC tag targets or forces a full ticket,
        so a spoofed beacon cannot evict a real neighbour's tag (it can at most keep an RSU verified
        in the last LOST_RSU_AFTER + BEACON_REVERIFY s listed). A fresh entry is not re-checked."""
        last = self.verified_heard.get(rsu, -math.inf)
        if sim_time - last < BEACON_REVERIFY or not self.vehicle.verify_beacon(beacon):
            return
        if sim_time - last > NEW_RSU_AFTER:
            self.vehicle.send_full_ticket()
        self.verified_heard[rsu] = sim_time

    def _should_handover(self, node, rsu: str, now: float) -> bool:
        """Lost the current RSU, or past HANDOVER_EDGE of its range and closer to ``rsu``.
        --handover-hysteresis: lost after HYST_LOST_RSU_AFTER, ``rsu`` must have been heard
        HYST_BEACONS times in HYST_WINDOW s, and no edge handover for HYST_HOLD s after one."""
        cur = self.vehicle.current_rsu_id
        lost = cur is None or now - self.heard.get(cur, -1e9) > self.lost_after
        if self.hysteresis:
            times = self.beacon_times.get(rsu, ())
            if len(times) < HYST_BEACONS or now - times[0] > HYST_WINDOW:
                return False
            if not lost and now < self.hold_until:
                return False
        if lost:
            return True                                 # lost the current RSU
        dist = {h.name: d for h, d in node.nearby_rsus(radius=1e9)}
        d_cur, d_new = dist.get(cur, math.inf), dist.get(rsu, math.inf)
        return d_cur > HANDOVER_EDGE * node.env.config.get("rsu_range", 300.0) and d_new < d_cur

    def _send_renew(self, node, rsu: str, beacon: dict, sim_time: float, rsu_node: int) -> None:
        """--ticket-renewal: one signed request for a fresh ticket (also a handover if ``rsu`` is new)."""
        try:
            req = self.vehicle.make_renew_request(rsu, beacon)
        except ValueError:
            node.log("BEACON_REJECT", 0, None, rsu)
            return
        self.pending = (rsu, sim_time, "renew")
        # vehicle cost: check the beacon signature, sign the request
        node.send(rsu_node, req, delay=node.processing_delay("verify_sig") + node.processing_delay("sign"))

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
        prove = "prove"
        if self.vehicle.credential is not None:
            prove = "bbs_prove_online" if self.vehicle.last_proof_precomputed else "bbs_prove"
        delay = node.processing_delay("verify_sig") + node.processing_delay(prove)
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
        if kind == "renew":
            key = v.trusted_rsu_keys.get(rsu)
            if f.get("ok") and f.get("ticket") and key and v.accept_ticket(f["ticket"], key, f.get("r")):
                node.log("RENEW_OK", nbytes, latency, rsu)
                _stats(node.env)["renewals"] += 1
            else:
                node.log("RENEW_FALLBACK", nbytes, latency, f"{rsu}:{f.get('reason')}")
                v.ticket = None                         # full authentication on the next beacon
            return
        if f.get("ok") and kind == "auth":
            key = v.trusted_rsu_keys.get(rsu)
            if key and v.accept_ticket(f.get("ticket") or {}, key, f.get("r")):
                node.log("AUTH_OK", nbytes, latency, rsu)
            else:
                node.log("TICKET_REJECT", nbytes, latency, rsu)
        elif f.get("ok"):
            if f.get("ticket"):
                # --cluster-size: a ticket for the new cluster came with the handover
                key = v.trusted_rsu_keys.get(rsu)
                if not key or not v.accept_ticket(f["ticket"], key, f.get("r"), count_session=False):
                    node.log("TICKET_REJECT", nbytes, latency, rsu)
                    v.ticket = None
                    return
            v.handover_accepted(rsu)
            node.log("HANDOVER_OK", nbytes, latency, rsu)
            if self.hysteresis:
                self.hold_until = sim_time + HYST_HOLD
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
