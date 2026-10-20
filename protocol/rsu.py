"""RSU-side authentication, handover, and detector logic, independent of ns-3.

The ledger is anything with the interface of docs/interfaces.md, section 3
(``node.ledger`` in the simulator, ``MockLedger.view(rsu_id)`` in tests):
reads ``get_root``, ``get_policy``, ``get_auth``, ``is_revoked`` and writes
``record_auth``, ``report_misbehaviour``.

All times come from ``clock`` (default: wall clock; ``node.now`` in the simulator).
"""
from __future__ import annotations
import hashlib, secrets, time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable, Any
from . import ecqv
from .crypto import (verify_merkle, verify, schnorr_sign, schnorr_verify, bip340_verify, bsm_mac_key,
                     bsm_tag_ok, SchnorrProof)
from .messages import Message, make_message, unpack_kinematics
from .registration import pseudonym_leaf
from .vehicle import auth_context, bind_context, canonical_json, ticket_digest

def _usable(features: Any) -> bool:
    """Detector answer that belongs in the sender's history: no error, not a foreign copy."""
    features = features or {}
    return not features.get("error") and not features.get("foreign")


@dataclass(slots=True)
class _PidState:
    """Per-pseudonym bookkeeping of one RSU: MAC BSMs since the last signed anchor, the
    anchors-only detector history (None until the pid's first MAC BSM: until then
    bsm_history holds anchors only) and the evidence hash of each message in the K-of-W
    window that is an anchor flagged on that history (None otherwise)."""
    evidence: deque
    mac_run: int = 0
    anchors: deque | None = None


class RSU:
    """``ticket_digest_cache`` > 0 accepts BSMs that carry only a ticket digest
    (--bsm-ticket digest): a bounded LRU maps digest -> ticket payload, filled only
    with tickets whose RSU signature was checked (issued here, PREAUTH notes,
    handover requests, full-ticket BSMs). The BSM must still verify under the
    ticket's pseudonym key and pass the pid, expiry and revocation checks. Trade-off:
    a vehicle not yet in the cache loses its BSMs here (``unknown_ticket_digest``)
    until it sends a full ticket, and 64-bit digests rely on second-preimage
    resistance only against RSU-signed tickets. ``beacon_public_key=False`` leaves
    the key out of beacons (vehicles check against their trusted RSU keys anyway).
    Compact kinematics ("k") and BIP340 signatures (hex string) are recognised by form.

    MAC BSMs (--bsm-auth mac, recognised by a ``tags`` field instead of ``signature``)
    must carry a cached ticket digest and a tag under this RSU's id that verifies with
    bsm_mac_key(RSU secret, ticket pk, digest); keys are cached per (pid, digest) in an
    LRU as large as the digest cache. Only the pseudonym owner (or this RSU) can make
    that tag, so the BSM is still bound to the ticket's key, but a MAC is no evidence
    for anyone else. The vehicle picks its anchor schedule, so the RSU enforces it:

    - at most ``mac_run_limit`` MAC BSMs per pid between two accepted signed anchors
      (``anchor_overdue`` after that), so lies cannot stay MAC-only;
    - once a pid has K flags in its last W messages but no flagged anchor among them,
      only anchors are accepted from it (``anchor_required``) until it is reported or
      its window drops below K flags again. The lie then has to be signed or stop.
    - an anchor counts as evidence only if the detector flags it against the pid's
      earlier *anchors* (every one signed), not against MAC history that this RSU could
      have forged, so a third party can re-check the claim from signed messages alone.
      An attacker that lies only in MAC BSMs is therefore not reported, but gets at most
      K-1 lies per window accepted; an honest vehicle with K flagged MACs loses its MAC
      BSMs here until the flags leave the window (anchors still go through).

    A pseudonym is reported once sum(flags) >= K over all its messages and a flagged
    anchor is in the same window; the evidence hash is that anchor's. With signed BSMs
    only, every BSM is an anchor and this is the plain K-of-W rule. ``pid_state_cache``
    > 0 bounds the per-pid detector state (history, flags, anchor bookkeeping) as an
    LRU; 0 keeps it for every pid seen.

    ``quarantine_k`` > 0 (--fast-revocation) adds a local tier in front of the ledger's
    K-of-RSUs revocation: a report here also yields a signed QUARANTINE note
    (make_quarantine) for the neighbours, and once ``quarantine_k`` distinct trusted RSUs
    (valid notes plus this RSU's own report) have reported a pid it is rejected here as
    ``quarantined`` (auth, handover, BSMs) for ``quarantine_ttl`` s, or until the ledger
    shows it revoked (then the usual "revoked" checks apply). Trade-off: this applies the
    ledger's own rule before the commit is visible, without the ledger's ordering or
    audit trail; K-1 colluding RSUs still cannot block anyone, but K can block a pid for
    one TTL without a ledger record (each new distinct reporter restarts the TTL).

    v3 options (all off by default):

    - ``implicit_cert``: tickets are ECQV implicit certificates (protocol/ecqv.py). The
      AUTH_REQ carries ``cert_req`` = R_U (bound into the ZKP context), the answer the
      certificate and ``r``. _ticket_ok() then only reconstructs the ticket key; the
      certificate is authenticated by the first signature or MAC made with it, so a
      ticket enters the digest cache only after such a check (or from a signed PREAUTH).
    - ``tesla``: a tesla.Receiver; BSMs with ``tm`` are buffered until their chain key
      is disclosed (protocol/tesla.py), then go through the same checks as MAC BSMs.
      Signed anchors carry the chain commitment ``tc`` and wait behind earlier pending
      TESLA BSMs of the same pid, so the detector sees every pid's messages in order.
    - ``cluster``: this RSU's cluster id. Tickets carry ``cl``; a vehicle does not hand
      over between RSUs of one cluster, and a handover into this cluster re-issues the
      ticket for it.
    - ``bbs_j_max`` > 0 accepts BBS credential proofs (protocol/bbs.py) instead of the
      Merkle path + Schnorr proof; the epoch "root" on the ledger is then the TA's BBS
      public key.

    ``ops`` lists the cryptographic operations of the last call (for the CPU model)."""

    def __init__(self, rsu_id: str, ledger: Any, private_key: int, public_key: bytes,
                 freshness_seconds: float = 5.0, ticket_seconds: float = 30.0,
                 trusted_rsu_keys: dict[str, bytes] | None = None,
                 detector: Any = None,
                 detector_k: int = 2,
                 detector_w: int = 10,
                 nonce_window: float = 1.0,
                 ticket_digest_cache: int = 0,
                 beacon_public_key: bool = True,
                 mac_run_limit: int = 40,
                 pid_state_cache: int = 0,
                 quarantine_k: int = 0,
                 quarantine_ttl: float = 30.0,
                 implicit_cert: bool = False,
                 tesla: Any = None,
                 cluster: int | None = None,
                 bbs_j_max: int = 0,
                 send_fn: Callable[[Any, Any, bytes], None] | None = None,
                 schedule_fn: Callable[[float, Callable], None] | None = None,
                 clock: Callable[[], float] = time.time):
        self.rsu_id, self.ledger = rsu_id, ledger
        self.private_key, self.public_key = private_key, public_key
        self.freshness_seconds, self.ticket_seconds = freshness_seconds, ticket_seconds
        self.trusted_rsu_keys = trusted_rsu_keys if trusted_rsu_keys is not None else {rsu_id: public_key}
        self.clock = clock
        # Recent beacon nonces: a request may answer any nonce of the last nonce_window seconds,
        # and every vehicle may use the same beacon, but each (nonce, pid) only once.
        self.nonce: str | None = None
        self.beacon_timestamp: float | None = None
        self.nonce_window = nonce_window
        self.recent_nonces: dict[str, float] = {}
        self._nonce_order: deque[str] = deque()
        self.used_nonces: set[tuple[str, str]] = set()

        # Backbone pre-authorization cache (so handovers work before ledger commit propagates)
        self.preauth_cache: dict[str, dict[str, Any]] = {}
        # Ticket signatures already verified (a ticket is repeated in every BSM)
        self._good_tickets: dict[str, float] = {}
        self.ticket_digest_cache = ticket_digest_cache
        self._digest_tickets: OrderedDict[str, dict] = OrderedDict()
        self.beacon_public_key = beacon_public_key
        self._mac_keys: OrderedDict[tuple[str, str], bytes] = OrderedDict()
        self.mac_run_limit = mac_run_limit

        # Misbehaviour detector hook: check(bsm, history) -> (flagged, features)
        self.detector = detector
        self.detector_k = detector_k
        self.detector_w = detector_w
        self.bsm_history: dict[str, deque[dict[str, Any]]] = {}
        self.bsm_flags: dict[str, deque[bool]] = {}
        self.reported: set[str] = set()
        self.pid_state_cache = pid_state_cache
        self._pid_state: OrderedDict[str, _PidState] = OrderedDict()
        self.quarantine_k, self.quarantine_ttl = quarantine_k, quarantine_ttl
        self.reporters: dict[str, set[str]] = {}
        self.quarantine_until: dict[str, float] = {}
        self.implicit_cert, self.tesla, self.cluster = implicit_cert, tesla, cluster
        self.bbs_j_max = bbs_j_max
        self._implicit: OrderedDict[bytes, dict] = OrderedDict()
        self.ops: list[str] = []
        self._rssi_d: tuple[float, float] | None = None

        # Node hooks (Network simulation node interface)
        self.send_fn = send_fn
        self.schedule_fn = schedule_fn

    # ------------------------------------------------------------- beacons
    def beacon(self, extra: dict | None = None) -> dict:
        """Signed beacon; ``extra`` fields (e.g. the revocation filter ``rf``) are signed too."""
        now = self.clock()
        self.nonce = secrets.token_hex(16)
        self.beacon_timestamp = now
        self.recent_nonces[self.nonce] = now
        self._nonce_order.append(self.nonce)
        while self._nonce_order and now - self.recent_nonces[self._nonce_order[0]] > self.nonce_window:
            old = self._nonce_order.popleft()
            del self.recent_nonces[old]
            self.used_nonces = {u for u in self.used_nonces if u[0] != old}
        payload = {"rsu_id": self.rsu_id, "nonce": self.nonce, "timestamp": now, **(extra or {})}
        out = {"payload": payload, "signature": schnorr_sign(self.private_key, canonical_json(payload))}
        if self.beacon_public_key:
            out["public_key"] = self.public_key.hex()
        return out

    def _take_nonce(self, nonce: str, pid: str, timestamp: float | None) -> str | None:
        """Check a beacon nonce and mark it used for this pid. Returns a reject reason or None."""
        issued = self.recent_nonces.get(nonce)
        if issued is None or (nonce, pid) in self.used_nonces:
            return "invalid_or_replayed_nonce"
        if timestamp is not None and timestamp != issued:
            return "stale_request"
        if self.clock() - issued > self.freshness_seconds:
            return "stale_request"
        self.used_nonces.add((nonce, pid))
        return None

    def _root_hex(self, epoch: int, now: float) -> str | None:
        root = self.ledger.get_root(epoch)
        if not root or float(root.get("validUntil", 0)) < now:
            return None
        return root.get("merkleRoot")

    # ------------------------------------------------------ authentication
    def authenticate(self, request_bytes: bytes) -> dict:
        self.ops = []
        try:
            msg = Message.from_bytes(request_bytes)
        except Exception:
            return {"ok": False, "reason": "malformed_request"}
        if msg.type != "AUTH_REQ":
            return {"ok": False, "reason": "wrong_message_type"}
        f = msg.fields
        bbs_mode = "bbs_proof" in f
        try:
            pid, pub = str(f["pid"]), bytes.fromhex(f["public_key"])
            epoch, nonce, ts = int(f["epoch"]), str(f["nonce"]), float(f["timestamp"])
            service, vclass, requested_rsu = str(f["service"]), str(f["vehicle_class"]), str(f["rsu_id"])
            if bbs_mode:
                nym, j, bbs_proof = bytes.fromhex(f["nym"]), int(f["j"]), bytes.fromhex(f["bbs_proof"])
            else:
                path = [(str(x[0]), str(x[1])) for x in f["merkle_path"]]
                proof = SchnorrProof.from_dict(f["proof"])
            cert_req = bytes.fromhex(f["cert_req"]) if f.get("cert_req") else None
        except Exception:
            return {"ok": False, "reason": "malformed_request"}
        fail = lambda reason: {"ok": False, "reason": reason, "pid": pid}
        if self.implicit_cert and cert_req is None:
            return fail("malformed_request")
        now = self.clock()
        if requested_rsu != self.rsu_id or nonce not in self.recent_nonces or (nonce, pid) in self.used_nonces:
            return fail("invalid_or_replayed_nonce")
        if ts != self.recent_nonces[nonce] or abs(now - ts) > self.freshness_seconds:
            return fail("stale_request")
        root_hex = self._root_hex(epoch, now)
        if root_hex is None:
            return fail("unknown_or_expired_epoch")
        ctx = bind_context(auth_context(self.rsu_id, nonce, ts, service, pid, vclass), cert_req)
        if bbs_mode:
            # credential proof: TA signature on (hidden sk_v, class, epoch), nym = H(epoch, j)^sk_v
            from . import bbs
            self.ops.append("bbs_verify")
            if not 0 <= j < self.bbs_j_max:
                return fail("j_out_of_range")
            if pid != bbs.pid_of(nym) or not bbs.verify_proof(bytes.fromhex(root_hex), nym, bbs_proof,
                                                              vclass, epoch, j, ctx + pub):
                return fail("invalid_proof")
        else:
            self.ops += ["merkle_check", "verify"]
            # The leaf binds pid, key and class: a wrong class or a borrowed pid fails here.
            try:
                if not verify_merkle(pseudonym_leaf(pid, pub, vclass), path, bytes.fromhex(root_hex)):
                    return fail("not_registered")
            except Exception:
                return fail("not_registered")
            if not verify(pub, proof, ctx):
                return fail("invalid_proof")
        if self.ledger.is_revoked(pid):
            return fail("revoked")
        if self.quarantined(pid):
            return fail("quarantined")
        if vclass not in (self.ledger.get_policy(service) or []):
            return fail("policy_denied")
        self.used_nonces.add((nonce, pid))
        expiry = now + self.ticket_seconds
        fields = {"pid": pid, "service": service, "class": vclass,
                  "issuer": self.rsu_id, "issued_at": now, "expiry": expiry}
        try:
            ticket, payload, r = self._issue(fields, pub, cert_req)
        except Exception:
            return fail("invalid_cert")
        self.ledger.record_auth(pid, service, vclass, expiry)
        self._remember_ticket(ticket, payload)
        out = {"ok": True, "ticket": ticket, "reason": "authenticated", "pid": pid}
        if r is not None:
            out["r"] = r
        return out

    def _issue(self, fields: dict, pub: bytes, cert_req: bytes | None) -> tuple[dict, dict, str | None]:
        """A ticket for ``fields`` (+ this RSU's cluster): (ticket, payload with "pk", r or None)."""
        if self.cluster is not None:
            fields = {**fields, "cl": self.cluster}
        if self.implicit_cert:
            if cert_req is None:
                raise ValueError("implicit certificate needs a cert_req")
            cert, r = ecqv.issue(self.private_key, cert_req, fields)
            self.ops.append("ecqv_issue")
            ticket = {"payload": cert}
            return ticket, self._ticket_ok(ticket), ecqv.scalar_hex(r)
        payload = {"pid": fields["pid"], "pk": pub.hex(), **{k: v for k, v in fields.items() if k != "pid"}}
        self.ops.append("sign")
        return {"payload": payload, "signature": schnorr_sign(self.private_key, canonical_json(payload))}, payload, None

    def _ticket_ok(self, ticket: Any) -> dict | None:
        """Payload of a ticket from a trusted RSU, or None. Explicit tickets: RSU signature
        checked. Implicit certificates (``pu``): payload plus the reconstructed key "pk"; the
        caller authenticates the certificate with a signature or MAC under that key."""
        if not isinstance(ticket, dict):
            return None
        payload, signature = ticket.get("payload"), ticket.get("signature")
        if isinstance(payload, dict) and "pu" in payload:
            raw = canonical_json(payload)
            hit = self._implicit.get(raw)
            if hit is not None:
                self._implicit.move_to_end(raw)
                return hit
            issuer_key = self.trusted_rsu_keys.get(str(payload.get("issuer", "")))
            if issuer_key is None:
                return None
            try:
                q = ecqv.reconstruct(payload, issuer_key)
            except Exception:
                return None
            self.ops.append("ecqv_reconstruct")
            out = self._implicit[raw] = {**payload, "pk": q.hex()}
            while len(self._implicit) > 5000:
                self._implicit.popitem(last=False)
            return out
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            return None
        key = f"{signature.get('R')}{signature.get('s')}"
        if key in self._good_tickets:
            return payload if canonical_json(payload) == self._good_tickets[key] else None
        issuer_key = self.trusted_rsu_keys.get(str(payload.get("issuer", "")))
        self.ops.append("verify_sig")
        if issuer_key is None or not schnorr_verify(issuer_key, canonical_json(payload), signature):
            return None
        if len(self._good_tickets) > 5000:
            self._good_tickets.clear()
        self._good_tickets[key] = canonical_json(payload)
        return payload

    def _remember_ticket(self, ticket: dict, payload: dict) -> None:
        """Cache a ticket whose RSU signature is already checked under its digest."""
        if self.ticket_digest_cache <= 0:
            return
        digest = ticket_digest(ticket)
        self._digest_tickets[digest] = payload
        self._digest_tickets.move_to_end(digest)
        while len(self._digest_tickets) > self.ticket_digest_cache:
            self._digest_tickets.popitem(last=False)

    def _mac_key(self, pid: str, digest: str, public_key: bytes) -> bytes:
        key = self._mac_keys.get((pid, digest))
        if key is None:
            self.ops.append("ecdh")
            key = self._mac_keys[(pid, digest)] = bsm_mac_key(self.private_key, public_key, digest)
            while len(self._mac_keys) > max(1, self.ticket_digest_cache):
                self._mac_keys.popitem(last=False)
        else:
            self._mac_keys.move_to_end((pid, digest))
        return key

    def _state(self, pid: str) -> _PidState:
        st = self._pid_state.get(pid)
        if st is None:
            st = self._pid_state[pid] = _PidState(evidence=deque(maxlen=self.detector_w))
            while 0 < self.pid_state_cache < len(self._pid_state):
                old, _ = self._pid_state.popitem(last=False)
                self.bsm_history.pop(old, None)
                self.bsm_flags.pop(old, None)
        else:
            self._pid_state.move_to_end(pid)
        return st

    def _anchor_needed(self, pid: str) -> bool:
        """K-of-W reached without a flagged anchor: only a signed anchor may come next."""
        return (self.detector is not None and pid not in self.reported
                and sum(self.bsm_flags.get(pid, ())) >= self.detector_k)

    # ------------------------------------------------------------ handover
    def preauthorize_neighbour(self, next_rsu_id: str, ticket: dict) -> bytes:
        """Pre-authorization over RSU backbone: send signed note to neighbour RSU."""
        payload = {
            "ticket": ticket,
            "source_rsu": self.rsu_id,
            "target_rsu": next_rsu_id,
            "timestamp": float(self.clock())
        }
        sig = schnorr_sign(self.private_key, canonical_json(payload))
        return make_message("PREAUTH", signature=sig, **payload).to_bytes()

    def receive_preauth(self, preauth_bytes: bytes) -> dict:
        """Process incoming backbone pre-authorization from a neighbour RSU."""
        try:
            msg = Message.from_bytes(preauth_bytes)
            if msg.type != "PREAUTH":
                return {"ok": False, "reason": "wrong_message_type"}
            f = msg.fields
            source_rsu = f.get("source_rsu")
            target_rsu = f.get("target_rsu")
            if target_rsu != self.rsu_id:
                return {"ok": False, "reason": "wrong_destination"}
            source_key = self.trusted_rsu_keys.get(source_rsu)
            if source_key is None:
                return {"ok": False, "reason": "untrusted_source_rsu"}
            payload = {
                "ticket": f.get("ticket"),
                "source_rsu": source_rsu,
                "target_rsu": target_rsu,
                "timestamp": f.get("timestamp")
            }
            if not schnorr_verify(source_key, canonical_json(payload), f.get("signature", {})):
                return {"ok": False, "reason": "invalid_preauth_signature"}
            if abs(self.clock() - float(f["timestamp"])) > self.freshness_seconds:
                return {"ok": False, "reason": "stale_preauth"}
            ticket_payload = self._ticket_ok(f.get("ticket"))
            if ticket_payload is None:
                return {"ok": False, "reason": "invalid_ticket_signature"}
            pid = str(ticket_payload.get("pid", ""))
            self.preauth_cache[pid] = ticket_payload
            self._remember_ticket(f["ticket"], ticket_payload)
            return {"ok": True, "reason": "preauth_accepted", "pid": pid}
        except Exception:
            return {"ok": False, "reason": "malformed_preauth"}

    def handover(self, request_bytes: bytes) -> dict:
        self.ops = []
        try:
            msg = Message.from_bytes(request_bytes)
        except Exception:
            return {"ok": False, "reason": "malformed_request"}
        if msg.type != "HANDOVER_REQ":
            return {"ok": False, "reason": "wrong_message_type"}
        f = msg.fields
        ticket = f.get("ticket", {})
        payload = ticket.get("payload", {}) if isinstance(ticket, dict) else {}
        pid = str(payload.get("pid", "")) if isinstance(payload, dict) else ""
        fail = lambda reason: {"ok": False, "reason": reason, "pid": pid}
        if f.get("next_rsu_id") != self.rsu_id:
            return fail("wrong_destination")
        try:
            payload = self._ticket_ok(ticket)
            if payload is None:
                return fail("invalid_ticket_signature")
            now = self.clock()
            if float(payload["expiry"]) <= now or float(payload["issued_at"]) > now + 1:
                return fail("expired_or_invalid_ticket")
            # proof of possession: the request is signed by the ticket's pseudonym key
            request = {"ticket": ticket, "next_rsu_id": f.get("next_rsu_id"),
                       "nonce": f.get("nonce", ""), "timestamp": f.get("timestamp")}
            if f.get("cert_req"):
                request["cert_req"] = f["cert_req"]
            if f.get("renew"):
                request["renew"] = True
            self.ops.append("verify_sig")
            if not schnorr_verify(bytes.fromhex(payload["pk"]), canonical_json(request), f.get("signature", {})):
                return fail("invalid_request_signature")
            # only now (signed with the ticket key) is an implicit certificate authenticated
            self._remember_ticket(ticket, payload)
            if abs(now - float(f["timestamp"])) > self.freshness_seconds:
                return fail("stale_request")
            if f.get("nonce"):
                reason = self._take_nonce(str(f["nonce"]), pid, None)
                if reason:
                    return fail(reason)

            # Check shared authorization on ledger or in backbone preauth cache
            auth, via = self.ledger.get_auth(pid), "ledger"
            if not auth or float(auth.get("expiry", 0)) <= now:
                auth, via = self.preauth_cache.get(pid), "preauth"
            if not auth or float(auth.get("expiry", 0)) <= now:
                return fail("missing_shared_authorization")
            if auth.get("service") != payload.get("service") or auth.get("class") != payload.get("class"):
                return fail("authorization_mismatch")
            if self.ledger.is_revoked(pid):
                return fail("revoked")
            if self.quarantined(pid):
                return fail("quarantined")
            out = {"ok": True, "reason": "handover_accepted", "pid": pid, "via": via}
            cert_req = bytes.fromhex(f["cert_req"]) if f.get("cert_req") else None
            if f.get("renew"):
                # --ticket-renewal: a fresh ticket for the same pseudonym, without a new ZKP / BBS
                # proof. The ticket key signed the request (proof of possession), the nonce is fresh,
                # and revocation, quarantine and policy are checked as at authentication.
                if payload.get("class") not in (self.ledger.get_policy(str(payload.get("service"))) or []):
                    return fail("policy_denied")
                expiry = now + self.ticket_seconds
                fields = {k: payload[k] for k in ("pid", "service", "class")}
                fields.update(issuer=self.rsu_id, issued_at=now, expiry=expiry)
                new_ticket, new_payload, r = self._issue(fields, bytes.fromhex(payload["pk"]), cert_req)
                self._remember_ticket(new_ticket, new_payload)
                self.ledger.record_auth(pid, payload["service"], payload["class"], expiry)
                out.update(ticket=new_ticket, reason="renewed")
                if r is not None:
                    out["r"] = r
            elif self.cluster is not None and payload.get("cl") != self.cluster:
                # entering this cluster: a ticket for it, so no handover inside the cluster
                fields = {k: payload[k] for k in ("pid", "service", "class", "expiry")}
                fields.update(issuer=self.rsu_id, issued_at=now)
                new_ticket, new_payload, r = self._issue(fields, bytes.fromhex(payload["pk"]), cert_req)
                self._remember_ticket(new_ticket, new_payload)
                out.update(ticket=new_ticket, reason="cluster_ticket")
                if r is not None:
                    out["r"] = r
            return out
        except Exception:
            return fail("malformed_ticket")

    # ----------------------------------------------------------------- BSM
    def verify_bsm(self, message_bytes: bytes, rx_time: float | None = None,
                   rsu_pos: tuple[float, float] | None = None, sender: Any = None) -> dict:
        """Validate BSM signature (or session MAC tag) and ticket, then run the misbehaviour detector.

        The detector gets the flat dict of docs/interfaces.md, section 5:
        {"pid", "seq", "t", "x", "y", "speed", "heading", "rsu_x", "rsu_y", "rx_time", "sender"}
        and the earlier dicts of the same pseudonym (newest last). A pseudonym is
        reported once, after detector_k flagged messages out of its last detector_w,
        with a flagged signed anchor among them as evidence (see the class docstring).

        One result per call; a TESLA BSM still waiting for its key gives
        {"ok": False, "reason": "pending"} (receive_bsm returns every decided message)."""
        out = self.receive_bsm(message_bytes, rx_time, rsu_pos, sender)
        return out[0] if out else {"ok": False, "reason": "pending"}

    def receive_bsm(self, message_bytes: bytes, rx_time: float | None = None,
                    rsu_pos: tuple[float, float] | None = None, sender: Any = None,
                    rssi_d: tuple[float, float] | None = None) -> list[dict]:
        """BSM or TESLA_KEY in, every message decided by it out (in order). Signed and MAC
        BSMs are decided at once; TESLA BSMs when their key is disclosed (later call).
        ``rssi_d`` is this RSU's (distance estimate, sigma of its log) for the sender from received
        power, for the detector's signal-strength check."""
        self.ops = []
        self._rssi_d = rssi_d
        try:
            msg = Message.from_bytes(message_bytes)
        except Exception:
            return [{"ok": False, "reason": "malformed_bsm"}]
        try:
            if msg.type == "TESLA_KEY":
                return self._tesla_key(msg.fields, rx_time)
            if msg.type != "BSM":
                return [{"ok": False, "reason": "wrong_message_type"}]
            if "tm" in msg.fields:
                return self._tesla_bsm(msg.fields, message_bytes, rx_time, rsu_pos, sender)
            return self._signed_or_mac_bsm(msg.fields, message_bytes, rx_time, rsu_pos, sender)
        except Exception:
            return [{"ok": False, "reason": "malformed_bsm"}]

    def _ticket_of(self, payload: dict) -> tuple[dict | None, str | None, str]:
        """(ticket payload, digest, reject reason) of a BSM payload."""
        pid = str(payload.get("pid", ""))
        if "ticket_digest" in payload:
            digest = str(payload["ticket_digest"])
            ticket_payload = self._digest_tickets.get(digest)
            if ticket_payload is None:
                return None, digest, "unknown_ticket_digest"
            self._digest_tickets.move_to_end(digest)
        else:
            digest = None
            ticket_payload = self._ticket_ok(payload.get("ticket"))
            if ticket_payload is None:
                return None, None, "invalid_ticket_signature"
        if pid != str(ticket_payload.get("pid", "")):
            return None, digest, "ticket_pseudonym_mismatch"
        return ticket_payload, digest, ""

    def _signed_or_mac_bsm(self, fields: dict, message_bytes: bytes, rx_time, rsu_pos, sender) -> list[dict]:
        payload = fields["payload"]
        mac = "tags" in fields
        signature = None if mac else fields["signature"]
        if not isinstance(payload, dict) or (mac and "ticket_digest" not in payload):
            return [{"ok": False, "reason": "malformed_bsm"}]
        pid = str(payload.get("pid", ""))
        ticket_payload, digest, reason = self._ticket_of(payload)
        if ticket_payload is None:
            return [{"ok": False, "reason": reason, "pid": pid}]
        public_key = bytes.fromhex(ticket_payload["pk"])
        if mac:
            tags = fields["tags"]
            if not isinstance(tags, dict) or self.rsu_id not in tags:
                return [{"ok": False, "reason": "bsm_mac_not_for_rsu", "pid": pid}]
            key = self._mac_key(pid, digest, public_key)
            self.ops.append("hmac")
            if not bsm_tag_ok(key, canonical_json(payload), tags[self.rsu_id]):
                return [{"ok": False, "reason": "invalid_bsm_mac", "pid": pid}]
        else:
            check_sig = bip340_verify if isinstance(signature, str) else schnorr_verify
            self.ops.append("bsm_verify_one")
            if not check_sig(public_key, canonical_json(payload), signature):
                return [{"ok": False, "reason": "invalid_bsm_signature", "pid": pid}]
        if "ticket" in payload and "ticket_digest" not in payload:
            # signature checked under the ticket key: the ticket (explicit or implicit) is good
            self._remember_ticket(payload["ticket"], ticket_payload)
        item = (payload, ticket_payload, mac, message_bytes, rx_time, rsu_pos, sender, self._rssi_d)
        if self.tesla is None or mac or "ti" not in payload:
            return [self._after_auth(*item)]
        # TESLA mode, signed anchor: update the chain, then wait behind earlier pending BSMs
        digest = digest or ticket_digest(payload["ticket"])
        t0 = float(ticket_payload.get("issued_at", 0.0))
        released = []
        if "tc" in payload:
            released += self.tesla.anchor(pid, digest, t0, payload["tc"])
        released += self.tesla.receive_verified(pid, digest, t0, int(payload["ti"]), rx_time, item)
        return self._decide(released, pid)

    def _tesla_bsm(self, fields: dict, message_bytes: bytes, rx_time, rsu_pos, sender) -> list[dict]:
        payload = fields.get("payload")
        if self.tesla is None or not isinstance(payload, dict) or "ticket_digest" not in payload:
            return [{"ok": False, "reason": "malformed_bsm"}]
        pid = str(payload.get("pid", ""))
        ticket_payload, digest, reason = self._ticket_of(payload)
        if ticket_payload is None:
            return [{"ok": False, "reason": reason, "pid": pid}]
        self.ops.append("tesla")
        rx = rx_time if rx_time is not None else self.clock()
        item = (payload, ticket_payload, True, message_bytes, rx, rsu_pos, sender, self._rssi_d)
        status, released = self.tesla.receive(pid, digest, float(ticket_payload.get("issued_at", 0.0)),
                                              payload.get("ti"), fields.get("tm"), canonical_json(payload),
                                              fields.get("kd"), rx, item)
        out = [{"ok": False, "reason": status, "pid": pid}] if status != "buffered" else []
        return out + self._decide(released, pid)

    def _tesla_key(self, fields: dict, rx_time) -> list[dict]:
        """A standalone key disclosure (sent when no BSM would disclose the key in time)."""
        if self.tesla is None:
            return [{"ok": False, "reason": "malformed_bsm"}]
        pid, digest = str(fields.get("pid", "")), str(fields.get("ticket_digest", ""))
        ticket_payload = self._digest_tickets.get(digest)
        if ticket_payload is None or str(ticket_payload.get("pid", "")) != pid:
            return []
        self.ops.append("tesla")
        released = self.tesla.disclose(pid, digest, float(ticket_payload.get("issued_at", 0.0)),
                                       int(fields.get("j", 0)), fields.get("kd"),
                                       rx_time if rx_time is not None else self.clock())
        return self._decide(released, pid)

    def _decide(self, released: list, pid: str) -> list[dict]:
        out = []
        for item, ok, rx in released:
            if ok is None:
                out.append({"ok": False, "reason": "tesla_no_key", "pid": pid, "rx_time": rx})
            elif not ok:
                out.append({"ok": False, "reason": "invalid_tesla_mac", "pid": pid, "rx_time": rx})
            else:
                res = self._after_auth(*item)
                res["rx_time"] = rx
                out.append(res)
        return out

    def _after_auth(self, payload: dict, ticket_payload: dict, mac: bool, message_bytes: bytes,
                    rx_time, rsu_pos, sender, rssi_d: tuple[float, float] | None = None) -> dict:
        """Checks after the BSM is authentic: expiry, revocation, quarantine, anchor schedule,
        then the misbehaviour detector and the K-of-W reporting rule. ``mac`` covers every
        BSM that is not a signed anchor (session MAC or TESLA)."""
        pid = str(payload.get("pid", ""))
        try:
            now = self.clock()
            if float(ticket_payload.get("expiry", 0)) <= now or self.ledger.is_revoked(pid):
                return {"ok": False, "reason": "expired_or_revoked", "pid": pid}
            if self.quarantined(pid):
                return {"ok": False, "reason": "quarantined", "pid": pid}
            st = self._state(pid)
            if mac and st.mac_run >= self.mac_run_limit:
                return {"ok": False, "reason": "anchor_overdue", "pid": pid}
            if mac and self._anchor_needed(pid):
                return {"ok": False, "reason": "anchor_required", "pid": pid}
            st.mac_run = st.mac_run + 1 if mac else 0
            if "k" in payload:
                fields = unpack_kinematics(str(payload["k"]), rx_time if rx_time is not None else now)
                prev = self.bsm_history.get(pid)
                if prev and isinstance(prev[-1].get("seq"), int):
                    # serial-number arithmetic: the u16 seq continues from the last accepted one
                    last = prev[-1]["seq"]
                    fields["seq"] = last + ((fields["seq"] - last + 0x8000) & 0xFFFF) - 0x8000
                payload = {**payload, "fields": fields}

            # --- Misbehaviour Detector Integration Hook ---
            flagged, detector_features, reported = False, None, False
            evidence_hash, blocked = None, False
            if self.detector is not None:
                fields = payload.get("fields", {}) or {}
                rsu_x, rsu_y = rsu_pos if rsu_pos is not None else (None, None)
                # missing kinematics stay None: the detector then answers "error", not a flag
                t = next((fields[k] for k in ("t", "timestamp") if k in fields), None)
                bsm = {"pid": pid, "seq": fields.get("seq"), "t": t,
                       "x": fields.get("x"), "y": fields.get("y"),
                       "speed": fields.get("speed"), "heading": fields.get("heading", 0.0),
                       "rsu_x": rsu_x, "rsu_y": rsu_y,
                       "rx_time": rx_time if rx_time is not None else t, "sender": sender,
                       "rssi_d": rssi_d[0] if rssi_d else None, "rssi_sigma": rssi_d[1] if rssi_d else None}
                # the speed checks look 0.8-3 s back (up to 30 BSMs at 10 Hz); W is only the K-of-W window
                history = self.bsm_history.setdefault(pid, deque(maxlen=max(30, self.detector_w)))
                flags = self.bsm_flags.setdefault(pid, deque(maxlen=self.detector_w))
                check = self.detector.check if hasattr(self.detector, "check") else self.detector
                flagged, detector_features = check(bsm, list(history))
                if mac and st.anchors is None:
                    st.anchors = deque(history, maxlen=history.maxlen)   # so far every message was an anchor
                usable = _usable(detector_features)
                if (detector_features or {}).get("error"):
                    flagged = False
                anchor_flag = False
                if not mac and st.anchors is not None:
                    # evidence only from signed messages: judge the anchor against earlier anchors
                    anchor_flag, anchor_features = check(bsm, list(st.anchors))
                    if _usable(anchor_features):
                        st.anchors.append(bsm)
                    else:
                        anchor_flag = False
                elif not mac:
                    anchor_flag = flagged
                if usable:
                    history.append(bsm)
                    flags.append(bool(flagged))
                    st.evidence.append(hashlib.sha256(message_bytes).hexdigest() if anchor_flag else None)

                # Reporting rule: report a pseudonym after K flagged messages out of its last W,
                # with an anchor flagged on signed history alone in the window as evidence
                if pid not in self.reported and sum(flags) >= self.detector_k:
                    evidence_hash = next((h for h in reversed(st.evidence) if h), None)
                    if evidence_hash is not None:
                        self.reported.add(pid)
                        reported = True
                        self.ledger.report_misbehaviour(pid, evidence_hash)
                        if self.quarantine_k > 0:
                            blocked = self._add_reporter(pid, self.rsu_id)

            return {
                "ok": True,
                "reason": "valid_bsm",
                "pid": pid,
                "payload": payload,
                "flagged": bool(flagged),
                "features": detector_features,
                "reported": reported,
                "anchor": not mac,
                "evidence": evidence_hash if reported else None,
                "blocked": blocked,
            }
        except Exception:
            return {"ok": False, "reason": "malformed_bsm", "pid": pid}

    # ---------------------------------------------------------- quarantine
    def quarantined(self, pid: str) -> bool:
        """Provisionally blocked here (--fast-revocation) and not yet revoked on the ledger."""
        until = self.quarantine_until.get(pid)
        return until is not None and self.clock() < until and not self.ledger.is_revoked(pid)

    def _add_reporter(self, pid: str, reporter: str) -> bool:
        """Count a distinct reporter; True if this starts (or restarts) the block of pid."""
        seen = self.reporters.setdefault(pid, set())
        if reporter in seen:
            return False
        seen.add(reporter)
        # report weights from the ledger (--trust-weighted), 1.0 each otherwise: K-of-RSUs
        weight_of = getattr(self.ledger, "weight", None)
        total = sum(weight_of(r) for r in seen) if callable(weight_of) else len(seen)
        if total < self.quarantine_k - 1e-9:
            return False
        self.quarantine_until[pid] = self.clock() + self.quarantine_ttl
        return True

    def make_quarantine(self, pid: str, evidence: str) -> bytes:
        """Signed QUARANTINE note for the neighbours: this RSU reported ``pid`` with ``evidence``."""
        payload = {"pid": pid, "evidence": evidence, "reporter": self.rsu_id, "timestamp": float(self.clock())}
        sig = schnorr_sign(self.private_key, canonical_json(payload))
        return make_message("QUARANTINE", signature=sig, **payload).to_bytes()

    def receive_quarantine(self, note_bytes: bytes) -> dict:
        """Check a neighbour's QUARANTINE note (trusted reporter, signature, freshness) and
        count its reporter. ``blocked`` is True if the pid is blocked from now on."""
        try:
            msg = Message.from_bytes(note_bytes)
            if msg.type != "QUARANTINE":
                return {"ok": False, "reason": "wrong_message_type"}
            f = msg.fields
            payload = {k: f.get(k) for k in ("pid", "evidence", "reporter", "timestamp")}
            if not isinstance(payload["pid"], str) or not payload["pid"] or not isinstance(payload["evidence"], str):
                return {"ok": False, "reason": "malformed_quarantine"}
            key = self.trusted_rsu_keys.get(str(payload["reporter"]))
            if key is None:
                return {"ok": False, "reason": "untrusted_reporter"}
            if not schnorr_verify(key, canonical_json(payload), f.get("signature", {})):
                return {"ok": False, "reason": "invalid_quarantine_signature"}
            if abs(self.clock() - float(payload["timestamp"])) > self.freshness_seconds:
                return {"ok": False, "reason": "stale_quarantine"}
            pid = payload["pid"]
            blocked = self.quarantine_k > 0 and self._add_reporter(pid, str(payload["reporter"]))
            return {"ok": True, "reason": "quarantine_accepted", "pid": pid, "blocked": blocked}
        except Exception:
            return {"ok": False, "reason": "malformed_quarantine"}

    # ------------------------------------------------------- network hook
    def on_receive(self, node: Any, data: bytes, sim_time: float) -> dict[str, Any]:
        """Network node hook: called when bytes arrive over IEEE 802.11p radio.
        Replies go to the sender (node.last_sender) when known, else broadcast."""
        try:
            msg = Message.from_bytes(data)
        except Exception:
            return {"ok": False, "reason": "malformed_bytes"}

        reply_to = getattr(node, "last_sender", None)
        if reply_to is None:
            reply_to = "broadcast"
        result = {"ok": False}
        if msg.type == "AUTH_REQ":
            result = self.authenticate(data)
            if self.send_fn:
                resp = make_message("AUTH_RESP", ok=result["ok"], ticket=result.get("ticket"),
                                    reason=result["reason"], pid=result.get("pid"),
                                    rsu_id=self.rsu_id, handover=False)
                self.send_fn(node, reply_to, resp.to_bytes())
        elif msg.type == "HANDOVER_REQ":
            result = self.handover(data)
            if self.send_fn:
                resp = make_message("AUTH_RESP", ok=result["ok"], reason=result["reason"],
                                    pid=result.get("pid"), rsu_id=self.rsu_id, handover=True)
                self.send_fn(node, reply_to, resp.to_bytes())
        elif msg.type == "PREAUTH":
            result = self.receive_preauth(data)
        elif msg.type == "BSM":
            result = self.verify_bsm(data, rx_time=sim_time, sender=reply_to)

        return result
