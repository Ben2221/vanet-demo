"""RSU-side authentication, handover, and detector logic, independent of ns-3.

The ledger is anything with the interface of docs/interfaces.md, section 3
(``node.ledger`` in the simulator, ``MockLedger.view(rsu_id)`` in tests):
reads ``get_root``, ``get_policy``, ``get_auth``, ``is_revoked`` and writes
``record_auth``, ``report_misbehaviour``.

All times come from ``clock`` (default: wall clock; ``node.now`` in the simulator).
"""
from __future__ import annotations
import hashlib, secrets, time
from collections import deque
from typing import Callable, Any
from .crypto import verify_merkle, verify, schnorr_sign, schnorr_verify, SchnorrProof
from .messages import Message, make_message
from .registration import pseudonym_leaf
from .vehicle import auth_context, canonical_json

class RSU:
    def __init__(self, rsu_id: str, ledger: Any, private_key: int, public_key: bytes,
                 freshness_seconds: float = 5.0, ticket_seconds: float = 30.0,
                 trusted_rsu_keys: dict[str, bytes] | None = None,
                 detector: Any = None,
                 detector_k: int = 2,
                 detector_w: int = 10,
                 nonce_window: float = 1.0,
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

        # Misbehaviour detector hook: check(bsm, history) -> (flagged, features)
        self.detector = detector
        self.detector_k = detector_k
        self.detector_w = detector_w
        self.bsm_history: dict[str, deque[dict[str, Any]]] = {}
        self.bsm_flags: dict[str, deque[bool]] = {}
        self.reported: set[str] = set()

        # Node hooks (Network simulation node interface)
        self.send_fn = send_fn
        self.schedule_fn = schedule_fn

    # ------------------------------------------------------------- beacons
    def beacon(self) -> dict:
        now = self.clock()
        self.nonce = secrets.token_hex(16)
        self.beacon_timestamp = now
        self.recent_nonces[self.nonce] = now
        self._nonce_order.append(self.nonce)
        while self._nonce_order and now - self.recent_nonces[self._nonce_order[0]] > self.nonce_window:
            old = self._nonce_order.popleft()
            del self.recent_nonces[old]
            self.used_nonces = {u for u in self.used_nonces if u[0] != old}
        payload = {"rsu_id": self.rsu_id, "nonce": self.nonce, "timestamp": now}
        return {"payload": payload, "signature": schnorr_sign(self.private_key, canonical_json(payload)),
                "public_key": self.public_key.hex()}

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
        try:
            msg = Message.from_bytes(request_bytes)
        except Exception:
            return {"ok": False, "reason": "malformed_request"}
        if msg.type != "AUTH_REQ":
            return {"ok": False, "reason": "wrong_message_type"}
        f = msg.fields
        try:
            pid, pub = str(f["pid"]), bytes.fromhex(f["public_key"])
            epoch, nonce, ts = int(f["epoch"]), str(f["nonce"]), float(f["timestamp"])
            service, vclass, requested_rsu = str(f["service"]), str(f["vehicle_class"]), str(f["rsu_id"])
            path = [(str(x[0]), str(x[1])) for x in f["merkle_path"]]
            proof = SchnorrProof.from_dict(f["proof"])
        except Exception:
            return {"ok": False, "reason": "malformed_request"}
        fail = lambda reason: {"ok": False, "reason": reason, "pid": pid}
        now = self.clock()
        if requested_rsu != self.rsu_id or nonce not in self.recent_nonces or (nonce, pid) in self.used_nonces:
            return fail("invalid_or_replayed_nonce")
        if ts != self.recent_nonces[nonce] or abs(now - ts) > self.freshness_seconds:
            return fail("stale_request")
        root_hex = self._root_hex(epoch, now)
        if root_hex is None:
            return fail("unknown_or_expired_epoch")
        # The leaf binds pid, key and class: a wrong class or a borrowed pid fails here.
        try:
            if not verify_merkle(pseudonym_leaf(pid, pub, vclass), path, bytes.fromhex(root_hex)):
                return fail("not_registered")
        except Exception:
            return fail("not_registered")
        ctx = auth_context(self.rsu_id, nonce, ts, service, pid, vclass)
        if not verify(pub, proof, ctx):
            return fail("invalid_proof")
        if self.ledger.is_revoked(pid):
            return fail("revoked")
        if vclass not in (self.ledger.get_policy(service) or []):
            return fail("policy_denied")
        self.used_nonces.add((nonce, pid))
        expiry = now + self.ticket_seconds
        payload = {"pid": pid, "pk": pub.hex(), "service": service, "class": vclass,
                   "issuer": self.rsu_id, "issued_at": now, "expiry": expiry}
        ticket = {"payload": payload, "signature": schnorr_sign(self.private_key, canonical_json(payload))}
        self.ledger.record_auth(pid, service, vclass, expiry)
        return {"ok": True, "ticket": ticket, "reason": "authenticated", "pid": pid}

    def _ticket_ok(self, ticket: Any) -> dict | None:
        """Payload of a ticket signed by a trusted RSU, or None."""
        if not isinstance(ticket, dict):
            return None
        payload, signature = ticket.get("payload"), ticket.get("signature")
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            return None
        key = f"{signature.get('R')}{signature.get('s')}"
        if key in self._good_tickets:
            return payload if canonical_json(payload) == self._good_tickets[key] else None
        issuer_key = self.trusted_rsu_keys.get(str(payload.get("issuer", "")))
        if issuer_key is None or not schnorr_verify(issuer_key, canonical_json(payload), signature):
            return None
        if len(self._good_tickets) > 5000:
            self._good_tickets.clear()
        self._good_tickets[key] = canonical_json(payload)
        return payload

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
            return {"ok": True, "reason": "preauth_accepted", "pid": pid}
        except Exception:
            return {"ok": False, "reason": "malformed_preauth"}

    def handover(self, request_bytes: bytes) -> dict:
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
            if self._ticket_ok(ticket) is None:
                return fail("invalid_ticket_signature")
            now = self.clock()
            if float(payload["expiry"]) <= now or float(payload["issued_at"]) > now + 1:
                return fail("expired_or_invalid_ticket")
            # proof of possession: the request is signed by the ticket's pseudonym key
            request = {"ticket": ticket, "next_rsu_id": f.get("next_rsu_id"),
                       "nonce": f.get("nonce", ""), "timestamp": f.get("timestamp")}
            if not schnorr_verify(bytes.fromhex(payload["pk"]), canonical_json(request), f.get("signature", {})):
                return fail("invalid_request_signature")
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
            return {"ok": True, "reason": "handover_accepted", "pid": pid, "via": via}
        except Exception:
            return fail("malformed_ticket")

    # ----------------------------------------------------------------- BSM
    def verify_bsm(self, message_bytes: bytes, rx_time: float | None = None,
                   rsu_pos: tuple[float, float] | None = None, sender: Any = None) -> dict:
        """Validate BSM signature and ticket, then run the misbehaviour detector.

        The detector gets the flat dict of docs/interfaces.md, section 5:
        {"pid", "seq", "t", "x", "y", "speed", "heading", "rsu_x", "rsu_y", "rx_time", "sender"}
        and the earlier dicts of the same pseudonym (newest last). A pseudonym is
        reported once, after detector_k flagged messages out of its last detector_w."""
        try:
            msg = Message.from_bytes(message_bytes)
            if msg.type != "BSM":
                return {"ok": False, "reason": "wrong_message_type"}
            payload = msg.fields["payload"]
            signature = msg.fields["signature"]
            if not isinstance(payload, dict):
                return {"ok": False, "reason": "malformed_bsm"}
            pid = str(payload.get("pid", ""))
            ticket_payload = self._ticket_ok(payload.get("ticket"))
            if ticket_payload is None:
                return {"ok": False, "reason": "invalid_ticket_signature", "pid": pid}
            if pid != str(ticket_payload.get("pid", "")):
                return {"ok": False, "reason": "ticket_pseudonym_mismatch", "pid": pid}
            public_key = bytes.fromhex(ticket_payload["pk"])
            if not schnorr_verify(public_key, canonical_json(payload), signature):
                return {"ok": False, "reason": "invalid_bsm_signature", "pid": pid}
            now = self.clock()
            if float(ticket_payload.get("expiry", 0)) <= now or self.ledger.is_revoked(pid):
                return {"ok": False, "reason": "expired_or_revoked", "pid": pid}

            # --- Misbehaviour Detector Integration Hook ---
            flagged, detector_features, reported = False, None, False
            if self.detector is not None:
                fields = payload.get("fields", {}) or {}
                rsu_x, rsu_y = rsu_pos if rsu_pos is not None else (None, None)
                # missing kinematics stay None: the detector then answers "error", not a flag
                t = next((fields[k] for k in ("t", "timestamp") if k in fields), None)
                bsm = {"pid": pid, "seq": fields.get("seq"), "t": t,
                       "x": fields.get("x"), "y": fields.get("y"),
                       "speed": fields.get("speed"), "heading": fields.get("heading", 0.0),
                       "rsu_x": rsu_x, "rsu_y": rsu_y,
                       "rx_time": rx_time if rx_time is not None else t, "sender": sender}
                # the speed checks look 0.8-3 s back (up to 30 BSMs at 10 Hz); W is only the K-of-W window
                history = self.bsm_history.setdefault(pid, deque(maxlen=max(30, self.detector_w)))
                flags = self.bsm_flags.setdefault(pid, deque(maxlen=self.detector_w))
                check = self.detector.check if hasattr(self.detector, "check") else self.detector
                flagged, detector_features = check(bsm, list(history))
                if (detector_features or {}).get("error"):
                    flagged = False
                elif (detector_features or {}).get("foreign"):
                    pass        # a copy sent by someone else: not the owner's history, not their window
                else:
                    history.append(bsm)
                    flags.append(bool(flagged))

                # Reporting rule: report a pseudonym after K flagged messages out of its last W
                if sum(flags) >= self.detector_k and pid not in self.reported:
                    self.reported.add(pid)
                    reported = True
                    evidence_hash = hashlib.sha256(message_bytes).hexdigest()
                    self.ledger.report_misbehaviour(pid, evidence_hash)

            return {
                "ok": True,
                "reason": "valid_bsm",
                "pid": pid,
                "payload": payload,
                "flagged": bool(flagged),
                "features": detector_features,
                "reported": reported,
            }
        except Exception:
            return {"ok": False, "reason": "malformed_bsm"}

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
