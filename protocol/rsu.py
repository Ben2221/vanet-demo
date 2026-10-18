"""RSU-side authentication, handover, and detector logic, independent of ns-3."""
from __future__ import annotations
import hashlib, json, secrets, time
from typing import Callable, Any
from .crypto import verify_merkle, verify, schnorr_sign, schnorr_verify
from .messages import Message, make_message
from .vehicle import auth_context, canonical_json

class RSU:
    def __init__(self, rsu_id: str, ledger: Any, private_key: int, public_key: bytes,
                 freshness_seconds: float = 5.0, ticket_seconds: float = 30.0,
                 trusted_rsu_keys: dict[str, bytes] | None = None,
                 detector: Any = None,
                 detector_k: int = 2,
                 detector_w: int = 10,
                 send_fn: Callable[[Any, str, bytes], None] | None = None,
                 schedule_fn: Callable[[float, Callable], None] | None = None):
        self.rsu_id, self.ledger = rsu_id, ledger
        self.private_key, self.public_key = private_key, public_key
        self.freshness_seconds, self.ticket_seconds = freshness_seconds, ticket_seconds
        self.trusted_rsu_keys = trusted_rsu_keys or {rsu_id: public_key}
        self.nonce: str | None = None
        self.beacon_timestamp: float | None = None
        self.used_nonces: set[str] = set()

        # Backbone pre-authorization cache (so handovers work before ledger commit propagates)
        self.preauth_cache: dict[str, dict[str, Any]] = {}

        # Misbehaviour detector hook: check(bsm, history) -> (flagged, features)
        self.detector = detector
        self.detector_k = detector_k
        self.detector_w = detector_w
        self.bsm_history: dict[str, list[dict[str, Any]]] = {}
        self.bsm_flags: dict[str, list[bool]] = {}

        # Node hooks (Network simulation node interface)
        self.send_fn = send_fn
        self.schedule_fn = schedule_fn

    def beacon(self) -> dict:
        self.nonce = secrets.token_hex(16)
        self.beacon_timestamp = time.time()
        payload = {"rsu_id": self.rsu_id, "nonce": self.nonce, "timestamp": self.beacon_timestamp}
        return {"payload": payload, "signature": schnorr_sign(self.private_key, canonical_json(payload)),
                "rsu_id": self.rsu_id, "nonce": self.nonce, "timestamp": self.beacon_timestamp,
                "public_key": self.public_key.hex()}

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
            proof_data = f["proof"]
            path = [(str(x[0]), str(x[1])) for x in f["merkle_path"]]
            from .crypto import SchnorrProof
            proof = SchnorrProof.from_dict(proof_data)
        except Exception:
            return {"ok": False, "reason": "malformed_request"}
        now = time.time()
        if requested_rsu != self.rsu_id or nonce != self.nonce or nonce in self.used_nonces:
            return {"ok": False, "reason": "invalid_or_replayed_nonce"}
        if abs(now - ts) > self.freshness_seconds or self.beacon_timestamp is None:
            return {"ok": False, "reason": "stale_request"}
        if not hasattr(self.ledger, "root_valid") or not self.ledger.root_valid(epoch, now):
            return {"ok": False, "reason": "unknown_or_expired_epoch"}
        try:
            root_hex = self.ledger.get_root(epoch)
            if not verify_merkle(pub, path, bytes.fromhex(root_hex)):
                return {"ok": False, "reason": "not_registered"}
        except Exception:
            return {"ok": False, "reason": "not_registered"}
        expected_class = self.ledger.vehicle_class(pid) if hasattr(self.ledger, "vehicle_class") else None
        if expected_class is None or vclass != expected_class:
            return {"ok": False, "reason": "class_not_authorized"}
        ctx = auth_context(self.rsu_id, nonce, ts, service, pid, vclass)
        if not verify(pub, proof, ctx):
            return {"ok": False, "reason": "invalid_proof"}
        if self.ledger.is_revoked(pid):
            return {"ok": False, "reason": "revoked"}
        if not self.ledger.allowed(service, vclass):
            return {"ok": False, "reason": "policy_denied"}
        self.used_nonces.add(nonce)
        expiry = now + self.ticket_seconds
        payload = {"pid": pid, "service": service, "class": vclass, "issuer": self.rsu_id,
                   "issued_at": now, "expiry": expiry}
        ticket = {"payload": payload, "signature": schnorr_sign(self.private_key, canonical_json(payload))}
        self.ledger.record_auth(pid, service, vclass, expiry)
        return {"ok": True, "ticket": ticket, "reason": "authenticated"}

    def preauthorize_neighbour(self, next_rsu_id: str, ticket: dict) -> bytes:
        """Pre-authorization over RSU backbone: send signed note to neighbour RSU."""
        payload = {
            "ticket": ticket,
            "source_rsu": self.rsu_id,
            "target_rsu": next_rsu_id,
            "timestamp": time.time()
        }
        sig = schnorr_sign(self.private_key, canonical_json(payload))
        return make_message("PREAUTH", ticket=ticket, source_rsu=self.rsu_id,
                            target_rsu=next_rsu_id, timestamp=payload["timestamp"],
                            signature=sig).to_bytes()

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

            ticket_payload = f["ticket"].get("payload", {})
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
        ticket = msg.fields.get("ticket", {})
        payload = ticket.get("payload", {}) if isinstance(ticket, dict) else {}
        signature = ticket.get("signature", {}) if isinstance(ticket, dict) else {}
        if msg.fields.get("next_rsu_id") != self.rsu_id:
            return {"ok": False, "reason": "wrong_destination"}
        try:
            issuer = str(payload["issuer"])
            issuer_key = self.trusted_rsu_keys.get(issuer)
            if issuer_key is None or not schnorr_verify(issuer_key, canonical_json(payload), signature):
                return {"ok": False, "reason": "invalid_ticket_signature"}
            if float(payload["expiry"]) <= time.time() or float(payload["issued_at"]) > time.time() + 1:
                return {"ok": False, "reason": "expired_or_invalid_ticket"}
            pid = str(payload["pid"])

            # Check shared authorization on ledger or in backbone preauth cache
            auth = self.ledger.get_auth(pid) if hasattr(self.ledger, "get_auth") else None
            if not auth or auth.get("expiry", 0) <= time.time():
                # Fall back to preauth cache over backbone
                auth = self.preauth_cache.get(pid)
            if not auth or auth.get("expiry", 0) <= time.time():
                return {"ok": False, "reason": "missing_shared_authorization"}
            if auth.get("service") != payload.get("service") or auth.get("class") != payload.get("class"):
                return {"ok": False, "reason": "authorization_mismatch"}
            if self.ledger.is_revoked(pid):
                return {"ok": False, "reason": "revoked"}
            return {"ok": True, "reason": "handover_accepted"}
        except Exception:
            return {"ok": False, "reason": "malformed_ticket"}

    def verify_bsm(self, message_bytes: bytes) -> dict:
        """Validate BSM signature, ticket, and run misbehaviour detector hook."""
        try:
            msg = Message.from_bytes(message_bytes)
            if msg.type != "BSM":
                return {"ok": False, "reason": "wrong_message_type"}
            payload = msg.fields["payload"]
            public_key = bytes.fromhex(msg.fields["public_key"])
            signature = msg.fields["signature"]
            if not isinstance(payload, dict) or not schnorr_verify(public_key, canonical_json(payload), signature):
                return {"ok": False, "reason": "invalid_bsm_signature"}
            ticket = payload.get("ticket", {})
            ticket_payload = ticket.get("payload", {})
            issuer = str(ticket_payload.get("issuer", ""))
            issuer_key = self.trusted_rsu_keys.get(issuer)
            if issuer_key is None or not schnorr_verify(issuer_key, canonical_json(ticket_payload), ticket.get("signature", {})):
                return {"ok": False, "reason": "invalid_ticket_signature"}
            pid = str(payload.get("pid", ""))
            if pid != str(ticket_payload.get("pid", "")):
                return {"ok": False, "reason": "ticket_pseudonym_mismatch"}
            if float(ticket_payload.get("expiry", 0)) <= time.time() or self.ledger.is_revoked(pid):
                return {"ok": False, "reason": "expired_or_revoked"}

            # --- Misbehaviour Detector Integration Hook ---
            flagged = False
            detector_features = None
            if self.detector is not None:
                history = self.bsm_history.get(pid, [])
                if hasattr(self.detector, "check"):
                    flagged, detector_features = self.detector.check(payload, history)
                elif callable(self.detector):
                    flagged, detector_features = self.detector(payload, history)

                # Record in history window
                if pid not in self.bsm_history:
                    self.bsm_history[pid] = []
                    self.bsm_flags[pid] = []
                self.bsm_history[pid].append(payload)
                self.bsm_flags[pid].append(bool(flagged))
                # Keep last W
                if len(self.bsm_history[pid]) > self.detector_w:
                    self.bsm_history[pid].pop(0)
                    self.bsm_flags[pid].pop(0)

                # Reporting rule: report a pseudonym after K flagged messages out of its last W
                recent_flags = self.bsm_flags[pid]
                if sum(recent_flags) >= self.detector_k:
                    evidence_hash = hashlib.sha256(canonical_json(payload)).hexdigest()
                    if hasattr(self.ledger, "report_misbehaviour"):
                        self.ledger.report_misbehaviour(pid, evidence_hash, reporter_rsu=self.rsu_id)

            return {
                "ok": True,
                "reason": "valid_bsm",
                "payload": payload,
                "flagged": flagged,
                "features": detector_features
            }
        except Exception:
            return {"ok": False, "reason": "malformed_bsm"}

    def on_receive(self, node: Any, data: bytes, sim_time: float) -> dict[str, Any]:
        """Network node hook: called when bytes arrive over IEEE 802.11p radio."""
        try:
            msg = Message.from_bytes(data)
        except Exception:
            return {"ok": False, "reason": "malformed_bytes"}

        result = {"ok": False}
        if msg.type == "AUTH_REQ":
            result = self.authenticate(data)
            if self.send_fn and "ticket" in result:
                resp = make_message("AUTH_RESP", ok=result["ok"], ticket=result.get("ticket"), reason=result["reason"])
                self.send_fn(node, "broadcast", resp.to_bytes())
        elif msg.type == "HANDOVER_REQ":
            result = self.handover(data)
            if self.send_fn:
                resp = make_message("AUTH_RESP", ok=result["ok"], reason=result["reason"])
                self.send_fn(node, "broadcast", resp.to_bytes())
        elif msg.type == "PREAUTH":
            result = self.receive_preauth(data)
        elif msg.type == "BSM":
            result = self.verify_bsm(data)

        return result
