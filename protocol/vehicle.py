"""Vehicle-side protocol logic, independent of ns-3."""
from __future__ import annotations
import json, time
from typing import Callable, Any
from .crypto import prove, schnorr_sign, schnorr_verify, CommitmentPool
from .messages import make_message, Message
from .registration import Pseudonym

def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def auth_context(rsu_id: str, nonce: str, timestamp: float, service: str,
                 pid: str, vehicle_class: str) -> bytes:
    fields = [b"VANET-AUTH-v1", rsu_id.encode(), nonce.encode(),
              format(float(timestamp), ".6f").encode(), service.encode(), pid.encode(),
              vehicle_class.encode()]
    return b"".join(len(item).to_bytes(4, "big") + item for item in fields)

class Vehicle:
    def __init__(self, pseudonyms: list[Pseudonym], vehicle_class: str = "car",
                 trusted_rsu_keys: dict[str, bytes] | None = None, freshness_seconds: float = 5.0,
                 pseudonym_switch_after: int = 3,
                 send_fn: Callable[[Any, str, bytes], None] | None = None,
                 schedule_fn: Callable[[float, Callable], None] | None = None):
        if not pseudonyms:
            raise ValueError("vehicle needs at least one pseudonym")
        self.pseudonyms = pseudonyms
        self.vehicle_class = vehicle_class
        self.session_count = 0
        self.ticket = None
        self.trusted_rsu_keys = trusted_rsu_keys or {}
        self.freshness_seconds = freshness_seconds
        if pseudonym_switch_after < 1:
            raise ValueError("pseudonym_switch_after must be positive")
        self.pseudonym_switch_after = pseudonym_switch_after
        # Pool of precomputed commitments (g^r computed while idle)
        self.commitment_pool = CommitmentPool(initial_size=5)
        # Node hooks (Network simulation node interface)
        self.send_fn = send_fn
        self.schedule_fn = schedule_fn
        self.current_rsu_id: str | None = None

    @property
    def current(self) -> Pseudonym:
        index = (self.session_count // self.pseudonym_switch_after) % len(self.pseudonyms)
        return self.pseudonyms[index]

    def verify_beacon(self, beacon: dict) -> bool:
        try:
            payload = beacon["payload"]
            rsu_id = str(payload["rsu_id"])
            trusted_key = self.trusted_rsu_keys.get(rsu_id)
            if trusted_key is None or bytes.fromhex(beacon["public_key"]) != trusted_key:
                return False
            ts = float(payload["timestamp"])
            if abs(time.time() - ts) > self.freshness_seconds:
                return False
            return schnorr_verify(trusted_key, canonical_json(payload), beacon["signature"])
        except Exception:
            return False

    def make_auth_request(self, beacon: dict, service: str) -> bytes:
        if not self.verify_beacon(beacon):
            raise ValueError("untrusted, invalid, or stale RSU beacon")
        p = self.current
        if p.merkle_path is None:
            raise RuntimeError("pseudonym has not been registered")
        b = beacon["payload"]
        ctx = auth_context(b["rsu_id"], b["nonce"], b["timestamp"], service, p.pid, self.vehicle_class)
        # Use precomputed commitment from pool (zero-knowledge, non-reused r)
        commitment = self.commitment_pool.pop()
        proof = prove(p.secret, ctx, commitment=commitment)
        self.current_rsu_id = b["rsu_id"]
        return make_message("AUTH_REQ", pid=p.pid, public_key=p.public_key.hex(),
                            epoch=p.epoch, merkle_path=p.merkle_path, proof=proof.to_dict(),
                            service=service, vehicle_class=self.vehicle_class,
                            timestamp=b["timestamp"], nonce=b["nonce"], rsu_id=b["rsu_id"]).to_bytes()

    def accept_ticket(self, ticket: dict, rsu_public_key: bytes) -> bool:
        try:
            payload, signature = ticket["payload"], ticket["signature"]
            if not isinstance(payload, dict) or not isinstance(signature, dict):
                return False
            if float(payload["expiry"]) <= time.time() or float(payload["issued_at"]) > time.time() + 1:
                return False
            if not schnorr_verify(rsu_public_key, canonical_json(payload), signature):
                return False
            self.ticket = ticket
            self.session_count += 1
            return True
        except Exception:
            return False

    def make_bsm(self, **safety_fields) -> bytes:
        """Create a signed BSM carrying the current pseudonym and current ticket."""
        p = self.current
        if self.ticket is None:
            raise RuntimeError("cannot send authenticated BSM without a ticket")
        payload = {"pid": p.pid, "fields": safety_fields, "ticket": self.ticket}
        signature = schnorr_sign(p.secret, canonical_json(payload))
        return make_message("BSM", payload=payload, signature=signature,
                            public_key=p.public_key.hex()).to_bytes()

    def make_handover_request(self, next_rsu_id: str) -> bytes:
        if self.ticket is None:
            raise RuntimeError("no authorization ticket to hand over")
        return make_message("HANDOVER_REQ", ticket=self.ticket, next_rsu_id=next_rsu_id).to_bytes()

    def make_before_break_handover(self, next_rsu_id: str, next_rsu_beacon: dict | None = None) -> bytes:
        """Make-before-break handover: request handover with next RSU while still covered by current RSU."""
        if next_rsu_beacon is not None and not self.verify_beacon(next_rsu_beacon):
            raise ValueError("untrusted or invalid target RSU beacon for make-before-break handover")
        return self.make_handover_request(next_rsu_id)

    def on_receive(self, node: Any, data: bytes, sim_time: float) -> dict[str, Any] | None:
        """Network node hook: called when bytes arrive over radio."""
        try:
            msg = Message.from_bytes(data)
        except Exception:
            return None

        if msg.type == "AUTH_RESP":
            f = msg.fields
            if f.get("ok") and "ticket" in f:
                issuer = f["ticket"].get("payload", {}).get("issuer")
                issuer_key = self.trusted_rsu_keys.get(issuer)
                if issuer_key:
                    self.accept_ticket(f["ticket"], issuer_key)
            return f
        return None
