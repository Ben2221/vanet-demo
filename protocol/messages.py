"""Validated deterministic JSON wire messages for the VANET Cryptography and Authentication Protocol.

Specifications & Documented Sizes (IEEE 802.11p ns-3 packet payload):
- BEACON: ~280-350 bytes (RSU ID, fresh nonce, 64-bit timestamp, Schnorr signature R+s, RSU compressed pubkey)
- AUTH_REQ: ~480-600 bytes (Pseudonym ID, compressed pubkey, epoch, Merkle path, Schnorr ZKP commitment+response, service, class, nonce, ts, rsu_id)
- AUTH_RESP: ~320-400 bytes (Status ok, signed ticket containing pid, service, class, issuer, expiry, and RSU signature)
- HANDOVER_REQ: ~350-450 bytes (Signed ticket from previous RSU, destination RSU ID)
- PREAUTH: ~380-480 bytes (RSU-to-RSU backbone notification with ticket, sender RSU signature, target RSU)
- BSM: ~350-500 bytes (Safety payload: position x/y/z, speed, heading, timestamp, ticket, vehicle signature, vehicle pubkey)
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any

SUPPORTED_TYPES = {"BEACON", "AUTH_REQ", "AUTH_RESP", "HANDOVER_REQ", "PREAUTH", "BSM"}
MAX_MESSAGE_BYTES = 1_000_000

@dataclass
class Message:
    type: str
    fields: dict[str, Any]

    def to_bytes(self) -> bytes:
        if self.type not in SUPPORTED_TYPES:
            raise ValueError(f"unsupported message type: {self.type}")
        if not isinstance(self.fields, dict):
            raise ValueError("message fields must be an object")
        raw = json.dumps({"version": 1, "type": self.type, "fields": self.fields},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("message too large")
        return raw

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_MESSAGE_BYTES:
            raise ValueError("invalid or oversized message")
        obj = json.loads(bytes(data).decode("utf-8"))
        if not isinstance(obj, dict) or obj.get("version") != 1:
            raise ValueError("invalid message envelope or version")
        if obj.get("type") not in SUPPORTED_TYPES or not isinstance(obj.get("fields"), dict):
            raise ValueError("invalid message type or fields")
        return cls(obj["type"], obj["fields"])

def make_message(message_type: str, **fields) -> Message:
    return Message(message_type, fields)

# --- Typed Message Classes with to_bytes() and from_bytes() ---

@dataclass
class BeaconMessage:
    type: str = "BEACON"
    payload: dict[str, Any] = None
    signature: dict[str, str] = None
    rsu_id: str = ""
    nonce: str = ""
    timestamp: float = 0.0
    public_key: str = ""

    def to_bytes(self) -> bytes:
        fields = {
            "payload": self.payload or {"rsu_id": self.rsu_id, "nonce": self.nonce, "timestamp": self.timestamp},
            "signature": self.signature or {},
            "rsu_id": self.rsu_id,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "public_key": self.public_key
        }
        return Message("BEACON", fields).to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "BeaconMessage":
        msg = Message.from_bytes(data)
        if msg.type != "BEACON":
            raise ValueError(f"expected BEACON, got {msg.type}")
        f = msg.fields
        return cls(
            payload=f.get("payload"),
            signature=f.get("signature"),
            rsu_id=f.get("rsu_id", ""),
            nonce=f.get("nonce", ""),
            timestamp=float(f.get("timestamp", 0.0)),
            public_key=f.get("public_key", "")
        )

@dataclass
class AuthReqMessage:
    type: str = "AUTH_REQ"
    pid: str = ""
    public_key: str = ""
    epoch: int = 1
    merkle_path: list = None
    proof: dict = None
    service: str = ""
    vehicle_class: str = ""
    timestamp: float = 0.0
    nonce: str = ""
    rsu_id: str = ""

    def to_bytes(self) -> bytes:
        fields = {
            "pid": self.pid,
            "public_key": self.public_key,
            "epoch": self.epoch,
            "merkle_path": self.merkle_path or [],
            "proof": self.proof or {},
            "service": self.service,
            "vehicle_class": self.vehicle_class,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "rsu_id": self.rsu_id
        }
        return Message("AUTH_REQ", fields).to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "AuthReqMessage":
        msg = Message.from_bytes(data)
        if msg.type != "AUTH_REQ":
            raise ValueError(f"expected AUTH_REQ, got {msg.type}")
        f = msg.fields
        return cls(
            pid=f.get("pid", ""),
            public_key=f.get("public_key", ""),
            epoch=int(f.get("epoch", 1)),
            merkle_path=f.get("merkle_path", []),
            proof=f.get("proof", {}),
            service=f.get("service", ""),
            vehicle_class=f.get("vehicle_class", ""),
            timestamp=float(f.get("timestamp", 0.0)),
            nonce=f.get("nonce", ""),
            rsu_id=f.get("rsu_id", "")
        )

@dataclass
class AuthRespMessage:
    type: str = "AUTH_RESP"
    ok: bool = False
    ticket: dict[str, Any] = None
    reason: str = ""

    def to_bytes(self) -> bytes:
        fields = {"ok": self.ok, "ticket": self.ticket or {}, "reason": self.reason}
        return Message("AUTH_RESP", fields).to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "AuthRespMessage":
        msg = Message.from_bytes(data)
        if msg.type != "AUTH_RESP":
            raise ValueError(f"expected AUTH_RESP, got {msg.type}")
        return cls(ok=msg.fields.get("ok", False), ticket=msg.fields.get("ticket"), reason=msg.fields.get("reason", ""))

@dataclass
class HandoverReqMessage:
    type: str = "HANDOVER_REQ"
    ticket: dict[str, Any] = None
    next_rsu_id: str = ""

    def to_bytes(self) -> bytes:
        fields = {"ticket": self.ticket or {}, "next_rsu_id": self.next_rsu_id}
        return Message("HANDOVER_REQ", fields).to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "HandoverReqMessage":
        msg = Message.from_bytes(data)
        if msg.type != "HANDOVER_REQ":
            raise ValueError(f"expected HANDOVER_REQ, got {msg.type}")
        return cls(ticket=msg.fields.get("ticket"), next_rsu_id=msg.fields.get("next_rsu_id", ""))

@dataclass
class PreauthMessage:
    type: str = "PREAUTH"
    ticket: dict[str, Any] = None
    source_rsu: str = ""
    target_rsu: str = ""
    timestamp: float = 0.0
    signature: dict[str, str] = None

    def to_bytes(self) -> bytes:
        fields = {
            "ticket": self.ticket or {},
            "source_rsu": self.source_rsu,
            "target_rsu": self.target_rsu,
            "timestamp": self.timestamp,
            "signature": self.signature or {}
        }
        return Message("PREAUTH", fields).to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "PreauthMessage":
        msg = Message.from_bytes(data)
        if msg.type != "PREAUTH":
            raise ValueError(f"expected PREAUTH, got {msg.type}")
        f = msg.fields
        return cls(
            ticket=f.get("ticket"),
            source_rsu=f.get("source_rsu", ""),
            target_rsu=f.get("target_rsu", ""),
            timestamp=float(f.get("timestamp", 0.0)),
            signature=f.get("signature")
        )

@dataclass
class BsmMessage:
    type: str = "BSM"
    payload: dict[str, Any] = None
    signature: dict[str, str] = None
    public_key: str = ""

    def to_bytes(self) -> bytes:
        fields = {
            "payload": self.payload or {},
            "signature": self.signature or {},
            "public_key": self.public_key
        }
        return Message("BSM", fields).to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "BsmMessage":
        msg = Message.from_bytes(data)
        if msg.type != "BSM":
            raise ValueError(f"expected BSM, got {msg.type}")
        f = msg.fields
        return cls(payload=f.get("payload"), signature=f.get("signature"), public_key=f.get("public_key", ""))
