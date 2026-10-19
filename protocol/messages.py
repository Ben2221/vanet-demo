"""Compact binary wire messages for the VANET Cryptography and Authentication Protocol.

Wire format (docs/interfaces.md, section 2):

    [type: u8] [version: u8] [fields: tagged value]

The first byte is the message type (1 BEACON, 2 AUTH_REQ, 3 AUTH_RESP,
4 HANDOVER_REQ, 5 PREAUTH, 6 BSM), so the network can classify packets
without parsing them. Fields are a self-describing binary encoding of the same
dict the protocol code works with. Lowercase hex strings (keys, signatures,
hashes, nonces) are carried as raw bytes and common field names and values
are one-byte references, so a message is 40-60 % of the size of the JSON form.
Signatures are still computed over canonical JSON of the payload, which the
decoder reproduces exactly.

Typical sizes in bytes (UDP payload in ns-3), 500 pseudonyms per epoch
(Merkle depth 9; each extra level adds 36 bytes to AUTH_REQ):
- BEACON:       ~160 (RSU id, 16-byte nonce, timestamp, Schnorr signature R+s, RSU public key)
- AUTH_REQ:     ~530 (pid, public key, epoch, Merkle path, Schnorr proof, service, class, nonce, ts, rsu id)
- AUTH_RESP:    ~210 (status, signed ticket: pid, public key, service, class, issuer, issued/expiry)
- HANDOVER_REQ: ~290 (ticket, target RSU, beacon nonce, timestamp, pseudonym signature)
- PREAUTH:      ~280 (ticket, source/target RSU, timestamp, RSU signature)
- BSM:          ~330 (seq, t, x, y, speed, heading, ticket, pseudonym signature)
"""
from __future__ import annotations
import re
import struct
from dataclasses import dataclass
from typing import Any

TYPE_CODES = {"BEACON": 1, "AUTH_REQ": 2, "AUTH_RESP": 3, "HANDOVER_REQ": 4, "PREAUTH": 5, "BSM": 6}
TYPE_NAMES = {v: k for k, v in TYPE_CODES.items()}
SUPPORTED_TYPES = set(TYPE_CODES)
WIRE_VERSION = 1
MAX_MESSAGE_BYTES = 1_000_000
MAX_DEPTH = 16

# Interned strings: field names and common values sent as one byte.
# Append only: changing an index changes the wire format.
INTERNED = [
    "payload", "signature", "public_key", "rsu_id", "nonce", "timestamp", "pid", "epoch",
    "merkle_path", "proof", "commitment", "response", "service", "vehicle_class", "ok", "ticket",
    "reason", "next_rsu_id", "source_rsu", "target_rsu", "fields", "issuer", "issued_at", "expiry",
    "class", "pk", "R", "s", "left", "right", "car", "truck", "emergency", "road_access",
    "seq", "t", "x", "y", "speed", "heading", "handover", "authenticated", "handover_accepted",
    "revoked", "policy_denied", "not_registered", "invalid_proof", "stale_request",
    "invalid_or_replayed_nonce", "unknown_or_expired_epoch", "missing_shared_authorization",
]
_INTERN_INDEX = {s: i for i, s in enumerate(INTERNED)}
_HEX = re.compile(r"^(?:[0-9a-f]{2})+$")

T_NONE, T_FALSE, T_TRUE, T_INT, T_FLOAT, T_STR, T_HEX, T_LIST, T_DICT, T_INTERN = range(10)
_F64 = struct.Struct("!d")


def _varint(n: int, out: bytearray) -> None:
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return


def _encode(value: Any, out: bytearray, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("message nested too deeply")
    if value is None:
        out.append(T_NONE)
    elif value is True:
        out.append(T_TRUE)
    elif value is False:
        out.append(T_FALSE)
    elif isinstance(value, int):
        out.append(T_INT)
        _varint((value << 1) if value >= 0 else ((-value << 1) - 1), out)
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("NaN and infinity are not allowed")
        out.append(T_FLOAT)
        out += _F64.pack(value)
    elif isinstance(value, str):
        if value in _INTERN_INDEX:
            out.append(T_INTERN)
            out.append(_INTERN_INDEX[value])
        elif _HEX.match(value):
            raw = bytes.fromhex(value)
            out.append(T_HEX)
            _varint(len(raw), out)
            out += raw
        else:
            raw = value.encode("utf-8")
            out.append(T_STR)
            _varint(len(raw), out)
            out += raw
    elif isinstance(value, (list, tuple)):
        out.append(T_LIST)
        _varint(len(value), out)
        for item in value:
            _encode(item, out, depth + 1)
    elif isinstance(value, dict):
        out.append(T_DICT)
        _varint(len(value), out)
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError("field names must be strings")
            _encode(k, out, depth + 1)
            _encode(v, out, depth + 1)
    else:
        raise ValueError(f"cannot encode {type(value).__name__}")


class _Reader:
    def __init__(self, data: bytes, pos: int) -> None:
        self.data, self.pos = data, pos

    def byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("truncated message")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated message")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def varint(self) -> int:
        n = shift = 0
        while True:
            b = self.byte()
            n |= (b & 0x7F) << shift
            if not b & 0x80:
                return n
            shift += 7
            if shift > 63:
                raise ValueError("varint too long")

    def value(self, depth: int = 0) -> Any:
        if depth > MAX_DEPTH:
            raise ValueError("message nested too deeply")
        tag = self.byte()
        if tag == T_NONE:
            return None
        if tag == T_FALSE:
            return False
        if tag == T_TRUE:
            return True
        if tag == T_INT:
            z = self.varint()
            return (z >> 1) if not z & 1 else -((z + 1) >> 1)
        if tag == T_FLOAT:
            return _F64.unpack(self.take(8))[0]
        if tag == T_STR:
            return self.take(self.varint()).decode("utf-8")
        if tag == T_HEX:
            return self.take(self.varint()).hex()
        if tag == T_INTERN:
            idx = self.byte()
            if idx >= len(INTERNED):
                raise ValueError("unknown interned string")
            return INTERNED[idx]
        if tag == T_LIST:
            n = self.varint()
            if n > len(self.data):
                raise ValueError("invalid list length")
            return [self.value(depth + 1) for _ in range(n)]
        if tag == T_DICT:
            n = self.varint()
            if n > len(self.data):
                raise ValueError("invalid dict length")
            out = {}
            for _ in range(n):
                k = self.value(depth + 1)
                if not isinstance(k, str):
                    raise ValueError("field names must be strings")
                out[k] = self.value(depth + 1)
            return out
        raise ValueError(f"unknown value tag {tag}")


def message_type(data: bytes) -> str:
    """Name of a message from its first byte (used by the network for logs and EDCA class)."""
    if not data:
        return "EMPTY"
    return TYPE_NAMES.get(data[0], f"T{data[0]}")


@dataclass
class Message:
    type: str
    fields: dict[str, Any]

    def to_bytes(self) -> bytes:
        if self.type not in SUPPORTED_TYPES:
            raise ValueError(f"unsupported message type: {self.type}")
        if not isinstance(self.fields, dict):
            raise ValueError("message fields must be an object")
        out = bytearray((TYPE_CODES[self.type], WIRE_VERSION))
        _encode(self.fields, out)
        if len(out) > MAX_MESSAGE_BYTES:
            raise ValueError("message too large")
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Message":
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_MESSAGE_BYTES or len(data) < 3:
            raise ValueError("invalid or oversized message")
        data = bytes(data)
        if data[0] not in TYPE_NAMES:
            raise ValueError("invalid message type")
        if data[1] != WIRE_VERSION:
            raise ValueError("invalid message version")
        reader = _Reader(data, 2)
        fields = reader.value()
        if not isinstance(fields, dict):
            raise ValueError("message fields must be an object")
        if reader.pos != len(data):
            raise ValueError("trailing bytes after message")
        return cls(TYPE_NAMES[data[0]], fields)

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
