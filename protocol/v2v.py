"""Vehicle-side verification of neighbours' BSMs (--v2v-verify).

RSUs verify every BSM they hear, but the receivers that act on a BSM are the other
vehicles. This verifier is what a vehicle can check with the information it has:

- signed BSMs (and anchors): the ticket from a full-ticket BSM (RSU signature, or the
  implicit certificate reconstructed and authenticated by the BSM signature), the
  ticket digest otherwise, then the signature under the ticket key;
- session-MAC BSMs (--bsm-auth mac): tagged for RSUs only, so a vehicle cannot verify
  them ("unverifiable");
- TESLA BSMs (--bsm-auth tesla): buffered until the sender discloses the key, as at
  the RSU (protocol/tesla.py). Signed anchors are accepted at once (vehicles act on
  urgent messages without waiting) and update the chain commitment;
- the revocation filter of the last verified RSU beacon (--revocation-filter): a BSM
  whose pseudonym is in the filter is dropped ("revoked_filter"). Without the filter a
  vehicle has no revocation information until the sender's ticket expires.
- emergency alerts: a BSM with the "ev" flag is accepted only under a ticket of class
  "emergency" ("fake_emergency" otherwise).

``ops`` lists the cryptographic operations of the last call (for the CPU model).
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Any, Callable

from . import bloom, ecqv
from .crypto import bip340_verify, schnorr_verify
from .messages import Message
from .tesla import Receiver
from .vehicle import EMERGENCY_CLASS, canonical_json, ticket_digest


class V2VVerifier:
    def __init__(self, trusted_rsu_keys: dict[str, bytes], clock: Callable[[], float],
                 tesla: Receiver | None = None, cache: int = 500) -> None:
        self.trusted_rsu_keys = trusted_rsu_keys
        self.clock = clock
        self.tesla = tesla
        self.cache = cache
        self.tickets: OrderedDict[str, dict] = OrderedDict()     # digest -> ticket payload with "pk"
        self.filter: str | None = None
        self.filter_time = -1.0
        self.ops: list[str] = []

    def set_filter(self, filter_hex: str, timestamp: float) -> None:
        if timestamp >= self.filter_time:
            self.filter, self.filter_time = filter_hex, timestamp

    def filtered(self, pid: str) -> bool:
        return self.filter is not None and bloom.contains(self.filter, pid)

    def _remember(self, digest: str, payload: dict) -> None:
        self.tickets[digest] = payload
        self.tickets.move_to_end(digest)
        while len(self.tickets) > self.cache:
            self.tickets.popitem(last=False)

    def _ticket(self, ticket: Any) -> dict | None:
        """Ticket payload with "pk": explicit tickets need the issuing RSU's signature."""
        if not isinstance(ticket, dict) or not isinstance(ticket.get("payload"), dict):
            return None
        payload = ticket["payload"]
        key = self.trusted_rsu_keys.get(str(payload.get("issuer", "")))
        if key is None:
            return None
        if "pu" in payload:
            self.ops.append("ecqv_reconstruct")
            try:
                return {**payload, "pk": ecqv.reconstruct(payload, key).hex()}
            except Exception:
                return None
        sig = ticket.get("signature")
        self.ops.append("verify_sig")
        if not isinstance(sig, dict) or not schnorr_verify(key, canonical_json(payload), sig):
            return None
        return payload

    def learn(self, data: bytes) -> None:
        """Remember the ticket of a full-ticket BSM heard from beyond the safety radius, so
        the sender's digest-only BSMs can be checked once it comes closer. The ticket is
        cached only after the BSM's signature verifies under it."""
        self.ops = []
        try:
            msg = Message.from_bytes(data)
            payload = msg.fields.get("payload") if msg.type == "BSM" else None
            if not isinstance(payload, dict) or "ticket" not in payload or "tags" in msg.fields or "tm" in msg.fields:
                return
            digest = ticket_digest(payload["ticket"])
            if digest in self.tickets:
                return
            tp = self._ticket(payload["ticket"])
            sig = msg.fields.get("signature")
            if tp is None or tp.get("pid") != payload.get("pid"):
                return
            check = bip340_verify if isinstance(sig, str) else schnorr_verify
            self.ops.append("bsm_verify_one")
            if check(bytes.fromhex(tp["pk"]), canonical_json(payload), sig):
                self._remember(digest, tp)
        except Exception:
            return

    def receive(self, data: bytes, rx_time: float) -> list[dict]:
        """Every message decided by ``data``: {"ok", "reason", "pid", "payload", "rx_time"}."""
        self.ops = []
        try:
            msg = Message.from_bytes(data)
        except Exception:
            return [{"ok": False, "reason": "malformed"}]
        f = msg.fields
        try:
            if msg.type == "TESLA_KEY":
                if self.tesla is None:
                    return []
                digest = str(f.get("ticket_digest", ""))
                tp = self.tickets.get(digest)
                if tp is None or tp.get("pid") != f.get("pid"):
                    return []
                self.ops.append("tesla")
                return self._decide(self.tesla.disclose(str(f["pid"]), digest, float(tp["issued_at"]),
                                                        int(f.get("j", 0)), f.get("kd"), rx_time))
            if msg.type != "BSM":
                return []
            payload = f.get("payload")
            if not isinstance(payload, dict):
                return [{"ok": False, "reason": "malformed"}]
            pid = str(payload.get("pid", ""))
            if "tags" in f:
                return [{"ok": False, "reason": "unverifiable", "pid": pid}]
            if "ticket_digest" in payload:
                digest = str(payload["ticket_digest"])
                tp = self.tickets.get(digest)
                if tp is None:
                    return [{"ok": False, "reason": "unknown_ticket_digest", "pid": pid}]
            else:
                digest = ticket_digest(payload.get("ticket") or {})
                tp = self._ticket(payload.get("ticket"))
                if tp is None:
                    return [{"ok": False, "reason": "invalid_ticket", "pid": pid}]
            if tp.get("pid") != pid:
                return [{"ok": False, "reason": "ticket_pseudonym_mismatch", "pid": pid}]
            t0 = float(tp.get("issued_at", 0.0))
            if "tm" in f:
                if self.tesla is None:
                    return [{"ok": False, "reason": "unverifiable", "pid": pid}]
                self.ops.append("tesla")
                status, released = self.tesla.receive(pid, digest, t0, payload.get("ti"), f.get("tm"),
                                                      canonical_json(payload), f.get("kd"), rx_time,
                                                      (payload, tp, rx_time))
                out = [{"ok": False, "reason": status, "pid": pid}] if status != "buffered" else []
                return out + self._decide(released)
            sig = f.get("signature")
            check = bip340_verify if isinstance(sig, str) else schnorr_verify
            self.ops.append("bsm_verify_one")
            if not check(bytes.fromhex(tp["pk"]), canonical_json(payload), sig):
                return [{"ok": False, "reason": "invalid_signature", "pid": pid}]
            if "ticket" in payload:
                self._remember(digest, tp)
            out = [self._final(payload, tp, rx_time)]
            if self.tesla is not None and "tc" in payload:
                out += self._decide(self.tesla.anchor(pid, digest, t0, payload["tc"]))
            return out
        except Exception:
            return [{"ok": False, "reason": "malformed"}]

    def _final(self, payload: dict, tp: dict, rx_time: float) -> dict:
        pid = str(payload.get("pid", ""))
        if float(tp.get("expiry", 0)) <= self.clock():
            return {"ok": False, "reason": "expired", "pid": pid, "rx_time": rx_time}
        if payload.get("ev") and tp.get("class") != EMERGENCY_CLASS:
            # "siren on" counts only under a ticket whose RSU-signed class is emergency
            return {"ok": False, "reason": "fake_emergency", "pid": pid, "payload": payload, "rx_time": rx_time}
        if self.filtered(pid):
            return {"ok": False, "reason": "revoked_filter", "pid": pid, "payload": payload, "rx_time": rx_time}
        return {"ok": True, "reason": "valid", "pid": pid, "payload": payload, "rx_time": rx_time}

    def _decide(self, released: list) -> list[dict]:
        out = []
        for (payload, tp, rx), ok, _ in released:
            pid = str(payload.get("pid", ""))
            if ok is None:
                out.append({"ok": False, "reason": "tesla_no_key", "pid": pid, "rx_time": rx})
            elif not ok:
                out.append({"ok": False, "reason": "invalid_tesla_mac", "pid": pid, "rx_time": rx})
            else:
                out.append(self._final(payload, tp, rx))
        return out
