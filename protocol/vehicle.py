"""Vehicle-side protocol logic, independent of ns-3.

All times come from ``clock`` (default: wall clock). In the simulator it is the
simulated clock (``node.now``), so freshness windows and ticket expiry follow
simulated time.
"""
from __future__ import annotations
import hashlib, json, time
from typing import Callable, Any, Iterable
import math
from . import ecqv, tesla as tesla_mod
from .crypto import N, _base_mul, prove, schnorr_sign, schnorr_verify, bip340_sign, bsm_mac_key, bsm_tag, CommitmentPool
from .messages import KINEMATIC_KEYS, make_message, pack_kinematics, Message
from .registration import Pseudonym

def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

_DIGESTS: dict[int, tuple[dict, str]] = {}


def ticket_digest(ticket: dict) -> str:
    """First 8 bytes (16 hex) of SHA-256 over the canonical ticket, for --bsm-ticket digest.

    Only ``payload`` and the signature's ``R``/``s`` are hashed, so junk keys added to a
    ticket do not yield new digests (one issued ticket, one digest). Cached per ticket object
    (decoded messages share their nested dicts, see Message.from_bytes)."""
    hit = _DIGESTS.get(id(ticket))
    if hit is not None and hit[0] is ticket:
        return hit[1]
    d = _ticket_digest(ticket)
    if len(_DIGESTS) >= 8192:
        _DIGESTS.clear()
    _DIGESTS[id(ticket)] = (ticket, d)        # keeps the object alive, so its id is not reused
    return d


def _ticket_digest(ticket: dict) -> str:
    sig = ticket.get("signature")
    sig = sig if isinstance(sig, dict) else {}
    core = {"payload": ticket.get("payload"), "signature": {"R": sig.get("R"), "s": sig.get("s")}}
    return hashlib.sha256(canonical_json(core)).hexdigest()[:16]

MAX_MAC_TAGS = 3
EMERGENCY_CLASS = "emergency"   # the only class whose BSMs may carry the "ev" (siren on) flag

def adaptive_anchor_period(cbr: float, base: int, current: int | None = None, band: float = 0.02) -> int:
    """--adaptive-anchor: anchor period for a measured channel busy ratio, monotone in cbr.
    Below 0.2 base // 2 (at least 2, at most base), up to 0.4 ``base``, above 2 * base
    (10 -> 5 / 10 / 20). Hysteresis: within ``band`` of a threshold the ``current`` period
    is kept if it is one of the two periods meeting there."""
    def rule(c: float) -> int:
        if c < 0.2:
            return min(base, max(2, base // 2))
        return base if c <= 0.4 else 2 * base
    n = rule(cbr)
    if current is not None and current != n and current in (rule(cbr - band), rule(cbr + band)):
        return current
    return n

def auth_context(rsu_id: str, nonce: str, timestamp: float, service: str,
                 pid: str, vehicle_class: str) -> bytes:
    fields = [b"VANET-AUTH-v1", rsu_id.encode(), nonce.encode(),
              format(float(timestamp), ".6f").encode(), service.encode(), pid.encode(),
              vehicle_class.encode()]
    return b"".join(len(item).to_bytes(4, "big") + item for item in fields)

def bind_context(ctx: bytes, cert_req: bytes | None) -> bytes:
    """--implicit-cert: bind the ECQV request point into the proof context, so nobody can
    swap it on the air and receive a certificate for this pseudonym."""
    if not cert_req:
        return ctx
    return ctx + len(cert_req).to_bytes(4, "big") + b"ECQV" + cert_req

def bbs_pseudonyms(credential, count: int) -> tuple[list[Pseudonym], dict[str, int]]:
    """--credential bbs: pseudonyms 0..count-1 of a BBS credential. pid = H(nym_j); the
    secp256k1 key that the ticket binds is derived from sk_v and j (only the holder knows it)."""
    from . import bbs
    out, index = [], {}
    raw = bbs.secret_to_bytes(credential.sk_v)
    for j in range(count):
        pid = bbs.pid_of(credential.nym(j))
        sk = int.from_bytes(hashlib.sha256(b"VANET-BBS-SESSION" + raw + j.to_bytes(4, "big")).digest(), "big") % N or 1
        out.append(Pseudonym(pid, sk, _base_mul(sk), credential.epoch, credential.vehicle_class))
        index[pid] = j
    return out, index

class Vehicle:
    """``bsm_ticket``: "full" puts the ticket in every BSM; "digest" sends only its
    ticket_digest() and the full ticket in the first BSM after a new ticket, a handover
    or send_full_ticket(), and in every ``ticket_every``-th BSM. ``compact_wire`` packs
    the kinematics with pack_kinematics() and signs BSMs with 64-byte BIP340.

    ``bsm_auth="mac"`` (implies the digest ticket schedule): BSMs carry the ticket digest
    and, instead of a signature, ``tags`` = {rsu_id: 8-byte HMAC} for up to MAX_MAC_TAGS
    RSUs (the current RSU first, then ``mac_rsus`` of make_bsm), keyed with
    bsm_mac_key(pseudonym secret, RSU key, digest). Every ``anchor_every``-th BSM, every
    BSM with the full ticket and every BSM without a trusted target RSU is a signed
    ANCHOR instead. Trade-off: a MAC BSM convinces only the addressed RSUs (no V2V
    verifiability, and an addressed RSU could forge it, so no non-repudiation); anchors
    keep both and are what misbehaviour reports point to. RSUs enforce the schedule
    (``anchor_overdue`` / ``anchor_required``, see RSU), so skipping anchors only loses
    BSMs. ``last_bsm_anchor`` tells which kind make_bsm produced last.

    ``handover_sessions=False`` (--handover-hysteresis): only full authentications count
    toward ``pseudonym_switch_after``, so handover ping-pong does not burn pseudonyms.
    Trade-off: one pseudonym then covers a longer stretch of road (more linkable).

    v3 options: ``implicit_cert`` (ECQV tickets: AUTH_REQ carries ``cert_req``, BSMs and
    handover requests are signed with the ticket secret d_U), ``bsm_auth="tesla"``
    (implies the digest ticket schedule: between signed anchors a BSM carries ``ti``, a
    TESLA MAC ``tm`` and the disclosed chain key ``kd``; anchors commit to the chain with
    ``tc``; ``make_bsm(urgent=True)`` always signs), ``credential`` (a BBS credential;
    the pseudonyms come from bbs_pseudonyms() and AUTH_REQ carries a BBS proof)."""

    def __init__(self, pseudonyms: list[Pseudonym], vehicle_class: str = "car",
                 trusted_rsu_keys: dict[str, bytes] | None = None, freshness_seconds: float = 5.0,
                 pseudonym_switch_after: int = 3,
                 send_fn: Callable[[Any, Any, bytes], None] | None = None,
                 schedule_fn: Callable[[float, Callable], None] | None = None,
                 clock: Callable[[], float] = time.time,
                 bsm_ticket: str = "full", ticket_every: int = 10, compact_wire: bool = False,
                 bsm_auth: str = "sig", anchor_every: int = 10, handover_sessions: bool = True,
                 implicit_cert: bool = False, tesla_interval: float = tesla_mod.DEFAULT_INTERVAL,
                 tesla_delay: int = tesla_mod.DEFAULT_DELAY, credential=None, bbs_index: dict | None = None,
                 ticket_period: float = 0.0):
        if not pseudonyms:
            raise ValueError("vehicle needs at least one pseudonym")
        self.pseudonyms = pseudonyms
        self.vehicle_class = vehicle_class
        self.pid_index = 0
        self.sessions_on_current = 0    # authentications (+ handovers) with the current pseudonym
        self.handover_sessions = handover_sessions
        self.ticket = None
        self.trusted_rsu_keys = trusted_rsu_keys if trusted_rsu_keys is not None else {}
        self.freshness_seconds = freshness_seconds
        if pseudonym_switch_after < 1:
            raise ValueError("pseudonym_switch_after must be positive")
        self.pseudonym_switch_after = pseudonym_switch_after
        self.clock = clock
        # Pool of precomputed commitments (g^r computed while idle)
        self.commitment_pool = CommitmentPool(initial_size=5)
        # Node hooks (Network simulation node interface)
        self.send_fn = send_fn
        self.schedule_fn = schedule_fn
        self.current_rsu_id: str | None = None
        if bsm_ticket not in ("full", "digest"):
            raise ValueError("bsm_ticket must be 'full' or 'digest'")
        if bsm_ticket == "digest" and ticket_every < 1:
            raise ValueError("ticket_every must be positive")
        self.bsm_ticket, self.ticket_every, self.compact_wire = bsm_ticket, ticket_every, compact_wire
        self._full_ticket_due = True
        self._digest_bsms = 0
        self._digest: tuple[dict, str] | None = None
        if bsm_auth not in ("sig", "mac", "tesla"):
            raise ValueError("bsm_auth must be 'sig', 'mac' or 'tesla'")
        if anchor_every < 1:
            raise ValueError("anchor_every must be positive")
        self.bsm_auth, self.anchor_every = bsm_auth, anchor_every
        if bsm_auth in ("mac", "tesla"):
            self.bsm_ticket = "digest"
        self._mac_bsms = 0
        self._mac_keys: dict[tuple[str, str], bytes] = {}
        self.last_bsm_anchor = True
        self.implicit_cert = implicit_cert
        self.ticket_secret: int | None = None      # signs BSMs / handover requests (d_U or the pseudonym secret)
        self._cert_k: int | None = None            # pending ECQV request secret k_U
        self.tesla_interval, self.tesla_delay = tesla_interval, tesla_delay
        self.tesla: tesla_mod.Sender | None = None
        self.last_tesla: tuple[int, int] | None = None   # (interval, disclosed index) of the last BSM
        self.credential, self.bbs_index = credential, bbs_index or {}
        self._bbs_pre: dict[int, dict] = {}          # BBS proofs precomputed for the next login
        self.last_proof_precomputed = False
        if credential is not None:
            self.precompute_proof()
        self.ticket_period = ticket_period          # digest mode: full ticket at least every this many s (0: off)
        self._last_full = -math.inf

    @property
    def current(self) -> Pseudonym:
        return self.pseudonyms[self.pid_index % len(self.pseudonyms)]

    def change_pseudonym(self) -> Pseudonym:
        """Switch to the next pseudonym. The ticket belongs to the old one, so drop it."""
        self.pid_index += 1
        self.sessions_on_current = 0
        self.ticket = None
        self.ticket_secret = None
        self.tesla = None
        self.current_rsu_id = None
        return self.current

    def precompute_proof(self) -> None:
        """BBS mode: prepare the nonce-independent part of the next proof (the current
        pseudonym's scope, and the next one's for a pseudonym change)."""
        if self.credential is None:
            return
        for k in (0, 1):
            j = self.bbs_index.get(self.pseudonyms[(self.pid_index + k) % len(self.pseudonyms)].pid)
            if j is not None and j not in self._bbs_pre:
                self._bbs_pre[j] = self.credential.precompute(j)

    @property
    def ticket_cluster(self):
        return None if self.ticket is None else self.ticket["payload"].get("cl")

    def ticket_valid(self, margin: float = 0.0) -> bool:
        if self.ticket is None:
            return False
        return float(self.ticket["payload"]["expiry"]) - margin > self.clock()

    def verify_beacon(self, beacon: dict) -> bool:
        try:
            payload = beacon["payload"]
            rsu_id = str(payload["rsu_id"])
            trusted_key = self.trusted_rsu_keys.get(rsu_id)
            # the key in the beacon is optional (--compact-wire omits it): only the trusted key counts
            sent_key = beacon.get("public_key")
            if trusted_key is None or (sent_key is not None and bytes.fromhex(sent_key) != trusted_key):
                return False
            ts = float(payload["timestamp"])
            if abs(self.clock() - ts) > self.freshness_seconds:
                return False
            return schnorr_verify(trusted_key, canonical_json(payload), beacon["signature"])
        except Exception:
            return False

    def make_auth_request(self, beacon: dict, service: str) -> bytes:
        if not self.verify_beacon(beacon):
            raise ValueError("untrusted, invalid, or stale RSU beacon")
        if self.sessions_on_current >= self.pseudonym_switch_after:
            self.change_pseudonym()
        p = self.current
        if p.merkle_path is None and self.credential is None:
            raise RuntimeError("pseudonym has not been registered")
        b = beacon["payload"]
        extra = {}
        cert_req = None
        if self.implicit_cert:
            self._cert_k, point = ecqv.request()
            cert_req = point
            extra["cert_req"] = point.hex()
        ctx = bind_context(auth_context(b["rsu_id"], b["nonce"], b["timestamp"], service, p.pid,
                                        self.vehicle_class), cert_req)
        if self.credential is not None:
            j = self.bbs_index[p.pid]
            # precomputed while idle (see precompute_proof); the online part is cheap
            pre = self._bbs_pre.pop(j, None)
            self.last_proof_precomputed = pre is not None
            nym, proof_bytes = self.credential.finish(pre or self.credential.precompute(j), ctx + p.public_key)
            self.precompute_proof()
            return make_message("AUTH_REQ", pid=p.pid, public_key=p.public_key.hex(), epoch=p.epoch,
                                nym=nym.hex(), j=j, bbs_proof=proof_bytes.hex(), service=service,
                                vehicle_class=self.vehicle_class, timestamp=b["timestamp"],
                                nonce=b["nonce"], rsu_id=b["rsu_id"], **extra).to_bytes()
        # Use precomputed commitment from pool (zero-knowledge, non-reused r)
        commitment = self.commitment_pool.pop()
        proof = prove(p.secret, ctx, commitment=commitment)
        return make_message("AUTH_REQ", pid=p.pid, public_key=p.public_key.hex(),
                            epoch=p.epoch, merkle_path=p.merkle_path, proof=proof.to_dict(),
                            service=service, vehicle_class=self.vehicle_class,
                            timestamp=b["timestamp"], nonce=b["nonce"], rsu_id=b["rsu_id"], **extra).to_bytes()

    def accept_ticket(self, ticket: dict, rsu_public_key: bytes, r: str | None = None,
                      count_session: bool = True) -> bool:
        """Store a ticket from an RSU. Only a ticket for the current pseudonym and key is accepted.
        Implicit certificates need ``r`` and the pending request secret (make_auth_request or
        make_handover_request); the ticket secret is then d_U = e * k_U + r."""
        try:
            payload = ticket["payload"]
            if not isinstance(payload, dict):
                return False
            p = self.current
            now = self.clock()
            if payload.get("pid") != p.pid:
                return False
            if float(payload["expiry"]) <= now or float(payload["issued_at"]) > now + 1:
                return False
            if "pu" in payload:
                if not self.implicit_cert or self._cert_k is None or r is None:
                    return False
                secret = ecqv.receive(self._cert_k, int(r, 16), payload, rsu_public_key)
                if secret is None:
                    return False
                self._cert_k = None
            else:
                signature = ticket["signature"]
                if not isinstance(signature, dict) or payload.get("pk") != p.public_key.hex():
                    return False
                if not schnorr_verify(rsu_public_key, canonical_json(payload), signature):
                    return False
                secret = p.secret
            self.ticket, self.ticket_secret = ticket, secret
            self._full_ticket_due = True
            if count_session:
                self.sessions_on_current += 1
            self.current_rsu_id = str(payload.get("issuer"))
            if self.bsm_auth == "tesla":
                life = float(payload["expiry"]) - float(payload["issued_at"])
                self.tesla = tesla_mod.Sender(float(payload["issued_at"]),
                                              int(math.ceil(life / self.tesla_interval)) + 2,
                                              self.tesla_interval, self.tesla_delay)
                self._mac_bsms = 0
            return True
        except Exception:
            return False

    def _secret(self) -> int:
        return self.ticket_secret if self.ticket_secret is not None else self.current.secret

    def handover_accepted(self, rsu_id: str) -> None:
        if self.handover_sessions:
            self.sessions_on_current += 1
        self.current_rsu_id = rsu_id
        self._full_ticket_due = True

    def send_full_ticket(self) -> None:
        """Attach the full ticket to the next BSM (digest mode), e.g. on hearing a new RSU."""
        self._full_ticket_due = True

    def _full_ticket_next(self) -> bool:
        if self.bsm_ticket == "full":
            return True
        now = self.clock()
        if (self._full_ticket_due or self._digest_bsms >= self.ticket_every - 1
                or (self.ticket_period > 0 and now - self._last_full >= self.ticket_period)):
            self._full_ticket_due, self._digest_bsms = False, 0
            self._last_full = now
            return True
        self._digest_bsms += 1
        return False

    def _mac_targets(self, mac_rsus: Iterable[str]) -> list[str]:
        out: list[str] = []
        for rsu in ([self.current_rsu_id] if self.current_rsu_id else []) + list(mac_rsus):
            if rsu in self.trusted_rsu_keys and rsu not in out:
                out.append(rsu)
        return out[:MAX_MAC_TAGS]

    def _mac_key(self, rsu: str, digest: str) -> bytes:
        key = self._mac_keys.get((rsu, digest))
        if key is None:
            if len(self._mac_keys) > 64:
                self._mac_keys.clear()
            key = self._mac_keys[(rsu, digest)] = bsm_mac_key(self._secret(), self.trusted_rsu_keys[rsu], digest)
        return key

    def make_tesla_key(self) -> bytes | None:
        """TESLA_KEY message with the newest disclosable chain key, or None if there is
        nothing new to disclose (the last BSM already disclosed it)."""
        if self.tesla is None or self.ticket is None:
            return None
        now = self.clock()
        j = self.tesla.disclosable(now)
        if j < 1 or (self.last_tesla is not None and self.last_tesla[1] >= j):
            return None
        if self._digest is None or self._digest[0] is not self.ticket:
            self._digest = (self.ticket, ticket_digest(self.ticket))
        i = self.last_tesla[0] if self.last_tesla else 0
        self.last_tesla = (i, j)
        return make_message("TESLA_KEY", pid=self.current.pid, ticket_digest=self._digest[1], j=j,
                            kd=self.tesla.key(j).hex()).to_bytes()

    def make_bsm(self, *, mac_rsus: Iterable[str] = (), urgent: bool = False, commit: bool = True,
                 ev: bool = False, **safety_fields) -> bytes:
        """Create a signed BSM carrying the current pseudonym and current ticket (or its digest).
        The verifying key is the one in the ticket, so no separate key is sent; the digest
        is inside the signed payload. In mac mode a non-anchor BSM is MAC'd for the current
        RSU and ``mac_rsus`` (RSUs heard recently) instead of signed. ``ev`` marks an emergency
        alert (siren on); receivers honour it only under a ticket of class "emergency"."""
        p = self.current
        if self.ticket is None:
            raise RuntimeError("cannot send authenticated BSM without a ticket")
        if self.compact_wire:
            keys = set(safety_fields) - {"timestamp"} | ({"t"} if "timestamp" in safety_fields else set())
            if keys != KINEMATIC_KEYS or len(safety_fields) != len(KINEMATIC_KEYS):
                raise ValueError(f"compact_wire BSMs need exactly the fields {sorted(KINEMATIC_KEYS)}")
            payload = {"pid": p.pid, "k": pack_kinematics(safety_fields)}
        else:
            payload = {"pid": p.pid, "fields": safety_fields}
        if ev:
            payload["ev"] = 1
        full = self._full_ticket_next()
        if full:
            payload["ticket"] = self.ticket
        else:
            if self._digest is None or self._digest[0] is not self.ticket:
                self._digest = (self.ticket, ticket_digest(self.ticket))
            payload["ticket_digest"] = self._digest[1]
        if self.bsm_auth == "tesla" and self.tesla is not None and self.tesla.usable(self.clock()):
            now = self.clock()
            i = self.tesla.index(now)
            payload["ti"] = i
            disclosed = self.tesla.disclosable(now)
            if not full and not urgent and self._mac_bsms < self.anchor_every - 1:
                self._mac_bsms += 1
                self.last_bsm_anchor = False
                _, mac = self.tesla.mac(now, canonical_json(payload))
                extra = {"kd": self.tesla.key(disclosed).hex()} if disclosed >= 1 else {}
                self.last_tesla = (i, disclosed)
                return make_message("BSM", payload=payload, tm=mac, **extra).to_bytes()
            self._mac_bsms, self.last_bsm_anchor = 0, True
            # adaptive mode signs every BSM; the chain commitment rides on some, and always on a
            # full-ticket BSM (the first after a new ticket starts a new chain)
            if commit or full:
                payload["tc"] = self.tesla.commitment(now)
            self.last_tesla = (i, disclosed)
        elif self.bsm_auth == "mac":
            targets = [] if full else self._mac_targets(mac_rsus)
            if targets and self._mac_bsms < self.anchor_every - 1:
                self._mac_bsms += 1
                self.last_bsm_anchor = False
                data, digest = canonical_json(payload), payload["ticket_digest"]
                tags = {rsu: bsm_tag(self._mac_key(rsu, digest), data) for rsu in targets}
                return make_message("BSM", payload=payload, tags=tags).to_bytes()
            self._mac_bsms, self.last_bsm_anchor = 0, True
        sign = bip340_sign if self.compact_wire else schnorr_sign
        signature = sign(self._secret(), canonical_json(payload))
        return make_message("BSM", payload=payload, signature=signature).to_bytes()

    def make_renew_request(self, rsu_id: str, beacon: dict) -> bytes:
        """--ticket-renewal: ask ``rsu_id`` for a fresh ticket for the current pseudonym, signed
        with the ticket key and bound to the RSU's beacon nonce (no new ZKP / BBS proof)."""
        if not self.verify_beacon(beacon) or beacon["payload"]["rsu_id"] != rsu_id:
            raise ValueError("untrusted, invalid, or stale RSU beacon")
        return self.make_handover_request(rsu_id, beacon["payload"]["nonce"], new_cert=self.implicit_cert,
                                          renew=True)

    def make_handover_request(self, next_rsu_id: str, nonce: str = "", new_cert: bool = False,
                              renew: bool = False) -> bytes:
        """Handover request signed with the ticket key, so a sniffed ticket alone is useless.
        ``nonce`` is the target RSU's beacon nonce (prevents replay at that RSU). ``new_cert``
        (--implicit-cert into another cluster) adds a fresh ECQV request for the new ticket."""
        if self.ticket is None:
            raise RuntimeError("no authorization ticket to hand over")
        payload = {"ticket": self.ticket, "next_rsu_id": next_rsu_id, "nonce": nonce,
                   "timestamp": float(self.clock())}
        if new_cert and self.implicit_cert:
            self._cert_k, point = ecqv.request()
            payload["cert_req"] = point.hex()
        if renew:
            payload["renew"] = True
        signature = schnorr_sign(self._secret(), canonical_json(payload))
        return make_message("HANDOVER_REQ", signature=signature, **payload).to_bytes()

    def make_before_break_handover(self, next_rsu_id: str, next_rsu_beacon: dict | None = None,
                                   new_cert: bool = False) -> bytes:
        """Make-before-break handover: request handover with next RSU while still covered by current RSU."""
        nonce = ""
        if next_rsu_beacon is not None:
            if not self.verify_beacon(next_rsu_beacon):
                raise ValueError("untrusted or invalid target RSU beacon for make-before-break handover")
            if next_rsu_beacon["payload"]["rsu_id"] != next_rsu_id:
                raise ValueError("beacon is from a different RSU")
            nonce = next_rsu_beacon["payload"]["nonce"]
        return self.make_handover_request(next_rsu_id, nonce, new_cert)

    def on_receive(self, node: Any, data: bytes, sim_time: float) -> dict[str, Any] | None:
        """Network node hook: called when bytes arrive over radio."""
        try:
            msg = Message.from_bytes(data)
        except Exception:
            return None

        if msg.type == "AUTH_RESP":
            f = msg.fields
            if f.get("pid") not in (None, self.current.pid):
                return None                 # response for another vehicle
            if f.get("ok") and f.get("ticket"):
                issuer = f["ticket"].get("payload", {}).get("issuer")
                issuer_key = self.trusted_rsu_keys.get(issuer)
                if not issuer_key or not self.accept_ticket(f["ticket"], issuer_key, f.get("r"),
                                                            count_session=not f.get("handover")):
                    return {**f, "ok": False, "reason": "ticket_not_accepted"}
            elif f.get("ok") and f.get("handover"):
                self.handover_accepted(str(f.get("rsu_id")))
            return f
        return None
