"""BBS anonymous credentials on BLS12-381 (--credential bbs).

Instead of a pool of pre-registered pseudonyms (Merkle mode), every vehicle holds one
BBS signature from the TA on the messages

    m0 = the vehicle secret sk_v   (hidden: issued blindly, the TA never learns it)
    m1 = the vehicle class         (disclosed at authentication: the policy needs it)
    m2 = the epoch                 (disclosed)

and authenticates with a fresh zero-knowledge proof of possession of that signature
(core proof of draft-irtf-cfrg-bbs-signatures), extended with a scope pseudonym

    nym_j = H_scope(epoch, j) ^ sk_v,    0 <= j < J

proven to use the same hidden sk_v. Two proofs are unlinkable unless they use the same
j; the RSU checks j < J, so one credential yields at most J pseudonyms per epoch
(Sybil bound) and pid = SHA-256(nym)[:8] is what the ledger revokes. Tracing works as
before: sk_v is escrowed with the RSU organisations (t-of-n); after an approved trace
the TA recomputes nym_0..nym_{J-1} and revokes all of them. The TA alone cannot trace.

Proof (presentation) = Abar, Bbar, D (G1, 48 B each) and e^, r1^, r3^, m0^, c (32 B
each): 304 bytes, plus nym (48 B). Verification costs one multi-exponentiation and
one two-pairing product check.

Generators come from hash_to_curve, so nobody knows their discrete logarithms.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from functools import lru_cache

from py_arkworks_bls12381 import G1Point, G2Point, GT, Scalar

DST = b"VANET-BBS-BLS12381G1-v1"
L = 3                       # messages: sk_v, class, epoch
G1_BYTES, SCALAR_BYTES = 48, 32
PROOF_BYTES = 3 * G1_BYTES + 5 * SCALAR_BYTES


# ------------------------------------------------------------------ helpers
def _hs(*parts: bytes) -> Scalar:
    h = hashlib.sha512(DST + b"H2S")
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return Scalar.from_be_bytes_mod_order(h.digest()[:48])


def rand_scalar() -> Scalar:
    while True:
        s = Scalar.from_be_bytes_mod_order(secrets.token_bytes(48))
        if not s.is_zero():
            return s


def _sb(s: Scalar) -> bytes:
    return bytes(s.to_be_bytes())


def _gb(p) -> bytes:
    return bytes(p.to_compressed_bytes())


def message_scalar(value: str) -> Scalar:
    return _hs(b"msg", value.encode())


@lru_cache(maxsize=1)
def generators() -> tuple:
    """P1, Q1, H0..H(L-1)."""
    gen = lambda name: G1Point.hash_to_curve(DST + b"GEN", name)  # noqa: E731
    return (gen(b"P1"), gen(b"Q1")) + tuple(gen(b"H%d" % i) for i in range(L))


@lru_cache(maxsize=4096)
def scope_point(scope: str):
    return G1Point.hash_to_curve(DST + b"SCOPE", scope.encode())


def scope_of(epoch: int, j: int) -> str:
    return f"{int(epoch)}|{int(j)}"


@lru_cache(maxsize=64)
def _domain(pk_bytes: bytes) -> Scalar:
    return _hs(b"domain", pk_bytes, *(_gb(g) for g in generators()))


# ----------------------------------------------------------------- the TA
@dataclass
class IssuerKey:
    sk: Scalar
    pk: G2Point

    @classmethod
    def generate(cls) -> "IssuerKey":
        sk = rand_scalar()
        return cls(sk, G2Point() * sk)

    @property
    def pk_hex(self) -> str:
        return _gb(self.pk).hex()


def commit_secret(sk_v: Scalar, nonce: bytes) -> tuple[bytes, dict]:
    """Vehicle side of blind issuance: C = H0 * sk_v and a Schnorr proof of knowledge."""
    H0 = generators()[2]
    C = H0 * sk_v
    t = rand_scalar()
    T = H0 * t
    c = _hs(b"issue", _gb(C), _gb(T), nonce)
    return _gb(C), {"T": _gb(T).hex(), "z": _sb(t + c * sk_v).hex()}


def issue(issuer: IssuerKey, commitment: bytes, pok: dict, nonce: bytes,
          vehicle_class: str, epoch: int) -> tuple[bytes, Scalar]:
    """TA side: check the proof of knowledge of the committed sk_v, then sign
    B = P1 + Q1*domain + C + H1*class + H2*epoch. Returns the signature (A, e)."""
    P1, Q1, H0, H1, H2 = generators()
    C = G1Point.from_compressed_bytes(commitment)
    T = G1Point.from_compressed_bytes(bytes.fromhex(pok["T"]))
    z = Scalar.from_be_bytes(bytes.fromhex(pok["z"]))
    c = _hs(b"issue", commitment, _gb(T), nonce)
    if H0 * z != T + C * c:
        raise ValueError("invalid proof of knowledge of the vehicle secret")
    domain = _domain(_gb(issuer.pk))
    B = P1 + Q1 * domain + C + H1 * message_scalar(vehicle_class) + H2 * message_scalar(str(epoch))
    e = rand_scalar()
    return _gb(B * (issuer.sk + e).inverse()), e


# ------------------------------------------------------------- the vehicle
@dataclass
class Credential:
    sk_v: Scalar
    A: bytes
    e: Scalar
    vehicle_class: str
    epoch: int
    issuer_pk: bytes

    def _B(self):
        P1, Q1, H0, H1, H2 = generators()
        return (P1 + Q1 * _domain(self.issuer_pk) + H0 * self.sk_v
                + H1 * message_scalar(self.vehicle_class) + H2 * message_scalar(str(self.epoch)))

    def valid(self) -> bool:
        A = G1Point.from_compressed_bytes(self.A)
        W = G2Point.from_compressed_bytes(self.issuer_pk)
        return GT.pairing_check([A, -self._B()], [W + G2Point() * self.e, G2Point()])

    def nym(self, j: int) -> bytes:
        return _gb(scope_point(scope_of(self.epoch, j)) * self.sk_v)

    def precompute(self, j: int) -> dict:
        """Everything of a proof for scope (epoch, j) that does not depend on the RSU's nonce:
        the randomised signature (Abar, Bbar, D), the commitments T1-T3 and nym. Done while
        idle; ``finish`` then needs one hash and four scalar operations. Use each result once."""
        P1, Q1, H0, H1, H2 = generators()
        r1, r2, e_t, r1_t, r3_t, m0_t = (rand_scalar() for _ in range(6))
        A = G1Point.from_compressed_bytes(self.A)
        D = self._B() * r2
        Abar = A * (r1 * r2)
        Bbar = D * r1 - Abar * self.e
        Hs = scope_point(scope_of(self.epoch, j))
        return {"j": j, "r1": r1, "r3": r2.inverse(), "e_t": e_t, "r1_t": r1_t, "r3_t": r3_t, "m0_t": m0_t,
                "Abar": Abar, "Bbar": Bbar, "D": D, "nym": Hs * self.sk_v,
                "T1": G1Point.multiexp_unchecked([Abar, D], [e_t, r1_t]),
                "T2": G1Point.multiexp_unchecked([D, H0], [r3_t, m0_t]), "T3": Hs * m0_t}

    def finish(self, pre: dict, presentation_header: bytes) -> tuple[bytes, bytes]:
        """Online part: challenge over the precomputed commitments and the header, responses."""
        c = _challenge(pre["Abar"], pre["Bbar"], pre["D"], pre["T1"], pre["T2"], pre["T3"], pre["nym"],
                       self.vehicle_class, self.epoch, pre["j"], _domain(self.issuer_pk), presentation_header)
        out = [_gb(pre["Abar"]), _gb(pre["Bbar"]), _gb(pre["D"]), _sb(pre["e_t"] + self.e * c),
               _sb(pre["r1_t"] - pre["r1"] * c), _sb(pre["r3_t"] - pre["r3"] * c),
               _sb(pre["m0_t"] + self.sk_v * c), _sb(c)]
        return _gb(pre["nym"]), b"".join(out)

    def prove(self, j: int, presentation_header: bytes) -> tuple[bytes, bytes]:
        """(nym_j, proof) for scope (epoch, j), bound to ``presentation_header``."""
        return self.finish(self.precompute(j), presentation_header)


def _challenge(Abar, Bbar, D, T1, T2, T3, nym, vehicle_class, epoch, j, domain, ph) -> Scalar:
    return _hs(b"proof", _gb(Abar), _gb(Bbar), _gb(D), _gb(T1), _gb(T2), _gb(T3), _gb(nym),
               vehicle_class.encode(), str(int(epoch)).encode(), str(int(j)).encode(), _sb(domain), ph)


def verify_proof(issuer_pk: bytes, nym: bytes, proof: bytes, vehicle_class: str, epoch: int,
                 j: int, presentation_header: bytes) -> bool:
    """RSU side: the proof shows a TA credential on (hidden sk_v, class, epoch) and that
    nym = H_scope(epoch, j) ^ sk_v for the same sk_v."""
    try:
        if len(proof) != PROOF_BYTES:
            return False
        g = [G1Point.from_compressed_bytes(proof[i * 48:(i + 1) * 48]) for i in range(3)]
        Abar, Bbar, D = g
        sc = [Scalar.from_be_bytes(proof[144 + i * 32:176 + i * 32]) for i in range(5)]
        e_h, r1_h, r3_h, m0_h, c = sc
        N_ = G1Point.from_compressed_bytes(nym)
        if Abar == G1Point.identity():
            return False
        P1, Q1, H0, H1, H2 = generators()
        domain = _domain(bytes(issuer_pk))
        T1 = G1Point.multiexp_unchecked([Bbar, Abar, D], [c, e_h, r1_h])
        Bv = P1 + Q1 * domain + H1 * message_scalar(vehicle_class) + H2 * message_scalar(str(epoch))
        T2 = G1Point.multiexp_unchecked([Bv, D, H0], [c, r3_h, m0_h])
        Hs = scope_point(scope_of(epoch, j))
        T3 = Hs * m0_h - N_ * c
        if _challenge(Abar, Bbar, D, T1, T2, T3, N_, vehicle_class, epoch, j, domain,
                      presentation_header) != c:
            return False
        W = G2Point.from_compressed_bytes(bytes(issuer_pk))
        return GT.pairing_check([Abar, -Bbar], [W, G2Point()])
    except Exception:
        return False


def pid_of(nym: bytes) -> str:
    return hashlib.sha256(b"VANET-NYM" + bytes(nym)).hexdigest()[:16]


def secret_to_bytes(sk_v: Scalar) -> bytes:
    return _sb(sk_v)


def secret_from_bytes(raw: bytes) -> Scalar:
    return Scalar.from_be_bytes(raw)


def nyms_of(sk_v: Scalar, epoch: int, count: int) -> list[str]:
    """Every pid a credential can produce in an epoch (for revocation after a trace)."""
    return [pid_of(_gb(scope_point(scope_of(epoch, j)) * sk_v)) for j in range(count)]


def enroll(issuer: IssuerKey, vehicle_class: str, epoch: int) -> Credential:
    """Whole blind issuance in one call (setup, before the run)."""
    sk_v = rand_scalar()
    nonce = secrets.token_bytes(16)
    C, pok = commit_secret(sk_v, nonce)
    A, e = issue(issuer, C, pok, nonce, vehicle_class, epoch)
    cred = Credential(sk_v, A, e, vehicle_class, epoch, _gb(issuer.pk))
    if not cred.valid():
        raise RuntimeError("BBS issuance produced an invalid credential")
    return cred
