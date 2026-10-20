"""ECQV implicit certificates (SEC 4) on secp256k1, for --implicit-cert tickets.

An explicit ticket carries the pseudonym key ``pk`` and the RSU's Schnorr signature
(~110 bytes). An implicit certificate carries only a 33-byte reconstruction point
``pu``; anyone who trusts the issuing RSU key Q_CA derives the ticket key

    Q_U = e * P_U + Q_CA,   e = H(cert)

and only the requester can know the matching secret d_U = e * k_U + r. A forged or
altered certificate yields a key nobody knows, so the certificate is authenticated
implicitly: by the first signature (BSM, handover request) or MAC made with d_U.

Issuance (inside the ZKP authentication, which binds ``R_U`` into its context so it
cannot be swapped on the air):

    vehicle:  k_U random,  R_U = k_U * G                       (AUTH_REQ "cert_req")
    RSU:      k random,    P_U = R_U + k * G,  cert = fields + P_U
              e = H(cert), r = e * k + d_CA                     (AUTH_RESP ticket + "r")
    vehicle:  d_U = e * k_U + r,  check d_U * G == e * P_U + Q_CA
"""
from __future__ import annotations

import hashlib
import json
import secrets
from functools import lru_cache

from .crypto import N, _base_mul, _i32, _parse, _point_add, _point_mul


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def cert_hash(cert: dict) -> int:
    """e = H(cert) as a scalar; the certificate is the whole ticket payload incl. ``pu``."""
    e = int.from_bytes(hashlib.sha256(b"VANET-ECQV-v1" + _canonical(cert)).digest(), "big") % N
    return e or 1


def request() -> tuple[int, bytes]:
    """Vehicle side: (k_U, R_U = k_U * G)."""
    k = secrets.randbelow(N - 1) + 1
    return k, _base_mul(k)


def issue(ca_secret: int, request_point: bytes, fields: dict) -> tuple[dict, int]:
    """RSU side: certificate (``fields`` plus ``pu``) and the private-key contribution r."""
    _parse(bytes(request_point))                    # raises on an invalid point
    k = secrets.randbelow(N - 1) + 1
    pu = _point_add(bytes(request_point), _base_mul(k))
    cert = {**fields, "pu": pu.hex()}
    r = (cert_hash(cert) * k + ca_secret) % N
    return cert, r


def receive(k_request: int, r: int, cert: dict, ca_public: bytes) -> int | None:
    """Vehicle side: the ticket secret d_U, or None if it does not match the certificate."""
    d = (cert_hash(cert) * k_request + int(r)) % N
    if d == 0:
        return None
    try:
        return d if _base_mul(d) == reconstruct(cert, ca_public) else None
    except Exception:
        return None


def reconstruct(cert: dict, ca_public: bytes) -> bytes:
    """Ticket public key Q_U = e * P_U + Q_CA (compressed). Cached: a ticket repeats."""
    return _reconstruct(_canonical(cert), bytes(ca_public))


@lru_cache(maxsize=8192)
def _reconstruct(cert_bytes: bytes, ca_public: bytes) -> bytes:
    cert = json.loads(cert_bytes)
    return _point_add(_point_mul(bytes.fromhex(cert["pu"]), cert_hash(cert)), ca_public)


def scalar_hex(x: int) -> str:
    return _i32(x).hex()
