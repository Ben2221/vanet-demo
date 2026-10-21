"""Batch verification of signed BSMs (--batch-verify).

``batch_verify`` checks n Schnorr signatures (schnorr_sign) or BIP340 signatures
(bip340_sign, --compact-wire) with one equation, using random 128-bit weights a_i
(a_1 = 1):

    (sum a_i s_i) * G  ==  sum a_i * R_i  +  sum (a_i c_i) * P_i

A forged signature passes only with probability about 2^-128. If the batch fails,
``find_invalid`` splits it in halves until the bad signatures are found, so one
forged BSM costs about 2 log2(n) extra batch checks instead of rejecting the batch.

What a batch saves comes from multi-scalar multiplication (Straus / Pippenger), which
coincurve does not expose, so the simulator does not time coincurve here. Instead
``measure_speedup`` times single and batch verification with the *same* pure-Python
secp256k1 arithmetic below (fixed-base table for G in both, Straus for small
batches, Pippenger for large ones) and reports the per-signature speedup. The
simulator scales the measured single-verification time (protocol/measure.py) by that
factor (``batch_cost``).
"""
from __future__ import annotations

import hashlib
import secrets
import time

from .crypto import N, _base_mul, _hash_scalar, _parse, _point_mul, _bip340_digest

P = 2 ** 256 - 2 ** 32 - 977
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


# ------------------------------------------------------------ the real check
def _lift_x(x: bytes) -> bytes:
    """BIP340 lift_x: the point with x-coordinate x and even y, compressed."""
    return b"\x02" + x


def _bip340_challenge(r: bytes, px: bytes, msg32: bytes) -> int:
    tag = hashlib.sha256(b"BIP0340/challenge").digest()
    return int.from_bytes(hashlib.sha256(tag + tag + r + px + msg32).digest(), "big") % N


def _terms(item) -> tuple[int, bytes, int, bytes] | None:
    """(s, R, c, P) of one (public_key, message, signature) item, or None if malformed."""
    public_key, message, signature = item
    try:
        if isinstance(signature, str):                 # BIP340, 64 bytes hex
            sig = bytes.fromhex(signature)
            if len(sig) != 64:
                return None
            r, s = sig[:32], int.from_bytes(sig[32:], "big")
            px = _parse(bytes(public_key)).format(compressed=True)[1:]
            if s >= N:
                return None
            return s, _lift_x(r), _bip340_challenge(r, px, _bip340_digest(message)), _lift_x(px)
        R = bytes.fromhex(signature["R"])
        s = int.from_bytes(bytes.fromhex(signature["s"]), "big")
        if not 0 < s < N:
            return None
        _parse(R)
        return s, R, _hash_scalar(b"SCHNORR-SIG-v1", R, bytes(public_key), message), bytes(public_key)
    except Exception:
        return None


def batch_verify(items: list) -> bool:
    """True if every (public_key, message, signature) in ``items`` is valid."""
    if not items:
        return True
    from coincurve import PublicKey
    lhs = 0
    rhs = []
    for idx, item in enumerate(items):
        t = _terms(item)
        if t is None:
            return False
        s, R, c, Pk = t
        a = 1 if idx == 0 else secrets.randbits(128) | 1
        lhs = (lhs + a * s) % N
        try:
            rhs.append(_parse(R) if a == 1 else _parse(_point_mul(R, a)))
            rhs.append(_parse(_point_mul(Pk, a * c % N)))
        except Exception:
            return False
    try:
        right = PublicKey.combine_keys(rhs).format(compressed=True)
    except Exception:
        return False                                   # sum is the point at infinity
    return lhs != 0 and _base_mul(lhs) == right


def find_invalid(items: list, check=batch_verify) -> tuple[list[int], int]:
    """Indices of invalid items and the number of batch checks used (binary splitting)."""
    checks = 0

    def rec(lo: int, hi: int) -> list[int]:
        nonlocal checks
        checks += 1
        if check(items[lo:hi]):
            return []
        if hi - lo == 1:
            return [lo]
        mid = (lo + hi) // 2
        return rec(lo, mid) + rec(mid, hi)

    return rec(0, len(items)), checks


def batch_cost(n: int, single: float, speedup: dict[int, float], invalid: int = 0) -> float:
    """Seconds to verify n signatures as one batch: n * single / speedup(n), plus the
    binary-splitting checks when ``invalid`` of them are bad."""
    if n <= 0:
        return 0.0
    if n == 1 or not speedup:
        return n * single
    sizes = sorted(speedup)
    k = max([s for s in sizes if s <= n] or [sizes[0]])
    base = n * single / max(1.0, speedup[k])
    if invalid:
        # each bad signature costs about 2*log2(n) checks of shrinking halves: ~ 2 * base
        base *= 1 + 2 * invalid
        base = min(base, n * single * 1.2)            # never much worse than one by one
    return base


# --------------------------------------------- pure-Python curve for timing only
def _jdouble(p):
    X, Y, Z = p
    if not Y:
        return (0, 1, 0)
    YY = Y * Y % P
    S = 4 * X * YY % P
    M = 3 * X * X % P
    X3 = (M * M - 2 * S) % P
    return (X3, (M * (S - X3) - 8 * YY * YY) % P, 2 * Y * Z % P)


def _jadd(p, q):
    if not p[2]:
        return q
    if not q[2]:
        return p
    X1, Y1, Z1 = p
    X2, Y2, Z2 = q
    Z1Z1, Z2Z2 = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2Z2 % P, X2 * Z1Z1 % P
    S1, S2 = Y1 * Z2 * Z2Z2 % P, Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        return _jdouble(p) if S1 == S2 else (0, 1, 0)
    H, R = (U2 - U1) % P, (S2 - S1) % P
    HH = H * H % P
    HHH = H * HH % P
    V = U1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    return (X3, (R * (V - X3) - S1 * HHH) % P, H * Z1 * Z2 % P)


def _neg(p):
    return (p[0], (-p[1]) % P, p[2])


INF = (0, 1, 0)
G_J = (GX, GY, 1)
W = 4


def _g_table():
    """Fixed-base comb for G: T[k][d] = d * 2^(4k) * G, so d*G needs no doublings."""
    table, base = [], G_J
    for _ in range(64):
        row = [INF]
        for _ in range(15):
            row.append(_jadd(row[-1], base))
        table.append(row)
        for _ in range(W):
            base = _jdouble(base)
    return table


_GT = None


def _gmul(k: int):
    global _GT
    if _GT is None:
        _GT = _g_table()
    acc = INF
    for i in range(64):
        d = (k >> (4 * i)) & 15
        if d:
            acc = _jadd(acc, _GT[i][d])
    return acc


def _straus(points, scalars):
    tables = []
    for p in points:
        row = [INF, p]
        for _ in range(14):
            row.append(_jadd(row[-1], p))
        tables.append(row)
    bits = max(s.bit_length() for s in scalars)
    acc = INF
    for w in range((bits + W - 1) // W - 1, -1, -1):
        for _ in range(W):
            acc = _jdouble(acc)
        for t, s in zip(tables, scalars):
            d = (s >> (W * w)) & 15
            if d:
                acc = _jadd(acc, t[d])
    return acc


def _pippenger(points, scalars):
    n = len(points)
    c = max(2, n.bit_length() - 2)
    bits = max(s.bit_length() for s in scalars)
    acc = INF
    for w in range((bits + c - 1) // c - 1, -1, -1):
        for _ in range(c):
            acc = _jdouble(acc)
        buckets = [INF] * (1 << c)
        for p, s in zip(points, scalars):
            d = (s >> (c * w)) & ((1 << c) - 1)
            if d:
                buckets[d] = _jadd(buckets[d], p)
        run, total = INF, INF
        for d in range((1 << c) - 1, 0, -1):
            run = _jadd(run, buckets[d])
            total = _jadd(total, run)
        acc = _jadd(acc, total)
    return acc


def _msm(points, scalars):
    return _straus(points, scalars) if len(points) <= 128 else _pippenger(points, scalars)


def _rand_point():
    k = secrets.randbelow(N - 1) + 1
    return _gmul(k)


def measure_speedup(sizes=(2, 4, 8, 16, 32, 64), reps: int = 3) -> dict[int, float]:
    """Per-signature speedup of batch over single verification, same arithmetic.

    single: s*G (fixed-base table) + Straus(-c*P) and compare with R
    batch:  (sum a s)*G (table) + MSM over the 2n points R_i, P_i with -a_i, -a_i c_i
    """
    pts = [_rand_point() for _ in range(2 * max(sizes))]
    sc = [secrets.randbelow(N) for _ in range(2 * max(sizes))]

    def single():
        _jadd(_gmul(sc[0]), _straus([pts[0]], [sc[1]]))

    def batch(n):
        scal = []
        for i in range(n):
            a = secrets.randbits(128) | 1
            scal += [a, a * sc[i] % N]
        _jadd(_gmul(sc[0]), _msm(pts[:2 * n], scal))

    def timed(fn):
        fn()
        t0 = time.perf_counter()
        for _ in range(reps):
            fn()
        return (time.perf_counter() - t0) / reps

    t1 = timed(single)
    return {n: round(n * t1 / timed(lambda n=n: batch(n)), 3) for n in sizes}
