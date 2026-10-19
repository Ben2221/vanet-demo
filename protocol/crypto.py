"""Cryptographic primitives for the VANET Cryptography and Authentication Protocol."""
from __future__ import annotations
import hashlib
import secrets
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable
from coincurve import PrivateKey, PublicKey

# secp256k1 group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G_COMPRESSED = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

def _i32(x: int) -> bytes:
    return int(x % N).to_bytes(32, "big")

def _hash_scalar(*parts: bytes) -> int:
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return int.from_bytes(h.digest(), "big") % N

@lru_cache(maxsize=8192)
def _parse(point: bytes) -> PublicKey:
    """Parsed curve point; cached because the same keys (RSUs, pseudonyms) are checked over and over."""
    return PublicKey(point)

def _point_mul(point: bytes, scalar: int) -> bytes:
    if scalar % N == 0:
        raise ValueError("zero scalar does not produce a valid public point")
    return _parse(point).multiply(_i32(scalar)).format(compressed=True)

def _base_mul(scalar: int) -> bytes:
    """scalar * G with libsecp256k1's precomputed generator tables (same result as multiplying G)."""
    if scalar % N == 0:
        raise ValueError("secret/scalar must be non-zero")
    return PrivateKey(_i32(scalar)).public_key.format(compressed=True)

def _point_add(a: bytes, b: bytes) -> bytes:
    return PublicKey.combine_keys([_parse(a), _parse(b)]).format(compressed=True)

def _valid_point(point: bytes) -> bool:
    try:
        _parse(bytes(point))
        return True
    except Exception:
        return False

def is_valid_public_key(point: bytes) -> bool:
    """Check if point is a valid curve point on secp256k1."""
    return _valid_point(point)

def keygen() -> tuple[int, bytes]:
    """Return (private scalar, compressed public key)."""
    x = secrets.randbelow(N - 1) + 1
    return x, _base_mul(x)

@dataclass(frozen=True)
class Commitment:
    """Precomputed commitment pair (r, R = g^r) computed while idle."""
    r: int
    R: bytes

    def __post_init__(self):
        if not 1 <= self.r < N:
            raise ValueError("invalid scalar for commitment")

class CommitmentPool:
    """Pool of precomputed commitments (g^r computed while idle).
    Each r is used exactly once to ensure zero-knowledge and prevent private key recovery.
    """
    def __init__(self, initial_size: int = 10):
        self._pool: list[Commitment] = []
        if initial_size > 0:
            self.refill(initial_size)

    def refill(self, count: int) -> None:
        for _ in range(count):
            r = secrets.randbelow(N - 1) + 1
            R = _base_mul(r)
            self._pool.append(Commitment(r=r, R=R))

    def pop(self) -> Commitment:
        if not self._pool:
            self.refill(5)
        return self._pool.pop()

    def __len__(self) -> int:
        return len(self._pool)

@dataclass(frozen=True)
class SchnorrProof:
    commitment: str
    response: str

    def to_dict(self) -> dict:
        return {"commitment": self.commitment, "response": self.response}

    @classmethod
    def from_dict(cls, obj: dict) -> "SchnorrProof":
        return cls(str(obj["commitment"]), str(obj["response"]))

def prove(secret: int, ctx: bytes, commitment: Commitment | None = None) -> SchnorrProof:
    """Non-interactive Schnorr proof; callers must use a fresh nonce/commitment per proof.
    Supports precomputed commitments (g^r) for ultra-low latency proof generation."""
    if not 1 <= secret < N:
        raise ValueError("invalid secret scalar")
    y = _base_mul(secret)
    if commitment is not None:
        r = commitment.r
        R = commitment.R
    else:
        r = secrets.randbelow(N - 1) + 1  # fresh and never reused
        R = _base_mul(r)
    c = _hash_scalar(b"SCHNORR-FS-v1", R, y, ctx)
    s = (r + c * secret) % N
    return SchnorrProof(R.hex(), _i32(s).hex())


def verify(public_key: bytes, proof: SchnorrProof, ctx: bytes) -> bool:
    """Verify sG = R + cY with challenge bound to the complete context."""
    try:
        if not _valid_point(public_key):
            return False
        R = bytes.fromhex(proof.commitment)
        s_bytes = bytes.fromhex(proof.response)
        if len(s_bytes) != 32 or not _valid_point(R):
            return False
        s = int.from_bytes(s_bytes, "big")
        if s >= N:
            return False
        c = _hash_scalar(b"SCHNORR-FS-v1", R, public_key, ctx)
        lhs = _base_mul(s) if s else None
        cY = _point_mul(public_key, c) if c else None
        if lhs is None:
            # The identity point is not represented by coincurve's PublicKey.
            return False
        rhs = _point_add(R, cY) if cY else R
        return lhs == rhs
    except Exception:
        return False

def schnorr_sign(secret: int, message: bytes) -> dict:
    """Schnorr signature (R, s) with a fresh random nonce."""
    if not 1 <= secret < N:
        raise ValueError("invalid secret scalar")
    y = _base_mul(secret)
    r = secrets.randbelow(N - 1) + 1
    R = _base_mul(r)
    c = _hash_scalar(b"SCHNORR-SIG-v1", R, y, message)
    s = (r + c * secret) % N
    return {"R": R.hex(), "s": _i32(s).hex()}

def schnorr_verify(public_key: bytes, message: bytes, signature: dict) -> bool:
    try:
        R = bytes.fromhex(signature["R"])
        s = int.from_bytes(bytes.fromhex(signature["s"]), "big")
        if not _valid_point(public_key) or not _valid_point(R) or not 0 <= s < N or s == 0:
            return False
        c = _hash_scalar(b"SCHNORR-SIG-v1", R, public_key, message)
        lhs = _base_mul(s)
        rhs = _point_add(R, _point_mul(public_key, c)) if c else R
        return lhs == rhs
    except Exception:
        return False

def hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()

def hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()

class MerkleTree:
    """Binary Merkle tree. Leaves are shuffled by registration code before construction."""
    def __init__(self, leaves: Iterable[bytes]):
        self.leaves = [hash_leaf(x) for x in leaves]
        if not self.leaves:
            raise ValueError("Merkle tree needs at least one leaf")
        self.levels = [self.leaves]
        while len(self.levels[-1]) > 1:
            level = self.levels[-1]
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else level[i]
                nxt.append(hash_node(left, right))
            self.levels.append(nxt)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    def proof(self, index: int) -> list[tuple[str, str]]:
        if not 0 <= index < len(self.leaves):
            raise IndexError(index)
        path = []
        idx = index
        for level in self.levels[:-1]:
            sibling_idx = idx ^ 1
            sibling = level[sibling_idx] if sibling_idx < len(level) else level[idx]
            path.append(("left" if sibling_idx < idx else "right", sibling.hex()))
            idx //= 2
        return path

def verify_merkle(leaf_data: bytes, path: list[tuple[str, str]], root: bytes) -> bool:
    current = hash_leaf(leaf_data)
    try:
        for side, sibling_hex in path:
            sibling = bytes.fromhex(sibling_hex)
            if len(sibling) != 32 or side not in ("left", "right"):
                return False
            current = hash_node(sibling, current) if side == "left" else hash_node(current, sibling)
        return secrets.compare_digest(current, root)
    except Exception:
        return False
