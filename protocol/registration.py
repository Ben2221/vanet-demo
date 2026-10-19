"""Vehicle pseudonym generation and TA-side Merkle registration."""
from __future__ import annotations
import random
import secrets
from dataclasses import dataclass
from .crypto import keygen, MerkleTree, is_valid_public_key

@dataclass
class Pseudonym:
    pid: str
    secret: int
    public_key: bytes
    epoch: int
    vehicle_class: str = "car"
    merkle_path: list[tuple[str, str]] | None = None

def pseudonym_leaf(pid: str, public_key: bytes, vehicle_class: str) -> bytes:
    """Merkle leaf for one pseudonym. Binding pid and class into the leaf means a
    vehicle cannot claim another pid or class than the TA registered, and the
    ledger needs no per-pseudonym record (only the root is published)."""
    fields = [b"VANET-LEAF-v1", pid.encode(), public_key, vehicle_class.encode()]
    return b"".join(len(item).to_bytes(4, "big") + item for item in fields)

def create_pseudonyms(count: int, epoch: int = 1, vehicle_class: str = "car") -> list[Pseudonym]:
    if count < 1:
        raise ValueError("count must be positive")
    return [Pseudonym(secrets.token_hex(8), *keygen(), epoch, vehicle_class) for _ in range(count)]

def register_pseudonyms(pseudonyms: list[Pseudonym], ledger, valid_until: float):
    """Shuffle leaves before tree creation; publish only root to ledger.
    Validates that each public key is a valid elliptic curve point.
    """
    if not pseudonyms:
        raise ValueError("cannot register an empty pseudonym set")
    epochs = {p.epoch for p in pseudonyms}
    if len(epochs) != 1:
        raise ValueError("register one epoch at a time")
    if len({p.pid for p in pseudonyms}) != len(pseudonyms):
        raise ValueError("duplicate pseudonym id")
    for p in pseudonyms:
        if not is_valid_public_key(p.public_key):
            raise ValueError(f"invalid public key curve point for pseudonym {p.pid}")
    shuffled = pseudonyms[:]
    random.SystemRandom().shuffle(shuffled)
    tree = MerkleTree([pseudonym_leaf(p.pid, p.public_key, p.vehicle_class) for p in shuffled])
    for index, p in enumerate(shuffled):
        p.merkle_path = tree.proof(index)
    ledger.register_root(shuffled[0].epoch, tree.root.hex(), valid_until)
    return tree.root
