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
    for p in pseudonyms:
        if not is_valid_public_key(p.public_key):
            raise ValueError(f"invalid public key curve point for pseudonym {p.pid}")
    shuffled = pseudonyms[:]
    random.SystemRandom().shuffle(shuffled)
    tree = MerkleTree([p.public_key for p in shuffled])
    for index, p in enumerate(shuffled):
        p.merkle_path = tree.proof(index)
        if hasattr(ledger, "register_pseudonym"):
            ledger.register_pseudonym(p.pid, p.vehicle_class)
    ledger.register_root(shuffled[0].epoch, tree.root.hex(), valid_until)
    return tree.root
