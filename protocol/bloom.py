"""Bloom filter of recently revoked pseudonyms, carried in signed RSU beacons
(--revocation-filter), so vehicles can drop BSMs of revoked senders themselves.

Only pseudonyms revoked (or quarantined) within the last ticket lifetime are needed:
an older revoked pseudonym cannot hold an unexpired ticket. The filter has
``BITS_PER_ITEM`` bits per entry (about 1 % false positives with K_HASHES = 7) and at
least MIN_BYTES; the hash count is fixed, the size follows from the encoding.
"""
from __future__ import annotations

import hashlib
import math

K_HASHES = 7
BITS_PER_ITEM = 10
MIN_BYTES = 8


def _positions(item: str, m_bits: int) -> list[int]:
    h = hashlib.sha256(b"VANET-RF" + item.encode()).digest()
    h1, h2 = int.from_bytes(h[:8], "big"), int.from_bytes(h[8:16], "big") | 1
    return [(h1 + i * h2) % m_bits for i in range(K_HASHES)]


def build(items) -> str:
    """Hex encoding of a filter holding ``items``."""
    items = sorted(set(items))
    nbytes = max(MIN_BYTES, math.ceil(len(items) * BITS_PER_ITEM / 8))
    bits = bytearray(nbytes)
    for it in items:
        for p in _positions(it, nbytes * 8):
            bits[p // 8] |= 1 << (p % 8)
    return bits.hex()


def contains(filter_hex: str, item: str) -> bool:
    try:
        bits = bytes.fromhex(filter_hex)
    except ValueError:
        return False
    if not bits:
        return False
    return all(bits[p // 8] >> (p % 8) & 1 for p in _positions(item, len(bits) * 8))


def false_positive_rate(n: int, nbytes: int) -> float:
    m = nbytes * 8
    return (1 - math.exp(-K_HASHES * n / m)) ** K_HASHES if m else 1.0
