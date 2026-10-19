"""Threshold Identity Escrow with Shamir Secret Sharing and AES-256-GCM.

Protocol specification:
- TA encrypts each vehicle's real identity record (AES-GCM).
- TA splits the AES key among RSU organizations with Shamir secret sharing (t-of-n).
- An RSU releases its share only if GetTrace shows the request approved on the ledger.
- TA alone cannot unmask anyone.
- At threshold (e.g. 2f+1 RSUs), the key is reconstructed and real identity revealed.
- TA then revokes all of that vehicle's pseudonyms on the ledger.
"""
from __future__ import annotations
import json
import os
import secrets
from dataclasses import dataclass
from typing import Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# A prime strictly greater than 2^256 for exact arithmetic over 256-bit AES keys
# 2^256 + 297 is prime
PRIME_256 = 115792089237316195423570985008687907853269984665640564039457584007913129640233

class ShamirSecretSharing:
    """Shamir (t, n) threshold secret sharing over Galois Field GF(P)."""

    def __init__(self, prime: int = PRIME_256):
        self.prime = prime

    def split(self, secret_bytes: bytes, threshold: int, total_shares: int) -> list[tuple[int, int]]:
        if threshold < 1 or threshold > total_shares:
            raise ValueError("threshold must be 1 <= threshold <= total_shares")
        secret_int = int.from_bytes(secret_bytes, "big")
        if secret_int >= self.prime:
            raise ValueError("secret exceeds field prime")

        # Polynomial: f(x) = secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1} mod P
        coeffs = [secret_int] + [secrets.randbelow(self.prime - 1) + 1 for _ in range(threshold - 1)]

        shares = []
        for x in range(1, total_shares + 1):
            y = sum(c * pow(x, exp, self.prime) for exp, c in enumerate(coeffs)) % self.prime
            shares.append((x, y))
        return shares

    def combine(self, shares: list[tuple[int, int]], threshold: int | None = None) -> bytes:
        if threshold is not None and len(shares) < threshold:
            raise ValueError(f"insufficient shares to reconstruct: got {len(shares)}, need {threshold}")
        k = len(shares)
        if k < 1:
            raise ValueError("no shares provided")
        if len({x for x, _ in shares}) != k:
            raise ValueError("duplicate share index")

        # Lagrange interpolation at x = 0:
        # S = sum_{j=0}^{k-1} y_j * prod_{m != j} (0 - x_m) / (x_j - x_m) mod P
        secret_int = 0
        for j, (xj, yj) in enumerate(shares):
            num, den = 1, 1
            for m, (xm, _) in enumerate(shares):
                if m != j:
                    num = (num * -xm) % self.prime
                    den = (den * (xj - xm)) % self.prime
            inv_den = pow(den, -1, self.prime)
            term = (yj * num * inv_den) % self.prime
            secret_int = (secret_int + term) % self.prime

        return secret_int.to_bytes(32, "big")

@dataclass
class IdentityEscrowRecord:
    encrypted_payload: dict[str, Any]
    threshold: int
    total_shares: int
    rsu_orgs: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "encrypted_payload": self.encrypted_payload,
            "threshold": self.threshold,
            "total_shares": self.total_shares,
            "rsu_orgs": self.rsu_orgs,
        }

class RSUEscrowAgent:
    """RSU organization key escrow participant."""
    def __init__(self, rsu_id: str, share: tuple[int, int], ledger: Any):
        self.rsu_id = rsu_id
        self.share = share
        self.ledger = ledger

    def release_share(self, req_id: str) -> tuple[int, int]:
        """Release key share only if GetTrace shows the request approved on the ledger."""
        trace = self.ledger.get_trace(req_id)
        if not trace or not trace.get("approved"):
            raise PermissionError(f"trace request {req_id} is not approved on the ledger")
        return self.share

class ThresholdIdentityEscrow:
    """Complete TA & RSU Threshold Identity Escrow subsystem."""
    def __init__(self, threshold: int | None = None, rsu_orgs: list[str] | None = None):
        self.rsu_orgs = rsu_orgs or ["RSU-Org-1", "RSU-Org-2", "RSU-Org-3", "RSU-Org-4", "RSU-Org-5"]
        # default 2f+1 with f = floor((n-1)/3) tolerated faulty RSU organizations (team decision)
        self.threshold = threshold if threshold is not None else 2 * ((len(self.rsu_orgs) - 1) // 3) + 1
        if not 1 <= self.threshold <= len(self.rsu_orgs):
            raise ValueError("threshold must be between 1 and the number of RSU organizations")
        self.shamir = ShamirSecretSharing()

    def escrow_vehicle_identity(self, real_identity: dict[str, Any]) -> tuple[IdentityEscrowRecord, dict[str, tuple[int, int]]]:
        """TA encrypts real identity record with AES-256-GCM and splits key across RSUs."""
        raw_identity = json.dumps(real_identity, sort_keys=True).encode("utf-8")
        aes_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, raw_identity, None)

        shares = self.shamir.split(aes_key, threshold=self.threshold, total_shares=len(self.rsu_orgs))
        shares_by_rsu = {self.rsu_orgs[i]: shares[i] for i in range(len(self.rsu_orgs))}

        record = IdentityEscrowRecord(
            encrypted_payload={
                "nonce": nonce.hex(),
                "ciphertext": ciphertext.hex(),
            },
            threshold=self.threshold,
            total_shares=len(self.rsu_orgs),
            rsu_orgs=self.rsu_orgs,
        )
        return record, shares_by_rsu

    def unmask(self, record: IdentityEscrowRecord, collected_shares: list[tuple[int, int]]) -> dict[str, Any]:
        """Reconstruct AES key from threshold shares and decrypt the vehicle's real identity record."""
        if len(collected_shares) < record.threshold:
            raise ValueError(f"insufficient shares: got {len(collected_shares)}, required {record.threshold}")
        recovered_key = self.shamir.combine(collected_shares[:record.threshold], threshold=record.threshold)

        nonce = bytes.fromhex(record.encrypted_payload["nonce"])
        ciphertext = bytes.fromhex(record.encrypted_payload["ciphertext"])

        aesgcm = AESGCM(recovered_key)
        try:
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"failed to decrypt identity escrow: {e}") from e
