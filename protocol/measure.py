"""Measure the protocol's cryptographic operations on this machine (Person 3's code).

The scenario turns these into processing delays (node.processing_delay(op)), so
authentication and handover latency include the real cost of the ZKP, the
Merkle check and the signatures, not only the radio time.

    python -m protocol.measure                       # writes protocol/compute_times.json
    python -m protocol.measure --scale 8             # e.g. an OBU about 8x slower than this PC
    python network/run_scenario.py --protocol real --compute-times protocol/compute_times.json

The scenario loads protocol/compute_times.json by itself when --compute-times is
not given (see network/run_scenario.py). Times are seconds per operation.

| op            | what                                                       | who            |
|---------------|------------------------------------------------------------|----------------|
| prove         | Schnorr ZKP with a precomputed commitment (online part)    | vehicle        |
| prove_full    | Schnorr ZKP including the commitment g^r                   | vehicle (idle) |
| verify        | Schnorr ZKP verification                                   | RSU            |
| merkle_check  | Merkle membership proof, depth for --leaves pseudonyms     | RSU            |
| sign          | Schnorr signature (ticket, beacon, handover request)       | RSU / vehicle  |
| verify_sig    | Schnorr signature verification (beacon, ticket, request)   | RSU / vehicle  |
| bsm_sign      | sign one BSM payload (canonical JSON + Schnorr)            | vehicle, 10 Hz |
| bsm_verify    | verify one BSM (ticket + BSM signature)                    | RSU            |
| ec_mult       | one secp256k1 point multiplication (unit cost)             | op_counts.py   |
| hash          | one SHA-256 of 64 bytes (unit cost)                        | op_counts.py   |
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import time
from pathlib import Path

from .crypto import _point_mul, CommitmentPool, MerkleTree, keygen, prove, schnorr_sign, schnorr_verify, verify, verify_merkle
from .registration import pseudonym_leaf
from .vehicle import auth_context, canonical_json

HERE = Path(__file__).resolve().parent


def bench(fn, n: int) -> float:
    fn()
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n


def measure(n: int = 300, leaves: int = 500) -> dict:
    sk, pk = keygen()
    ctx = auth_context("rsu0", "ab" * 16, 12.5, "road_access", "00" * 8, "car")
    pool = CommitmentPool(initial_size=0)
    pool.refill(n + 1)
    proof = prove(sk, ctx)

    tree_leaves = [pseudonym_leaf(f"{i:016x}", keygen()[1], "car") for i in range(leaves)]
    tree = MerkleTree(tree_leaves)
    path, root = tree.proof(0), tree.root

    ticket_payload = {"pid": "00" * 8, "pk": pk.hex(), "service": "road_access", "class": "car",
                      "issuer": "rsu0", "issued_at": 12.5, "expiry": 42.5}
    rsu_sk, rsu_pk = keygen()
    ticket = {"payload": ticket_payload, "signature": schnorr_sign(rsu_sk, canonical_json(ticket_payload))}
    bsm_payload = {"pid": "00" * 8, "ticket": ticket,
                   "fields": {"seq": 1, "t": 12.6, "x": 100.0, "y": 200.0, "speed": 13.9, "heading": 90.0}}
    bsm_sig = schnorr_sign(sk, canonical_json(bsm_payload))
    msg = canonical_json(ticket_payload)
    sig = schnorr_sign(rsu_sk, msg)

    def bsm_verify() -> None:
        schnorr_verify(rsu_pk, canonical_json(ticket["payload"]), ticket["signature"])
        schnorr_verify(pk, canonical_json(bsm_payload), bsm_sig)

    return {
        "prove": bench(lambda: prove(sk, ctx, commitment=pool.pop()), n),
        "prove_full": bench(lambda: prove(sk, ctx), n),
        "verify": bench(lambda: verify(pk, proof, ctx), n),
        "merkle_check": bench(lambda: verify_merkle(tree_leaves[0], path, root), n),
        "sign": bench(lambda: schnorr_sign(rsu_sk, msg), n),
        "verify_sig": bench(lambda: schnorr_verify(rsu_pk, msg, sig), n),
        "bsm_sign": bench(lambda: schnorr_sign(sk, canonical_json(bsm_payload)), n),
        "bsm_verify": bench(bsm_verify, n),
        "ec_mult": bench(lambda: _point_mul(pk, 0x1234567890ABCDEF), n),
        "hash": bench(lambda: hashlib.sha256(b"x" * 64).digest(), n * 10),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=300, help="repetitions per operation")
    ap.add_argument("--leaves", type=int, default=500, help="pseudonyms per epoch (sets the Merkle depth)")
    ap.add_argument("--scale", type=float, default=1.0, help="multiply every time (slower vehicle hardware)")
    ap.add_argument("--out", default=str(HERE / "compute_times.json"))
    a = ap.parse_args()
    times = {op: t * a.scale for op, t in measure(a.n, a.leaves).items()}
    out = {**times, "_meta": {"machine": platform.processor() or platform.machine(),
                              "python": platform.python_version(), "scale": a.scale,
                              "merkle_depth": math.ceil(math.log2(max(2, a.leaves))), "unit": "s"}}
    Path(a.out).write_text(json.dumps(out, indent=2) + "\n")
    for op, t in times.items():
        print(f"{op:13s} {t * 1000:8.3f} ms")
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
