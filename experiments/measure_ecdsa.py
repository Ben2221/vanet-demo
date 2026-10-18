"""Measure ECDSA P-256 sign and verify (and one SHA-256) on this machine (Person 4, baselines).

The ECDSA pseudonym-certificate baseline needs processing delays for the
scenario. Person 3 measures the new scheme (prove, verify, sign, merkle_check);
this measures the baseline's primitives the same way, so the comparison is fair:

    python experiments/measure_ecdsa.py                  # writes experiments/compute_times_ecdsa.json
    python network/run_scenario.py --compute-times experiments/compute_times_all.json ...

Merge it with Person 3's file:  python experiments/measure_ecdsa.py --merge protocol_times.json
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent


def bench(fn, n: int) -> float:
    fn()
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n


def measure(n: int = 500) -> dict:
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key()
    msg = b"x" * 200
    sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
    sign_s = bench(lambda: key.sign(msg, ec.ECDSA(hashes.SHA256())), n)
    verify_s = bench(lambda: pub.verify(sig, msg, ec.ECDSA(hashes.SHA256())), n)
    # NOTE: no EC-multiplication time is measured here on purpose. OpenSSL's P-256 is heavily
    # optimised and its generic secp256k1 is not; the new scheme's unit costs ("ec_mult") must come
    # from Person 3's own implementation (coincurve), measured the same way, and be merged with --merge.
    import hashlib
    hash_s = bench(lambda: hashlib.sha256(b"x" * 64).digest(), n * 10)
    return {"ecdsa_sign": sign_s, "ecdsa_verify": verify_s, "hash": hash_s}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=500)
    ap.add_argument("--merge", default=None, help="Person 3's compute-times JSON to merge with")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    times = measure(a.n)
    print({k: f"{v * 1000:.3f} ms" for k, v in times.items()})
    if a.merge:
        times = {**json.loads(Path(a.merge).read_text()), **times}
    out = Path(a.out) if a.out else HERE / ("compute_times_all.json" if a.merge else "compute_times_ecdsa.json")
    out.write_text(json.dumps(times, indent=2))
    print("written", out)
