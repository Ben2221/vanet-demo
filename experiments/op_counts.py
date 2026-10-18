"""Operation-count table: computation and communication cost per scheme (Person 4).

    python experiments/op_counts.py                      # prints the table, writes experiments/results/op_counts.{md,csv}
    python experiments/op_counts.py --times times.json   # add estimated times from measured unit costs

Counts per full authentication and per handover for: our scheme (Schnorr zero-knowledge
proof + Merkle membership + shared ledger state), the ECDSA pseudonym-certificate
baseline and the central-authority baseline. Message sizes are computed from the
formats the scenario uses (network/protocols/stub_auth.py today; replace the constants
below with Person 3's documented sizes once protocol/messages.py exists).

The counts are the comparison. Times are only estimated when --times has "ec_mult" and "hash":
take "ec_mult" from Person 3's measurement of the real implementation (coincurve), not from a
different library, or the comparison favours whichever curve its library optimises.

Papers from the review slides: add one row each to experiments/papers_review.csv (header
is created on first run) and they are appended to the table with the same columns.
Their numbers must come from the papers, not from this file.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from network.protocols import stub_auth as S

HERE = Path(__file__).resolve().parent
PAPERS = HERE / "papers_review.csv"
PAPER_COLS = ["scheme", "source", "vehicle_ec_mult", "vehicle_hash", "rsu_ec_mult", "rsu_hash",
              "auth_bytes", "handover_bytes", "bsm_overhead_bytes", "notes"]

ECDSA_SIG, ECDSA_CERT, CERT_DIGEST = 64, 130, 8
AUTH_REQ_HDR, AUTH_RESP_HDR, HO_REQ_HDR = S._AUTH_REQ.size, S._AUTH_RESP.size, S._HO_REQ.size
BACKBONE = 2 * 64 + 194          # central scheme: request forwarded to the authority and its answer


def schemes() -> list[dict]:
    """ec_mult / hash counts are for one authentication (and one handover) of one vehicle."""
    ours_auth_req = AUTH_REQ_HDR + S.PROOF + 32 * S.MERKLE_DEPTH
    ours_resp = AUTH_RESP_HDR + S.TICKET + S.SIG
    ours_ho = HO_REQ_HDR + S.TICKET + S.SIG
    ecdsa_req = AUTH_REQ_HDR + ECDSA_SIG + ECDSA_CERT
    ecdsa_resp = AUTH_RESP_HDR + S.TICKET + S.SIG
    return [
        {"scheme": "ours (Schnorr ZKP + Merkle + ledger)",
         # vehicle: verify beacon signature (2 mult), prove with a precomputed commitment (0 online); verify ticket (2)
         "vehicle_ec_mult": 4, "vehicle_hash": 2,
         # RSU: verify proof (2), sign ticket (1); Merkle path of MERKLE_DEPTH hashes; RecordAuth is off the critical path
         "rsu_ec_mult": 3, "rsu_hash": 1 + S.MERKLE_DEPTH,
         "ho_vehicle_ec_mult": 4, "ho_rsu_ec_mult": 3,          # handover: signature check + new ticket, no Merkle path
         "auth_bytes": ours_auth_req + ours_resp, "handover_bytes": ours_ho + ours_resp,
         "bsm_overhead_bytes": S.TICKET + S.SIG, "backbone_round_trips": 0,
         "ledger_reads": 1, "ledger_writes_off_path": 1},
        {"scheme": "ECDSA pseudonym certificates",
         "vehicle_ec_mult": 4, "vehicle_hash": 2,               # sign request, verify beacon + response (ECDSA = ~2 mult each)
         "rsu_ec_mult": 6, "rsu_hash": 3,                       # verify certificate (2), verify signature (2), sign response (2)
         "ho_vehicle_ec_mult": 4, "ho_rsu_ec_mult": 6,
         "auth_bytes": ecdsa_req + ecdsa_resp, "handover_bytes": ecdsa_req + ecdsa_resp,
         "bsm_overhead_bytes": ECDSA_SIG + CERT_DIGEST, "backbone_round_trips": 0,
         "ledger_reads": 0, "ledger_writes_off_path": 0},
        {"scheme": "central authority checks every vehicle",
         "vehicle_ec_mult": 4, "vehicle_hash": 2,
         "rsu_ec_mult": 6, "rsu_hash": 3,
         "ho_vehicle_ec_mult": 4, "ho_rsu_ec_mult": 6,
         "auth_bytes": ecdsa_req + ecdsa_resp + BACKBONE, "handover_bytes": ecdsa_req + ecdsa_resp + BACKBONE,
         "bsm_overhead_bytes": ECDSA_SIG + CERT_DIGEST, "backbone_round_trips": 1,
         "ledger_reads": 0, "ledger_writes_off_path": 0},
    ]


def with_times(rows: list[dict], times: dict | None) -> list[dict]:
    if not times or "ec_mult" not in times:
        return rows
    for r in rows:
        r["vehicle_ms"] = round(1000 * (r["vehicle_ec_mult"] * times["ec_mult"] + r["vehicle_hash"] * times.get("hash", 0)), 3)
        r["rsu_ms"] = round(1000 * (r["rsu_ec_mult"] * times["ec_mult"] + r["rsu_hash"] * times.get("hash", 0)), 3)
        r["handover_rsu_ms"] = round(1000 * r["ho_rsu_ec_mult"] * times["ec_mult"], 3)
    return rows


def papers() -> list[dict]:
    if not PAPERS.exists():
        PAPERS.write_text(",".join(PAPER_COLS) + "\n")
        return []
    with PAPERS.open(newline="") as f:
        return list(csv.DictReader(f))


def to_markdown(rows: list[dict]) -> str:
    cols = [c for c in rows[0] if c != "notes"] if rows else []
    cols = list(dict.fromkeys(c for r in rows for c in r))
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        lines.append("| " + " | ".join("" if r.get(c) is None else str(r.get(c, "")) for c in cols) + " |")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--times", default=None, help="JSON with ec_mult, hash (seconds), from measure_ecdsa.py")
    ap.add_argument("--out", default=str(HERE / "results"))
    a = ap.parse_args()
    times = json.loads(Path(a.times).read_text()) if a.times else None
    rows = with_times(schemes(), times) + papers()
    md = to_markdown(rows)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "op_counts.md").write_text(md + "\n")
    cols = list(dict.fromkeys(c for r in rows for c in r))
    with (out / "op_counts.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(md)
    if not papers():
        print(f"\nnote: add the papers from the review slides to {PAPERS.name}")
