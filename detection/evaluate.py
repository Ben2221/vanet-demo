"""Replay a message stream through a detector and score it (Person 4).

Per-message scores per attack (precision, recall, F1, false-positive rate), and
vehicle-level scores for the K-of-W reporting rule: how fast attackers are
reported and how many honest vehicles are reported by mistake.

Never judge on accuracy alone: the data is heavily imbalanced.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Callable

from detection import detector as det
from detection.reporting import ReportingRule

BSM_KEYS = ["pid", "seq", "t", "x", "y", "speed", "heading", "rsu_x", "rsu_y", "rx_time", "sender"]
HISTORY = 20            # same depth as the RSU keeps (network/protocols/stub_auth.py)


def run_detector(stream: list[dict], check: Callable = det.check, history: int = HISTORY) -> list[dict]:
    """Feed messages in reception order, one history per (receiver, pseudonym).

    Returns a copy of every message with ``flagged`` and ``features`` added.
    """
    det.reset()
    hist: dict[tuple, deque] = defaultdict(lambda: deque(maxlen=history))
    out = []
    for m in sorted(stream, key=lambda r: r["rx_time"]):
        bsm = {k: m.get(k) for k in BSM_KEYS}
        h = hist[(m.get("rsu_x"), m.get("rsu_y"), m["pid"])]
        flagged, feats = check(bsm, list(h))
        h.append(bsm)
        out.append({**m, "flagged": bool(flagged), "features": feats})
    return out


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def per_attack_metrics(results: list[dict]) -> dict:
    """{attack: {precision, recall, f1, fpr, n_attack, n_honest}} plus an "ALL" row.

    For attack A the positives are A's messages and the negatives all honest
    messages; other attacks' messages are left out of that row.
    """
    results = [r for r in results if not r.get("ambiguous")]
    honest = [r for r in results if r["label"] == 0]
    fp_all = sum(r["flagged"] for r in honest)
    out = {}
    names = sorted({r["attack"] for r in results if r["label"] == 1})
    for a in names + ["ALL"]:
        pos = [r for r in results if r["label"] == 1 and (a == "ALL" or r["attack"] == a)]
        tp = sum(r["flagged"] for r in pos)
        p, rec, f1 = _prf(tp, fp_all, len(pos) - tp)
        out[a] = {"precision": p, "recall": rec, "f1": f1,
                  "fpr": fp_all / len(honest) if honest else 0.0,
                  "n_attack": len(pos), "n_honest": len(honest)}
    return out


def vehicle_metrics(results: list[dict], k: int = 3, w: int = 10) -> dict:
    """Apply the K-of-W rule per pseudonym and score it per vehicle.

    detection_rate    attacker vehicles with at least one pseudonym reported
    false_report_rate honest vehicles reported (they would be revoked)
    delay_s           from the attacker's first attack message to the first report
    """
    rule = ReportingRule(k, w)
    attack_start: dict[str, float] = {}
    first_report: dict[str, float] = {}
    vehicles = {r["vehicle"] for r in results}
    for r in results:
        if r["label"] == 1:
            attack_start.setdefault(r["vehicle"], r["rx_time"])
        # a report is against a pseudonym, so it counts for the pseudonym's real owner
        if rule.update(r["pid"], r["flagged"], bool(r["features"].get("foreign"))):
            first_report.setdefault(r.get("pid_owner", r["vehicle"]), r["rx_time"])
    attackers = set(attack_start)
    honest = vehicles - attackers
    caught = [v for v in attackers if v in first_report and first_report[v] >= attack_start[v]]
    delays = sorted(first_report[v] - attack_start[v] for v in caught)
    wrong = [v for v in honest if v in first_report]
    return {"k": k, "w": w, "attackers": len(attackers), "detected": len(caught),
            "detection_rate": len(caught) / len(attackers) if attackers else None,
            "honest": len(honest), "honest_reported": len(wrong),
            "false_report_rate": len(wrong) / len(honest) if honest else None,
            "delay_s_median": delays[len(delays) // 2] if delays else None,
            "delay_s_max": delays[-1] if delays else None}


def tune_k_w(results: list[dict], ks=(1, 2, 3, 4, 5), ws=(5, 10, 15, 20)) -> list[dict]:
    """Table of vehicle metrics for every (K, W): pick the row with no false
    reports and the smallest delay."""
    return [vehicle_metrics(results, k, w) for w in ws for k in ks if k <= w]


def format_table(metrics: dict) -> str:
    lines = [f"{'attack':<14}{'precision':>10}{'recall':>8}{'F1':>8}{'FPR':>8}{'n':>8}"]
    for a, m in metrics.items():
        lines.append(f"{a:<14}{m['precision']:>10.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}"
                     f"{m['fpr']:>8.4f}{m['n_attack']:>8d}")
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse
    import json

    from detection.generator import generate

    ap = argparse.ArgumentParser(description="Evaluate the detector on generated data")
    ap.add_argument("--vehicles", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--w", type=int, default=10)
    ap.add_argument("--json", default=None, help="write the metrics to this file")
    a = ap.parse_args()
    res = run_detector(generate(n_vehicles=a.vehicles, seed=a.seed))
    pm, vm = per_attack_metrics(res), vehicle_metrics(res, a.k, a.w)
    print(format_table(pm))
    print(json.dumps(vm, indent=2))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"per_attack": pm, "vehicle": vm, "tuning": tune_k_w(res)}, f, indent=2)
