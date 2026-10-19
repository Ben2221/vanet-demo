"""Turn one run folder (metrics.csv, summary.json, attackers.csv, config.json) into
one row of numbers (Person 4).

Event names and columns are those of docs/interfaces.md section 6. Everything
that depends on protocol code logging something (pseudonym owners) is handled
defensively: if the event is missing, the detection numbers say how many
pseudonyms could not be resolved instead of guessing.

To resolve pseudonyms to vehicles, protocol code should log once per pseudonym

    node.log("PID_ASSIGN", 0, None, "<pid hex>")        # node = the vehicle

(also PSEUDONYM_CHANGE "... -> <pid>" and IDENTITY_REVEALED "<pid> -> <vehicle>"
are used when present).
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path

PLAIN_BSM_BYTES = 45          # network/bsm.py _PLAIN struct: what a BSM costs without security


def _pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _read_metrics(path: Path) -> list[dict]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def _num(x: str) -> float | None:
    try:
        return float(x) if x != "" else None
    except ValueError:
        return None


def collect_run(run_dir: str | Path) -> dict:
    d = Path(run_dir)
    rows = _read_metrics(d / "metrics.csv")
    summary = json.loads((d / "summary.json").read_text()) if (d / "summary.json").exists() else {}
    by_event: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_event[r["event"]].append(r)

    def lat(event: str) -> list[float]:
        return [v for v in (_num(r["latency_ms"]) for r in by_event.get(event, [])) if v is not None]

    out: dict = {}
    for name, ev in (("auth", "AUTH_OK"), ("handover", "HANDOVER_OK"),
                     ("ledger_commit", "LEDGER_SUBMIT"), ("ledger_visible", "LEDGER_VISIBLE")):
        v = lat(ev)
        out[f"{name}_n"] = len(v)
        out[f"{name}_ms_mean"] = sum(v) / len(v) if v else None
        out[f"{name}_ms_median"] = _pct(v, 0.5)
        out[f"{name}_ms_p95"] = _pct(v, 0.95)
    out["handover_fallbacks"] = len(by_event.get("HANDOVER_FALLBACK", []))
    out["auth_rejected"] = len(by_event.get("AUTH_REJECT", [])) + len(by_event.get("AUTH_REJECTED", []))
    out["pdr"] = summary.get("broadcast_pdr")
    out["unicast_pdr"] = summary.get("unicast_pdr")
    out["cbr_rsu_mean"] = summary.get("cbr_rsu_mean")
    bsm = summary.get("delay_ms", {}).get("BSM", {})
    out["bsm_delay_ms_mean"] = bsm.get("mean")
    out["bsm_delay_ms_p95"] = bsm.get("p95")
    sent, nbytes = summary.get("sent_by_type", {}), summary.get("bytes_by_type", {})
    if sent.get("BSM"):
        mean_bsm = nbytes.get("BSM", 0) / sent["BSM"]
        out["bsm_bytes"] = mean_bsm
        out["security_bytes_per_bsm"] = mean_bsm - PLAIN_BSM_BYTES
    out["wall_time_s"] = summary.get("wall_time_s")
    out.update(_detection(d, by_event))
    return out


# ------------------------------------------------------------------- detection
def _owner_map(by_event: dict[str, list[dict]]) -> dict[str, str]:
    owner: dict[str, str] = {}
    for r in by_event.get("PID_ASSIGN", []):
        owner[r["result"].strip()] = r["node"]
    for r in by_event.get("PSEUDONYM_CHANGE", []):
        m = re.search(r"->\s*([0-9a-f]+)\s*$", r["result"])
        if m:
            owner[m.group(1)] = r["node"]
    for r in by_event.get("IDENTITY_REVEALED", []):
        m = re.match(r"\s*([0-9a-f]+)\s*->\s*(\S+)", r["result"])
        if m:
            owner[m.group(1)] = m.group(2)
    return owner


def _detection(d: Path, by_event: dict[str, list[dict]]) -> dict:
    att_file = d / "attackers.csv"
    attackers: dict[str, dict] = {}
    if att_file.exists():
        with att_file.open(newline="") as f:
            attackers = {r["name"]: r for r in csv.DictReader(f)}
    out: dict = {"attackers": len(attackers)}
    owner = _owner_map(by_event)
    reports: dict[str, float] = {}          # pid -> time of first report
    for r in by_event.get("REPORT", []):
        reports.setdefault(r["result"].strip(), float(r["sim_time"]))
    revoked_at: dict[str, float] = {}       # pid -> time every RSU sees the revocation
    for r in by_event.get("REVOKED_VISIBLE", []):
        for pid in reports:
            if pid in r["result"] or pid in r["node"]:
                revoked_at.setdefault(pid, float(r["sim_time"]))
    unresolved = [p for p in reports if p not in owner]
    out["pids_reported"] = len(reports)
    out["pids_unresolved"] = len(unresolved)
    resolved = {p: owner[p] for p in reports if p in owner}
    caught = {v for v in resolved.values() if v in attackers}
    wrong = {v for v in resolved.values() if v not in attackers}
    out["attackers_reported"] = len(caught)
    out["detection_rate"] = len(caught) / len(attackers) if attackers and owner else None
    out["honest_reported"] = len(wrong) if owner else None
    delays = [revoked_at[p] - reports[p] for p in revoked_at]
    out["report_to_revocation_s_mean"] = sum(delays) / len(delays) if delays else None
    start = {v: float(a["start"]) for v, a in attackers.items()}
    first = [reports[p] - start[v] for p, v in resolved.items() if v in start and reports[p] >= start[v]]
    out["first_report_delay_s_mean"] = sum(first) / len(first) if first else None
    out["rsu_reports"] = len(by_event.get("REPORT", []))
    out["detect_flags"] = len(by_event.get("DETECT_FLAG", []))
    return out
