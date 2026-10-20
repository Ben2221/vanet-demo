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
    # rejections are counted once, at the RSU (the vehicle's AUTH_REJECTED row is the same event);
    # rejecting a revoked pseudonym is the protocol working, any other reason is a failure
    rejects = [r["result"].rsplit(":", 1)[-1] for r in by_event.get("AUTH_REJECT", [])]
    out["auth_rejected"] = len(rejects)
    out["auth_rejected_revoked"] = sum(1 for x in rejects if x == "revoked")
    out["auth_rejected_other"] = len(rejects) - out["auth_rejected_revoked"]
    out.update(_ratios(by_event, _attacker_names(d)))
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


def _attacker_names(d: Path) -> set[str]:
    if not (d / "attackers.csv").exists():
        return set()
    with (d / "attackers.csv").open(newline="") as f:
        return {r["name"] for r in csv.DictReader(f)}


def _ratios(by_event: dict[str, list[dict]], attackers: set[str]) -> dict:
    """Success ratios of honest vehicles (an attacker's rejected requests are revocation working),
    and how handovers were authorised (ledger record or backbone PREAUTH)."""
    out: dict = {}
    reqs = sum(1 for r in by_event.get("TX_AUTH_REQ", []) if r["node"] not in attackers)
    ok = sum(1 for r in by_event.get("AUTH_OK", []) if r["node"] not in attackers)
    out["auth_success_ratio"] = ok / reqs if reqs else None
    checks = [r["result"] for r in by_event.get("HANDOVER_CHECK", [])]
    # real protocol: "<pid>:handover_accepted:<via>"; stand-in and baselines: "<pid>:ok"
    accepted = [c for c in checks if "handover_accepted" in c or c.endswith(":ok")]
    out["handover_success_ratio"] = len(accepted) / len(checks) if checks else None
    out["handover_via_preauth"] = (sum(1 for c in accepted if c.endswith(":preauth")) / len(accepted)
                                   if accepted else None)
    vehicles = {r["node"] for r in by_event.get("ENTER", [])}
    changes = len(by_event.get("PSEUDONYM_CHANGE", []))
    out["pseudonym_changes_per_vehicle"] = changes / len(vehicles) if vehicles else None
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
    # The clock for "time to first report" starts when the attacker can first send an authenticated
    # lying BSM: the attack start, or its first ticket if it entered the road / got coverage later.
    # (Counting from the attack start alone charges the detector for time the car was not on the road.)
    start = {v: float(a["start"]) for v, a in attackers.items()}
    first_ok: dict[str, list[float]] = defaultdict(list)
    for r in by_event.get("AUTH_OK", []):
        first_ok[r["node"]].append(float(r["sim_time"]))
    ref = {}
    for v, t0 in start.items():
        later = [t for t in first_ok.get(v, []) if t >= t0]
        before = [t for t in first_ok.get(v, []) if t < t0]
        ref[v] = t0 if before or not later else min(later)
    first_by_vehicle: dict[str, float] = {}
    for p, v in resolved.items():
        if v in ref and reports[p] >= ref[v]:
            first_by_vehicle[v] = min(first_by_vehicle.get(v, float("inf")), reports[p] - ref[v])
    first = list(first_by_vehicle.values())
    out["first_report_delay_s_mean"] = sum(first) / len(first) if first else None
    out["first_report_delay_s_median"] = _pct(first, 0.5)
    out["rsu_reports"] = len(by_event.get("REPORT", []))
    out["detect_flags"] = len(by_event.get("DETECT_FLAG", []))

    # revocation and exclusion per attacker (a pseudonym revoked; the identity revealed and every
    # pseudonym of the vehicle revoked)
    revoked_any = {owner[p] for r in by_event.get("REVOKED_VISIBLE", []) for p in [r["result"].strip()]
                   if p in owner}
    revealed = {}
    for r in by_event.get("IDENTITY_REVEALED", []):
        m = re.match(r"\s*([0-9a-f]+)\s*->\s*(\S+)", r["result"])
        if m:
            revealed.setdefault(m.group(2), float(r["sim_time"]))
    out["attackers_revoked"] = len(revoked_any & set(attackers)) if owner else None
    out["revocation_rate"] = (len(revoked_any & set(attackers)) / len(attackers)
                              if attackers and owner else None)
    out["attackers_identity_revealed"] = len(set(revealed) & set(attackers))
    out["honest_revoked"] = len(revoked_any - set(attackers)) if owner else None
    excl = [revealed[v] - ref[v] for v in revealed if v in ref and revealed[v] >= ref[v]]
    out["attack_to_exclusion_s_mean"] = sum(excl) / len(excl) if excl else None

    # false flags: honest vehicles whose BSM was flagged at least once (a flag alone revokes nothing;
    # K flags out of W at two RSUs do). DETECT_FLAG result is "<pid>" or "<pid>:<check>+<check>".
    flagged = {owner[pid] for r in by_event.get("DETECT_FLAG", [])
               for pid in [r["result"].split(":", 1)[0].strip()] if pid in owner}
    out["honest_flagged"] = len(flagged - set(attackers)) if owner else None
    return out


def flag_checks(run_dir: str | Path) -> dict[str, dict[str, int]]:
    """Which detector checks fired, split by attacker / honest vehicle: {"attacker": {check: n}, ...}."""
    d = Path(run_dir)
    by_event: dict[str, list[dict]] = defaultdict(list)
    for r in _read_metrics(d / "metrics.csv"):
        by_event[r["event"]].append(r)
    owner = _owner_map(by_event)
    attackers = _attacker_names(d)
    out: dict[str, dict[str, int]] = {"attacker": defaultdict(int), "honest": defaultdict(int)}
    for r in by_event.get("DETECT_FLAG", []):
        pid, _, checks = r["result"].partition(":")
        who = "attacker" if owner.get(pid.strip()) in attackers else "honest"
        for c in filter(None, checks.split("+")):
            out[who][c] += 1
    return {k: dict(v) for k, v in out.items()}
