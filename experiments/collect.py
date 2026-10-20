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
STEADY_FROM = 10.0            # s; ticket_ms_steady_* leaves out the start-up burst


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
    # every way a vehicle gets a ticket: full authentication or --ticket-renewal
    tickets = lat("AUTH_OK") + lat("RENEW_OK")
    out["renew_n"] = len(by_event.get("RENEW_OK", []))
    out["ticket_ms_mean"] = sum(tickets) / len(tickets) if tickets else None
    out["ticket_ms_p95"] = _pct(tickets, 0.95)
    # the same after start-up: a real-map cut starts with hundreds of vehicles already on the
    # road, all asking for a ticket in the first seconds, which no real deployment sees
    steady = [v for ev in ("AUTH_OK", "RENEW_OK") for r in by_event.get(ev, [])
              if float(r["sim_time"]) >= STEADY_FROM and (v := _num(r["latency_ms"])) is not None]
    out["ticket_ms_steady_mean"] = sum(steady) / len(steady) if steady else None
    out["ticket_ms_steady_p95"] = _pct(steady, 0.95)
    out["handover_fallbacks"] = len(by_event.get("HANDOVER_FALLBACK", []))
    out["handovers_per_auth"] = out["handover_n"] / out["auth_n"] if out["auth_n"] else None
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
    out.update(_traffic(summary, by_event))
    out.update(_protocol_stats(d))
    out.update(_tracking(d))
    out.update(_emergency(d, by_event))
    if out.get("mix_silent_s") is not None and out.get("vehicle_seconds"):
        out["silent_share"] = out["mix_silent_s"] / out["vehicle_seconds"]      # mix-zone safety cost
    return out


# ------------------------------------------------------------ v3 numbers
LEGIT_REJECTS = {"revoked", "quarantined", "expired_or_revoked", "revoked_filter", "expired", "fake_emergency"}


def _vehicle_seconds(by_event: dict[str, list[dict]], duration: float) -> float:
    """Sum over vehicles of the time they were on the road (ENTER to LEAVE or the end)."""
    enter = {r["node"]: float(r["sim_time"]) for r in by_event.get("ENTER", [])}
    leave = {r["node"]: float(r["sim_time"]) for r in by_event.get("LEAVE", [])}
    return sum(max(0.0, leave.get(v, duration) - t) for v, t in enter.items())


def _traffic(summary: dict, by_event: dict[str, list[dict]]) -> dict:
    """Channel use per vehicle and second, and how much handover / backbone signalling there was."""
    vs = _vehicle_seconds(by_event, float(summary.get("duration_s") or 0.0))
    sent, nbytes = summary.get("sent_by_type", {}), summary.get("bytes_by_type", {})
    out = {"vehicle_seconds": vs,
           "preauth_msgs": len(by_event.get("TX_PREAUTH", [])),
           "cluster_switches": len(by_event.get("CLUSTER_SWITCH", [])),
           "pseudonym_changes": len(by_event.get("PSEUDONYM_CHANGE", []))}
    if vs > 0:
        safety = ("BSM", "TESLA_KEY")
        out["bsm_per_vehicle_s"] = sent.get("BSM", 0) / vs
        out["safety_bytes_per_vehicle_s"] = sum(nbytes.get(t, 0) for t in safety) / vs
        out["air_bytes_per_vehicle_s"] = sum(nbytes.values()) / vs
        out["auth_bytes_per_vehicle_s"] = sum(nbytes.get(t, 0) for t in
                                              ("AUTH_REQ", "AUTH_RESP", "HANDOVER_REQ")) / vs
    return out


def _protocol_stats(d: Path) -> dict:
    """Numbers from protocol_stats.json (written by the real protocol's teardown)."""
    f = d / "protocol_stats.json"
    if not f.exists():
        return {}
    try:
        st = json.loads(f.read_text())
    except json.JSONDecodeError:
        return {}                      # an interrupted run
    out: dict = {}

    def ratio(block: dict) -> float | None:
        bad = sum(n for r, n in block.get("rejected", {}).items() if r not in LEGIT_REJECTS)
        ok = block.get("accepted", 0)
        return ok / (ok + bad + block.get("dropped", 0)) if ok + bad + block.get("dropped", 0) else None

    rsu, v2v = st.get("rsu_bsm", {}), st.get("v2v", {})
    out["rsu_verified_ratio"] = ratio(rsu)
    out["rsu_accept_ms_mean"] = rsu.get("accept_latency_ms", {}).get("mean")
    out["rsu_accept_ms_p95"] = rsu.get("accept_latency_ms", {}).get("p95")
    out["rsu_dropped"] = rsu.get("dropped")
    if v2v.get("received"):
        out["v2v_verified_ratio"] = ratio(v2v)
        out["v2v_accept_ms_mean"] = v2v.get("accept_latency_ms", {}).get("mean")
        out["v2v_accept_ms_p95"] = v2v.get("accept_latency_ms", {}).get("p95")
        fr = v2v.get("from_revoked", 0)
        out["v2v_revoked_accepted_ratio"] = v2v.get("revoked_accepted", 0) / fr if fr else None
        out["v2v_revoked_accepted"] = v2v.get("revoked_accepted")
        out["filter_drops_attacker"] = v2v.get("filter_drops_attacker")
        out["filter_drops_honest"] = v2v.get("filter_drops_honest")
        out["v2v_dropped"] = v2v.get("dropped")
    for kind in ("rsu_cpu", "obu_cpu"):
        c = st.get(kind) or {}
        if c:
            out[f"{kind}_util_mean"] = c.get("util_mean")
            out[f"{kind}_util_max"] = c.get("util_max")
            out[f"{kind}_batch_mean"] = c.get("batch_mean")
    aw = st.get("awareness_error_m", {})
    out["awareness_error_m_mean"] = aw.get("mean")
    out["awareness_error_m_p95"] = aw.get("p95")
    out["tesla_key_msgs"] = st.get("tesla_key_msgs")
    out["renewals"] = st.get("renewals")
    out["signed_share"] = (st.get("signed_bsms", 0) / (st.get("signed_bsms", 0) + st.get("tesla_bsms", 0))
                           if st.get("signed_bsms", 0) + st.get("tesla_bsms", 0) else None)
    out["mix_silent_s"] = st.get("mix_silent_s")
    out["mix_changes"] = st.get("mix_changes")
    out["faulty_reports"] = st.get("faulty_reports")
    fb = st.get("filter_bytes", {})
    out["filter_bytes_mean"] = fb.get("mean")
    return out


def _emergency(d: Path, by_event: dict[str, list[dict]]) -> dict:
    """--emergency-ratio / --attack fake_emergency: tickets of emergency vehicles against the rest,
    alert delivery, and what fake alerts and fake emergency logins achieved."""
    f = d / "protocol_stats.json"
    try:
        ev = json.loads(f.read_text()).get("emergency") if f.exists() else None
    except json.JSONDecodeError:
        ev = None
    if not ev:
        return {}
    evs = {r["node"] for r in by_event.get("EMERGENCY_ROLE", [])}
    split: dict[bool, list[float]] = {True: [], False: []}
    for name in ("AUTH_OK", "RENEW_OK"):
        for r in by_event.get(name, []):
            v = _num(r["latency_ms"])
            if v is not None:
                split[r["node"] in evs].append(v)
    lat = ev.get("alert_latency_ms") or {}
    denied = [r for r in by_event.get("AUTH_REJECTED", []) if r["result"].endswith(":policy_denied")]
    return {
        "ev_vehicles": len(evs),
        "ev_ticket_ms_mean": sum(split[True]) / len(split[True]) if split[True] else None,
        "ev_ticket_ms_p95": _pct(split[True], 0.95),
        "other_ticket_ms_mean": sum(split[False]) / len(split[False]) if split[False] else None,
        "other_ticket_ms_p95": _pct(split[False], 0.95),
        "ev_warned_ratio": ev.get("warned_ratio"),
        "ev_alert_ms_mean": lat.get("mean"), "ev_alert_ms_p95": lat.get("p95"),
        "fake_alerts_sent": ev.get("fake_alerts_sent"),
        "fake_alerts_accepted": ev.get("fake_alerts_accepted"),
        "fake_alerts_rejected": (ev.get("fake_rejected_v2v") or 0) + (ev.get("fake_rejected_rsu") or 0),
        "fake_logins": len(by_event.get("FAKE_EMERGENCY_LOGIN", [])),
        "fake_logins_denied": len(denied),
        "ev_priority_logins": ev.get("priority_logins"),
        "ev_priority_capped": ev.get("priority_capped"),
        "ev_priority_false_claims": ev.get("priority_false_claims"),
    }


def _tracking(d: Path) -> dict:
    """Tracking attack on observed_bsms.csv (--privacy-log); cached in tracking.json."""
    obs, cache = d / "observed_bsms.csv", d / "tracking.json"
    if not obs.exists():
        return {}
    if cache.exists() and cache.stat().st_mtime >= obs.stat().st_mtime:
        try:
            return json.loads(cache.read_text())
        except json.JSONDecodeError:
            pass                       # half-written by an interrupted run: recompute
    from experiments.tracker import analyse
    try:
        res = analyse(obs)
    except (ValueError, KeyError):
        return {}                      # truncated log of an interrupted run
    cache.write_text(json.dumps(res))
    return res


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
    # vehicles that lost a pseudonym to revocation: honest ones are the cost of wrong reports
    revoked_pids = {r["result"].strip() for r in by_event.get("REVOKED_VISIBLE", [])}
    revoked_veh = {owner[p] for p in revoked_pids if p in owner}
    out["attackers_revoked"] = len(revoked_veh & set(attackers))
    out["honest_revoked"] = len(revoked_veh - set(attackers)) if owner else None
    out["detection_rate"] = len(caught) / len(attackers) if attackers and owner else None
    out["honest_reported"] = len(wrong) if owner else None
    delays = [revoked_at[p] - reports[p] for p in revoked_at]
    out["report_to_revocation_s_mean"] = sum(delays) / len(delays) if delays else None
    blocked_at = dict(revoked_at)           # pid -> first local block (QUARANTINE_BLOCK) or revocation
    for r in by_event.get("QUARANTINE_BLOCK", []):
        pid, t = r["result"].strip(), float(r["sim_time"])
        if pid in reports and t < blocked_at.get(pid, float("inf")):
            blocked_at[pid] = t
    blocks = [blocked_at[p] - reports[p] for p in blocked_at]
    out["report_to_block_s_mean"] = sum(blocks) / len(blocks) if blocks else None
    start = {v: float(a["start"]) for v, a in attackers.items()}
    first = [reports[p] - start[v] for p, v in resolved.items() if v in start and reports[p] >= start[v]]
    out["first_report_delay_s_mean"] = sum(first) / len(first) if first else None
    out["rsu_reports"] = len(by_event.get("REPORT", []))
    out["detect_flags"] = len(by_event.get("DETECT_FLAG", []))
    return out
