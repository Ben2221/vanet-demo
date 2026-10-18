"""In-memory ledger stand-in implementing the Blockchain Ledger interface specification."""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any

@dataclass
class MockLedger:
    root_by_epoch: dict[int, str] = field(default_factory=dict)
    root_expiry: dict[int, float] = field(default_factory=dict)
    policies: dict[str, set[str]] = field(default_factory=dict)
    auth_records: dict[str, dict] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)
    revocation_events: list[dict[str, Any]] = field(default_factory=list)
    classes_by_pid: dict[str, str] = field(default_factory=dict)
    misbehaviour_reports: dict[str, dict[str, Any]] = field(default_factory=dict)
    trace_requests: dict[str, dict[str, Any]] = field(default_factory=dict)
    commit_delay_ms: float = 1.0
    trace_threshold: int = 3
    auto_revoke_k: int = 2

    def register_root(self, epoch: int, root_hex: str, valid_until: float, caller_id: str = "TA") -> dict:
        self.root_by_epoch[epoch] = root_hex
        self.root_expiry[epoch] = float(valid_until)
        return {"txId": f"root-{epoch}-{int(time.time()*1000)}", "commitMs": self.commit_delay_ms}

    def get_root(self, epoch: int) -> str | None:
        return self.root_by_epoch.get(epoch)

    def root_valid(self, epoch: int, now: float) -> bool:
        return epoch in self.root_by_epoch and self.root_expiry.get(epoch, 0) >= now

    def register_pseudonym(self, pid: str, vehicle_class: str) -> None:
        self.classes_by_pid[pid] = vehicle_class

    def vehicle_class(self, pid: str) -> str | None:
        return self.classes_by_pid.get(pid)

    def set_policy(self, service: str, classes: set[str] | list[str], caller_id: str = "TA") -> dict:
        self.policies[service] = set(classes)
        return {"txId": f"policy-{service}", "commitMs": self.commit_delay_ms}

    def allowed(self, service: str, vehicle_class: str) -> bool:
        return vehicle_class in self.policies.get(service, set())

    def record_auth(self, pid: str, service: str, vehicle_class: str, expiry: float) -> dict:
        self.auth_records[pid] = {"service": service, "class": vehicle_class, "expiry": expiry}
        return {"txId": f"auth-{pid[:10]}-{int(time.time()*1000)}", "commitMs": self.commit_delay_ms}

    def get_auth(self, pid: str) -> dict | None:
        return self.auth_records.get(pid)

    def report_misbehaviour(self, pid: str, evidence_hash: str, reporter_rsu: str) -> dict:
        """Adds a report; revokes the pseudonym automatically once K different RSUs have reported it (default K=2)."""
        now = time.time()
        if pid not in self.misbehaviour_reports:
            self.misbehaviour_reports[pid] = {"reporters": set(), "evidence": []}
        report = self.misbehaviour_reports[pid]
        report["reporters"].add(reporter_rsu)
        report["evidence"].append({"rsu": reporter_rsu, "evidence_hash": evidence_hash, "time": now})

        revoked_now = False
        if len(report["reporters"]) >= self.auto_revoke_k and pid not in self.revoked:
            self.revoked.add(pid)
            self.revocation_events.append({"pid": pid, "time": now, "reason": f"auto_revoked_by_{len(report['reporters'])}_rsus"})
            revoked_now = True

        return {
            "txId": f"report-{pid[:8]}-{int(now*1000)}",
            "commitMs": self.commit_delay_ms,
            "reporters_count": len(report["reporters"]),
            "revoked": pid in self.revoked,
            "newly_revoked": revoked_now
        }

    def revoke(self, pids: list[str] | str, reason: str = "misbehaviour", caller_id: str = "TA") -> dict:
        """Revoke a single pseudonym or a list of pseudonyms (e.g. after trace approval)."""
        now = time.time()
        if isinstance(pids, str):
            pids = [pids]
        for pid in pids:
            self.revoked.add(pid)
            self.revocation_events.append({"pid": pid, "time": now, "reason": reason, "caller": caller_id})
        return {"txId": f"revoke-{int(now*1000)}", "commitMs": self.commit_delay_ms, "revoked_count": len(pids)}

    def is_revoked(self, pid: str) -> bool:
        return pid in self.revoked

    def get_revoked_since(self, since_time: float) -> list[dict[str, Any]]:
        """Used for RSU cache synchronization."""
        return [evt for evt in self.revocation_events if evt.get("time", 0) >= since_time]

    def request_trace(self, req_id: str, pid: str, reason: str, caller_id: str = "RSU-1") -> dict:
        """Opens a request on the ledger to reveal who owns a pseudonym."""
        now = time.time()
        self.trace_requests[req_id] = {
            "req_id": req_id,
            "pid": pid,
            "reason": reason,
            "caller": caller_id,
            "created_at": now,
            "approvals": set(),
            "approved": False
        }
        return {"txId": f"trace-req-{req_id}", "commitMs": self.commit_delay_ms}

    def approve_trace(self, req_id: str, rsu_id: str) -> dict:
        """Adds one RSU approval; trace counts as approved at the threshold."""
        if req_id not in self.trace_requests:
            raise KeyError(f"trace request {req_id} not found")
        trace = self.trace_requests[req_id]
        trace["approvals"].add(rsu_id)
        if len(trace["approvals"]) >= self.trace_threshold:
            trace["approved"] = True
        return {
            "txId": f"trace-app-{req_id}-{rsu_id}",
            "commitMs": self.commit_delay_ms,
            "approvals": len(trace["approvals"]),
            "approved": trace["approved"]
        }

    def get_trace(self, req_id: str) -> dict | None:
        """Returns request status and approvals."""
        return self.trace_requests.get(req_id)

    def is_trace_approved(self, req_id: str) -> bool:
        trace = self.trace_requests.get(req_id)
        return bool(trace and trace.get("approved", False))
