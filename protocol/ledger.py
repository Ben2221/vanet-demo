"""In-memory ledger stand-in implementing the Blockchain Ledger interface specification.

Method names and arguments follow docs/interfaces.md (sections 3 and 4), so the
RSU code runs unchanged against this mock, against an RSU's ``node.ledger`` in
the simulator, and against Person 2's Fabric ledger. The caller identity is
bound with ``view(identity)``, as the gateway does with the X-Identity header.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Any

@dataclass
class MockLedger:
    roots: dict[int, dict] = field(default_factory=dict)
    policies: dict[str, list[str]] = field(default_factory=dict)
    auth_records: dict[str, dict] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)
    revocation_events: list[dict[str, Any]] = field(default_factory=list)
    misbehaviour_reports: dict[str, dict[str, Any]] = field(default_factory=dict)
    trace_requests: dict[str, dict[str, Any]] = field(default_factory=dict)
    commit_delay_ms: float = 1.0
    trace_threshold: int = 3
    auto_revoke_k: int = 2

    def view(self, identity: str) -> "MockLedgerView":
        """The ledger as seen by one caller (RSU or TA)."""
        return MockLedgerView(self, identity)

    def _commit(self, tx: str, **extra) -> dict:
        return {"txId": f"{tx}-{int(time.time() * 1000)}", "commitMs": self.commit_delay_ms, **extra}

    # ------------------------------------------------------------- TA writes
    def register_root(self, epoch: int, merkle_root: str, valid_until: float, caller_id: str = "TA") -> dict:
        self.roots[int(epoch)] = {"epoch": int(epoch), "merkleRoot": merkle_root, "validUntil": float(valid_until)}
        return self._commit(f"root-{epoch}")

    def set_policy(self, service: str, classes, caller_id: str = "TA") -> dict:
        self.policies[service] = sorted(classes)
        return self._commit(f"policy-{service}")

    def revoke(self, pids: list[str] | str, reason: str = "misbehaviour", caller_id: str = "TA") -> dict:
        """Revoke a single pseudonym or a list of pseudonyms (e.g. after trace approval)."""
        now = time.time()
        if isinstance(pids, str):
            pids = [pids]
        for pid in pids:
            self._revoke(pid, now, reason, caller_id)
        return self._commit("revoke", revoked_count=len(pids))

    def _revoke(self, pid: str, now: float, reason: str, caller: str) -> None:
        if pid not in self.revoked:
            self.revoked.add(pid)
            self.revocation_events.append({"pid": pid, "time": now, "reason": reason, "caller": caller})

    # ------------------------------------------------------------ RSU writes
    def record_auth(self, pid_hash: str, service: str, cls: str, expiry: float, caller_id: str = "RSU") -> dict:
        self.auth_records[pid_hash] = {"pidHash": pid_hash, "service": service, "class": cls,
                                       "expiry": float(expiry), "rsu": caller_id}
        return self._commit(f"auth-{pid_hash[:10]}")

    def report_misbehaviour(self, pid: str, evidence_hash: str, caller_id: str = "RSU") -> dict:
        """Adds a report; revokes the pseudonym automatically once K different RSUs have reported it (default K=2)."""
        now = time.time()
        report = self.misbehaviour_reports.setdefault(pid, {"reporters": set(), "evidence": []})
        report["reporters"].add(caller_id)
        report["evidence"].append({"rsu": caller_id, "evidence_hash": evidence_hash, "time": now})
        newly = len(report["reporters"]) >= self.auto_revoke_k and pid not in self.revoked
        if newly:
            self._revoke(pid, now, f"auto_revoked_by_{len(report['reporters'])}_rsus", "ledger")
        return self._commit(f"report-{pid[:8]}", reports=len(report["reporters"]),
                            revoked=pid in self.revoked, newly_revoked=newly)

    def request_trace(self, req_id: str, pid: str, reason: str, caller_id: str = "RSU") -> dict:
        """Opens a request on the ledger to reveal who owns a pseudonym."""
        if req_id in self.trace_requests:
            raise ValueError(f"trace request {req_id} exists")
        self.trace_requests[req_id] = {"reqId": req_id, "pid": pid, "reason": reason,
                                       "requester": caller_id, "approvals": [], "approved": False}
        return self._commit(f"trace-req-{req_id}")

    def approve_trace(self, req_id: str, caller_id: str = "RSU") -> dict:
        """Adds one RSU approval; trace counts as approved at the threshold."""
        if req_id not in self.trace_requests:
            raise KeyError(f"trace request {req_id} not found")
        trace = self.trace_requests[req_id]
        if caller_id not in trace["approvals"]:
            trace["approvals"].append(caller_id)
        trace["approved"] = len(trace["approvals"]) >= self.trace_threshold
        return self._commit(f"trace-app-{req_id}-{caller_id}", approvals=len(trace["approvals"]),
                            approved=trace["approved"])

    # ----------------------------------------------------------------- reads
    def get_root(self, epoch: int) -> dict | None:
        return self.roots.get(int(epoch))

    def current_root(self) -> dict | None:
        return self.roots[max(self.roots)] if self.roots else None

    def get_policy(self, service: str) -> list[str] | None:
        return self.policies.get(service)

    def get_auth(self, pid_hash: str) -> dict | None:
        return self.auth_records.get(pid_hash)

    def is_revoked(self, pid: str) -> bool:
        return pid in self.revoked

    def get_revoked_since(self, since_time: float) -> list[dict[str, Any]]:
        """Used for RSU cache synchronization."""
        return [evt for evt in self.revocation_events if evt.get("time", 0) >= since_time]

    def get_trace(self, req_id: str) -> dict | None:
        """Returns request status and approvals."""
        return self.trace_requests.get(req_id)

    def is_trace_approved(self, req_id: str) -> bool:
        trace = self.trace_requests.get(req_id)
        return bool(trace and trace.get("approved", False))


class MockLedgerView:
    """MockLedger with the caller identity filled in, like node.ledger for an RSU."""

    def __init__(self, ledger: MockLedger, identity: str) -> None:
        self.ledger = ledger
        self.identity = identity

    def record_auth(self, pid_hash, service, cls, expiry):
        return self.ledger.record_auth(pid_hash, service, cls, expiry, caller_id=self.identity)

    def report_misbehaviour(self, pid, evidence_hash):
        return self.ledger.report_misbehaviour(pid, evidence_hash, caller_id=self.identity)

    def request_trace(self, req_id, pid, reason):
        return self.ledger.request_trace(req_id, pid, reason, caller_id=self.identity)

    def approve_trace(self, req_id):
        return self.ledger.approve_trace(req_id, caller_id=self.identity)

    def __getattr__(self, name):
        return getattr(self.ledger, name)
