"""Clients for the ledger API (interface 4), as seen from the scenario.

All clients expose one method:

    call(caller, fn, **args) -> dict

``caller`` is the identity making the call ("TA" or an RSU id such as "rsu3").
``fn`` is a vanetauth chaincode function in snake_case. Writes return at least
``{"txId": ..., "commitMs": ...}``; reads return the data.

  InMemoryLedger    built-in fallback with the chaincode's rules and a
                    configurable commit time, used until ledger/mock_ledger.py
                    (Person 2) exists
  MockLedgerAdapter wraps Person 2's ledger/mock_ledger.py
  RestLedgerClient  talks to Person 2's gateway in front of real Fabric

Pick one with make_client("mock" | "builtin" | "http://host:port").
"""

from __future__ import annotations

import itertools
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request

WRITES = {"register_root", "set_policy", "record_auth", "report_misbehaviour",
          "request_trace", "approve_trace", "revoke"}
READS = {"get_auth", "is_revoked", "get_revoked_since", "get_trace", "get_policy", "get_root"}

TA_ONLY = {"register_root", "set_policy", "revoke"}
RSU_ONLY = {"record_auth", "report_misbehaviour", "approve_trace"}
RSU_OR_TA = {"request_trace"}


class LedgerError(Exception):
    pass


class AccessDenied(LedgerError):
    pass


def is_rsu(caller: str) -> bool:
    return caller.lower().startswith("rsu")


def check_caller(caller: str, fn: str) -> None:
    if fn in TA_ONLY and caller != "TA":
        raise AccessDenied(f"{fn} may only be called by the TA, not {caller}")
    if fn in RSU_ONLY and not is_rsu(caller):
        raise AccessDenied(f"{fn} may only be called by an RSU, not {caller}")
    if fn in RSU_OR_TA and not (caller == "TA" or is_rsu(caller)):
        raise AccessDenied(f"{fn} may only be called by an RSU or the TA, not {caller}")


class InMemoryLedger:
    """The vanetauth chaincode in memory. Real identities are never stored."""

    def __init__(self, report_k: int = 2, trace_threshold: int = 3,
                 commit_ms: float = 500.0, commit_jitter: float = 0.2, seed: int = 1) -> None:
        self.report_k = report_k
        self.trace_threshold = trace_threshold
        self.commit_ms = commit_ms
        self.commit_jitter = commit_jitter
        self.rng = random.Random(seed)
        self.roots: dict[int, dict] = {}
        self.policies: dict[str, list] = {}
        self.auth: dict[str, dict] = {}
        self.reports: dict[str, dict[str, str]] = {}       # pid -> {rsu: evidence}
        self.revoked: dict[str, dict] = {}                  # pid -> {seq, reason}
        self.traces: dict[str, dict] = {}
        self._seq = itertools.count(1)
        self._tx = itertools.count(1)

    def _commit(self, **extra) -> dict:
        jitter = 1 + self.rng.uniform(-self.commit_jitter, self.commit_jitter)
        return {"txId": f"tx{next(self._tx):06d}", "commitMs": self.commit_ms * jitter, **extra}

    def _revoke(self, pid: str, reason: str) -> None:
        if pid not in self.revoked:
            self.revoked[pid] = {"pid": pid, "seq": next(self._seq), "reason": reason}

    def call(self, caller: str, fn: str, **a) -> dict:
        check_caller(caller, fn)
        if fn == "register_root":
            self.roots[int(a["epoch"])] = {"epoch": int(a["epoch"]), "merkleRoot": a["merkle_root"],
                                           "validUntil": a["valid_until"]}
            return self._commit()
        if fn == "set_policy":
            self.policies[a["service"]] = list(a["classes"])
            return self._commit()
        if fn == "record_auth":
            self.auth[a["pid_hash"]] = {"pidHash": a["pid_hash"], "service": a["service"],
                                        "class": a["cls"], "expiry": a["expiry"], "rsu": caller}
            return self._commit()
        if fn == "report_misbehaviour":
            pid = a["pid"]
            reps = self.reports.setdefault(pid, {})
            reps[caller] = a["evidence_hash"]
            if len(reps) >= self.report_k:
                self._revoke(pid, f"{len(reps)} RSU reports")
            return self._commit(reports=len(reps), revoked=pid in self.revoked)
        if fn == "request_trace":
            rid = a["req_id"]
            if rid in self.traces:
                raise LedgerError(f"trace {rid} exists")
            self.traces[rid] = {"reqId": rid, "pid": a["pid"], "reason": a["reason"],
                                "requester": caller, "approvals": [], "approved": False}
            return self._commit()
        if fn == "approve_trace":
            tr = self.traces.get(a["req_id"])
            if tr is None:
                raise LedgerError(f"no trace {a['req_id']}")
            if caller not in tr["approvals"]:
                tr["approvals"].append(caller)
            tr["approved"] = len(tr["approvals"]) >= self.trace_threshold
            return self._commit(approvals=len(tr["approvals"]), approved=tr["approved"])
        if fn == "revoke":
            for pid in a["pids"]:
                self._revoke(pid, a.get("reason", "TA"))
            return self._commit()
        if fn == "get_auth":
            rec = self.auth.get(a["pid_hash"])
            return {"auth": dict(rec) if rec else None}
        if fn == "is_revoked":
            return {"revoked": a["pid"] in self.revoked}
        if fn == "get_revoked_since":
            since = int(a.get("since") or 0)
            items = sorted((r for r in self.revoked.values() if r["seq"] > since), key=lambda r: r["seq"])
            cursor = items[-1]["seq"] if items else since
            return {"revoked": [r["pid"] for r in items], "cursor": cursor}
        if fn == "get_trace":
            tr = self.traces.get(a["req_id"])
            return {"trace": json.loads(json.dumps(tr)) if tr else None}
        if fn == "get_policy":
            return {"classes": self.policies.get(a["service"])}
        if fn == "get_root":
            return {"root": self.roots.get(int(a["epoch"]))}
        raise LedgerError(f"unknown function {fn}")


class MockLedgerAdapter:
    """Wraps Person 2's ledger/mock_ledger.py.

    Accepted shapes: an object with ``call(caller, fn, **args)``, or one method
    per function taking ``caller`` as the first argument.
    """

    def __init__(self, impl) -> None:
        self.impl = impl

    def call(self, caller: str, fn: str, **a) -> dict:
        if hasattr(self.impl, "call"):
            return self.impl.call(caller, fn, **a)
        return getattr(self.impl, fn)(caller, **a)


# REST mapping for Person 2's gateway: fn -> (HTTP method, path, body fields)
REST_ROUTES = {
    "register_root": ("POST", "/roots", {"epoch": "epoch", "merkle_root": "merkleRoot", "valid_until": "validUntil"}),
    "set_policy": ("POST", "/policies", {"service": "service", "classes": "classes"}),
    "record_auth": ("POST", "/auth-records", {"pid_hash": "pidHash", "service": "service", "cls": "class", "expiry": "expiry"}),
    "get_auth": ("GET", "/auth-records/{pid_hash}", {}),
    "report_misbehaviour": ("POST", "/reports", {"pid": "pid", "evidence_hash": "evidenceHash"}),
    "is_revoked": ("GET", "/revoked/{pid}", {}),
    "get_revoked_since": ("GET", "/revoked?since={since}", {}),
    "request_trace": ("POST", "/traces", {"req_id": "reqId", "pid": "pid", "reason": "reason"}),
    "approve_trace": ("POST", "/traces/{req_id}/approve", {}),
    "get_trace": ("GET", "/traces/{req_id}", {}),
    "revoke": ("POST", "/revocations", {"pids": "pids", "reason": "reason"}),
    "get_policy": ("GET", "/policies/{service}", {}),
    "get_root": ("GET", "/roots/{epoch}", {}),
}


class RestLedgerClient:
    """Calls Person 2's REST gateway. Each call carries the caller identity in a
    header so the gateway can pick that identity's Fabric certificate."""

    def __init__(self, base_url: str, identity_header: str = "X-Identity", timeout: float = 30.0) -> None:
        self.base = base_url.rstrip("/")
        self.header = identity_header
        self.timeout = timeout

    def call(self, caller: str, fn: str, **a) -> dict:
        if fn not in REST_ROUTES:
            raise LedgerError(f"unknown function {fn}")
        method, path, fields = REST_ROUTES[fn]
        path = path.format(**{k: urllib.parse.quote(str(v), safe="") for k, v in a.items()})
        body = None
        if method == "POST":
            body = json.dumps({fields[k]: v for k, v in a.items() if k in fields}).encode()
        req = urllib.request.Request(self.base + path, data=body, method=method,
                                     headers={"Content-Type": "application/json", self.header: caller})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            msg = e.read().decode(errors="replace")
            if e.code in (401, 403):
                raise AccessDenied(f"{fn} by {caller}: {msg}") from e
            if e.code == 404 and fn in READS:
                return {}
            raise LedgerError(f"{fn} by {caller}: HTTP {e.code} {msg}") from e
        wall_ms = (time.perf_counter() - t0) * 1000
        if fn in WRITES:
            data.setdefault("commitMs", wall_ms)
            data.setdefault("txId", "")
        return data


def make_client(spec: str, *, report_k: int = 2, trace_threshold: int = 3,
                commit_ms: float = 500.0, seed: int = 1, identity_header: str = "X-Identity"):
    """spec: 'mock' (Person 2's mock, else built-in), 'builtin', or a gateway URL."""
    if spec.startswith("http://") or spec.startswith("https://"):
        return RestLedgerClient(spec, identity_header)
    if spec == "mock":
        try:
            from ledger import mock_ledger  # Person 2

            cls = getattr(mock_ledger, "MockLedger", None)
            if cls is not None:
                return MockLedgerAdapter(cls())
        except ImportError:
            pass
    if spec in ("mock", "builtin"):
        return InMemoryLedger(report_k=report_k, trace_threshold=trace_threshold,
                              commit_ms=commit_ms, seed=seed)
    raise ValueError(f"unknown ledger '{spec}'")
