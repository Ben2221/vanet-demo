"""Ledger bridge: the simulated-time rule between ns-3 and Fabric.

  - Reads come from a local copy of ledger state and are instant in simulated time.
  - Writes go to the ledger API for real. The API returns how long the commit
    took (commitMs). The write becomes visible in every RSU's local copy only
    after that much simulated time has passed.
  - The RSU that wrote an authorization record sees it at once (it knows what it
    wrote); everyone else waits for the commit.

So a vehicle never waits for a block, but the delay before other RSUs see a
change is the real Fabric delay.

With a REST gateway, writes run on a thread pool so several commits overlap in
real time, as they would on a real network. When simulated time reaches the
expected commit time the bridge collects the result (waiting in real time if
Fabric is still busy) and schedules the visibility at submit time + commitMs.
"""

from __future__ import annotations

import statistics
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable

from network.ledger_client import AccessDenied, LedgerError, RestLedgerClient


class LedgerCache:
    """Committed ledger state as the RSUs see it."""

    def __init__(self) -> None:
        self.roots: dict[int, dict] = {}
        self.policies: dict[str, list] = {}
        self.auth: dict[str, dict] = {}
        self.revoked: dict[str, float] = {}        # pid -> sim time it became visible
        self.traces: dict[str, dict] = {}


class LedgerBridge:
    def __init__(self, client, now: Callable[[], float], schedule: Callable[[float, Callable], None],
                 log: Callable[..., None] | None = None, sync_interval: float = 1.0,
                 workers: int = 8, sync_identity: str = "TA") -> None:
        self.client = client
        self.now = now
        self.schedule = schedule
        self.log = log or (lambda *a, **k: None)
        self.cache = LedgerCache()
        self.remote = isinstance(client, RestLedgerClient)
        self.pool = ThreadPoolExecutor(max_workers=workers) if self.remote else None
        self.commit_ms: list[float] = []
        self.visibility_lag_ms: list[float] = []   # extra delay when Fabric was slower than simulated time
        self.sync_interval = sync_interval
        self.sync_identity = sync_identity          # who reads the revocation list for the sync
        self._cursor = 0
        self._views: dict[str, LedgerView] = {}

    # ------------------------------------------------------------------ views
    def view(self, identity: str) -> "LedgerView":
        if identity not in self._views:
            self._views[identity] = LedgerView(self, identity)
        return self._views[identity]

    def preload(self, caller: str, fn: str, **args) -> dict:
        """Setup-time write (before the simulation starts): committed and visible at once."""
        res = self.client.call(caller, fn, **args)
        self._apply(fn, args, res)
        return res

    def start(self) -> None:
        if self.remote and self.sync_interval > 0:
            self.schedule(self.sync_interval, self._sync)

    def close(self) -> None:
        if self.pool:
            self.pool.shutdown(wait=True)

    # ----------------------------------------------------------------- writes
    def write(self, caller: str, fn: str, args: dict, on_commit: Callable[[dict | None], None] | None) -> None:
        t_submit = self.now()
        if self.pool is None:
            try:
                res = self.client.call(caller, fn, **args)
            except LedgerError as e:
                self._failed(caller, fn, e, on_commit)
                return
            self._schedule_visible(caller, fn, args, res, t_submit, on_commit)
            return
        fut: Future = self.pool.submit(self.client.call, caller, fn, **args)
        est = statistics.median(self.commit_ms) / 1000 if self.commit_ms else 0.5

        def collect() -> None:
            try:
                res = fut.result()       # blocks in real time only if Fabric is still committing
            except LedgerError as e:
                self._failed(caller, fn, e, on_commit)
                return
            except Exception as e:      # network errors: report, do not crash the run
                self._failed(caller, fn, LedgerError(str(e)), on_commit)
                return
            self._schedule_visible(caller, fn, args, res, t_submit, on_commit)

        self.schedule(est, collect)

    def _failed(self, caller, fn, err, on_commit) -> None:
        event = "LEDGER_DENIED" if isinstance(err, AccessDenied) else "LEDGER_ERROR"
        self.log(caller, event, result=f"{fn}: {err}")
        if on_commit:
            on_commit({"error": str(err), "denied": isinstance(err, AccessDenied)})

    def _schedule_visible(self, caller, fn, args, res, t_submit, on_commit) -> None:
        commit_ms = float(res.get("commitMs", 0.0))
        self.commit_ms.append(commit_ms)
        due = t_submit + commit_ms / 1000.0
        lag = max(0.0, self.now() - due)
        if lag > 0:
            self.visibility_lag_ms.append(lag * 1000)
        self.log(caller, "LEDGER_SUBMIT", latency_ms=commit_ms, result=f"{fn}:{res.get('txId', '')}")

        def visible() -> None:
            self._apply(fn, args, res)
            self.log(caller, "LEDGER_VISIBLE", latency_ms=(self.now() - t_submit) * 1000,
                     result=f"{fn}:{res.get('txId', '')}")
            if on_commit:
                on_commit(res)

        self.schedule(max(0.0, due - self.now()), visible)

    def _apply(self, fn: str, a: dict, res: dict) -> None:
        c = self.cache
        if fn == "register_root":
            c.roots[int(a["epoch"])] = {"epoch": int(a["epoch"]), "merkleRoot": a["merkle_root"],
                                        "validUntil": a["valid_until"]}
        elif fn == "set_policy":
            c.policies[a["service"]] = list(a["classes"])
        elif fn == "record_auth":
            c.auth[a["pid_hash"]] = {"pidHash": a["pid_hash"], "service": a["service"],
                                     "class": a["cls"], "expiry": a["expiry"]}
        elif fn == "report_misbehaviour":
            revoked = res.get("revoked")
            if revoked is None:
                revoked = bool(self.client.call("TA", "is_revoked", pid=a["pid"]).get("revoked"))
            if revoked:
                self._mark_revoked([a["pid"]])
        elif fn == "revoke":
            self._mark_revoked(list(a["pids"]))
        elif fn in ("request_trace", "approve_trace"):
            tr = self.client.call("TA", "get_trace", req_id=a["req_id"]).get("trace")
            if tr:
                c.traces[a["req_id"]] = tr

    def _mark_revoked(self, pids: list[str]) -> None:
        for pid in pids:
            if pid not in self.cache.revoked:
                self.cache.revoked[pid] = self.now()
                self.log("ledger", "REVOKED_VISIBLE", result=pid)

    def _sync(self) -> None:
        """Pick up revocations made outside this scenario (real Fabric only)."""
        try:
            res = self.client.call(self.sync_identity, "get_revoked_since", since=self._cursor)
            self._mark_revoked(res.get("revoked", []))
            self._cursor = res.get("cursor", self._cursor)
        except LedgerError as e:
            self.log("ledger", "LEDGER_ERROR", result=f"sync: {e}")
        self.schedule(self.sync_interval, self._sync)

    def stats(self) -> dict:
        cm = sorted(self.commit_ms)

        def pct(p):
            return cm[min(len(cm) - 1, int(p * (len(cm) - 1) + 0.5))] if cm else None

        return {"writes": len(cm), "commit_ms_median": pct(0.5), "commit_ms_p95": pct(0.95),
                "late_visibility": len(self.visibility_lag_ms),
                "revoked": len(self.cache.revoked)}


class LedgerView:
    """What one RSU (or the TA) sees: instant reads, asynchronous writes."""

    def __init__(self, bridge: LedgerBridge, identity: str) -> None:
        self.bridge = bridge
        self.identity = identity
        self._own_auth: dict[str, dict] = {}

    # reads: local copy, no simulated delay
    def get_auth(self, pid_hash: str) -> dict | None:
        return self._own_auth.get(pid_hash) or self.bridge.cache.auth.get(pid_hash)

    def is_revoked(self, pid: str) -> bool:
        return pid in self.bridge.cache.revoked

    def revoked(self) -> list[str]:
        """Revoked pseudonyms, oldest first."""
        return list(self.bridge.cache.revoked)

    def get_trace(self, req_id: str) -> dict | None:
        return self.bridge.cache.traces.get(req_id)

    def traces(self) -> dict[str, dict]:
        """All trace requests visible so far, {req_id: trace} (a copy)."""
        return dict(self.bridge.cache.traces)

    def get_policy(self, service: str) -> list | None:
        return self.bridge.cache.policies.get(service)

    def get_root(self, epoch: int) -> dict | None:
        return self.bridge.cache.roots.get(int(epoch))

    def current_root(self) -> dict | None:
        roots = self.bridge.cache.roots
        return roots[max(roots)] if roots else None

    # writes: sent now, visible to others after the commit time
    def _w(self, fn: str, on_commit=None, **args) -> None:
        self.bridge.write(self.identity, fn, args, on_commit)

    def record_auth(self, pid_hash: str, service: str, cls: str, expiry: float, on_commit=None) -> None:
        self._own_auth[pid_hash] = {"pidHash": pid_hash, "service": service, "class": cls, "expiry": expiry}
        self._w("record_auth", on_commit, pid_hash=pid_hash, service=service, cls=cls, expiry=expiry)

    def report_misbehaviour(self, pid: str, evidence_hash: str, on_commit=None) -> None:
        self._w("report_misbehaviour", on_commit, pid=pid, evidence_hash=evidence_hash)

    def request_trace(self, req_id: str, pid: str, reason: str, on_commit=None) -> None:
        self._w("request_trace", on_commit, req_id=req_id, pid=pid, reason=reason)

    def approve_trace(self, req_id: str, on_commit=None) -> None:
        self._w("approve_trace", on_commit, req_id=req_id)

    def register_root(self, epoch: int, merkle_root: str, valid_until: float, on_commit=None) -> None:
        self._w("register_root", on_commit, epoch=epoch, merkle_root=merkle_root, valid_until=valid_until)

    def set_policy(self, service: str, classes: list, on_commit=None) -> None:
        self._w("set_policy", on_commit, service=service, classes=classes)

    def revoke(self, pids: list[str], reason: str, on_commit=None) -> None:
        self._w("revoke", on_commit, pids=pids, reason=reason)
