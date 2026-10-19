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

import hashlib
import itertools
import json
import os
import random
import re
import secrets
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


_HEX64 = re.compile(r"^[a-f0-9]{64}$")
_BAD_NAME = re.compile(r"[^a-z0-9-]")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class RestLedgerClient:
    """Calls Person 2's REST gateway (ledger/gateway, or ledger/mock/mock_ledger_server.py).

    The scenario keeps its own names and simulated times; this client translates
    them to the gateway contract (docs in ledger/gateway/README.md) and back:

      caller      "TA" -> "ta1"; RSU names pass through lowercased, or are folded
                  onto ``rsu_identities`` (e.g. rsu1..rsu4 enrolled on Fabric)
      pid         sha256(run salt + pid) as 64 lowercase hex, so runs never collide
      epoch/reqId made unique per run, for the same reason
      service     lowercased, characters outside [a-z0-9-] become '-'
      times       simulated seconds -> wall-clock ms in the future; reads return
                  the simulated values the scenario wrote
      responses   {"ok", "result", ...} is unwrapped into the shapes InMemoryLedger returns
      revoke      sent as POST /traces/{reqId}/revoke for the trace of one of the pids

    Each call carries the caller identity in a header so the gateway can pick that
    identity's Fabric certificate. The first call sets the gateway config (K, trace
    threshold) to the scenario's values.
    """

    def __init__(self, base_url: str, identity_header: str = "X-Identity", timeout: float = 30.0,
                 report_k: int = 2, trace_threshold: int = 3, ta_identity: str = "ta1",
                 rsu_identities: list[str] | None = None) -> None:
        self.base = base_url.rstrip("/")
        self.header = identity_header
        self.timeout = timeout
        self.report_k = report_k
        self.trace_threshold = trace_threshold
        self.ta_identity = ta_identity
        self.rsu_identities = rsu_identities or []
        self.salt = secrets.token_hex(4)
        self.epoch_base = int(time.time() * 1000)
        self._configured = False
        self._pid: dict[str, str] = {}            # scenario pid -> gateway pid
        self._pid_back: dict[str, str] = {}
        self._req_back: dict[str, str] = {}
        self._trace_of_pid: dict[str, str] = {}   # scenario pid -> scenario req_id
        self._expiry: dict[str, float] = {}       # gateway pid -> simulated expiry
        self._roots: dict[int, dict] = {}
        self._services: dict[str, str] = {}
        self._rsu_map: dict[str, str] = {}

    # ------------------------------------------------------------ translation
    def identity(self, caller: str) -> str:
        if caller == "TA":
            return self.ta_identity
        if not is_rsu(caller) or not self.rsu_identities:
            return caller.lower()
        if caller not in self._rsu_map:
            self._rsu_map[caller] = self.rsu_identities[len(self._rsu_map) % len(self.rsu_identities)]
        return self._rsu_map[caller]

    def pid(self, pid: str) -> str:
        if pid not in self._pid:
            g = _sha(f"{self.salt}:{pid}")
            self._pid[pid], self._pid_back[g] = g, pid
        return self._pid[pid]

    def req(self, req_id: str) -> str:
        g = f"r{self.salt}-{_sha(req_id)[:40]}"
        self._req_back[g] = req_id
        return g

    def service(self, service: str) -> str:
        if service not in self._services:
            self._services[service] = _BAD_NAME.sub("-", service.lower()).strip("-")[:32] or "service"
        return self._services[service]

    @staticmethod
    def hex64(value: str) -> str:
        return value if _HEX64.match(value) else _sha(value)

    @staticmethod
    def future_ms(seconds: float, cap_s: float | None = None) -> int:
        seconds = max(float(seconds), 1.0)
        if cap_s is not None:
            seconds = min(seconds, cap_s)
        return min(int(time.time() * 1000 + seconds * 1000), 9_007_199_254_740_991)

    # ------------------------------------------------------------------- http
    def _http(self, caller: str, method: str, path: str, body: dict | None = None,
              fn: str = "") -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json",
                                              self.header: self.identity(caller)})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                out = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            msg = e.read().decode(errors="replace")
            if e.code in (401, 403):
                raise AccessDenied(f"{fn} by {caller}: {msg}") from e
            return e.code, {"_error": f"{fn} by {caller}: HTTP {e.code} {msg}"}
        out.setdefault("_ms", (time.perf_counter() - t0) * 1000)
        return 200, out

    @staticmethod
    def _ok(status: int, out: dict) -> dict:
        if status != 200:
            raise LedgerError(out["_error"])
        return out

    def _configure(self) -> None:
        if self._configured:
            return
        self._configured = True
        cfg = {"K": self.report_k, "traceThreshold": self.trace_threshold,
               "maxAuthTtlSec": 86400, "demoMode": True}
        self._ok(*self._http("TA", "PUT", "/config", cfg, "set_config"))

    @staticmethod
    def _written(out: dict, **extra) -> dict:
        res = dict(out["result"]) if isinstance(out.get("result"), dict) else {}
        res.update(extra)
        res["txId"] = out.get("txId", "")
        res["commitMs"] = float(out.get("commitMs", out.get("_ms", 0.0)))
        return res

    def _trace(self, tr: dict) -> dict:
        return {**tr, "reqId": self._req_back.get(tr.get("reqId"), tr.get("reqId")),
                "pid": self._pid_back.get(tr.get("pid"), tr.get("pid")),
                "approvals": list(tr.get("approvals", [])),
                "approved": tr.get("status") in ("APPROVED", "EXECUTED")}

    # ------------------------------------------------------------------- call
    def call(self, caller: str, fn: str, **a) -> dict:
        if fn not in WRITES | READS:
            raise LedgerError(f"unknown function {fn}")
        self._configure()
        q = urllib.parse.quote

        if fn == "register_root":
            body = {"epoch": self.epoch_base + int(a["epoch"]), "merkleRoot": self.hex64(a["merkle_root"]),
                    "validUntil": self.future_ms(a["valid_until"])}
            out = self._written(self._ok(*self._http(caller, "POST", "/roots", body, fn)))
            self._roots[int(a["epoch"])] = {"epoch": int(a["epoch"]), "merkleRoot": a["merkle_root"],
                                           "validUntil": a["valid_until"]}
            return out
        if fn == "set_policy":
            path = f"/policies/{q(self.service(a['service']), safe='')}"
            return self._written(self._ok(*self._http(caller, "PUT", path, {"classes": list(a["classes"])}, fn)))
        if fn == "record_auth":
            pid = self.pid(a["pid_hash"])
            body = {"pid": pid, "service": self.service(a["service"]), "class": a["cls"],
                    "expiry": self.future_ms(a["expiry"], cap_s=86400 - 60)}
            out = self._written(self._ok(*self._http(caller, "POST", "/auth-records", body, fn)))
            self._expiry[pid] = a["expiry"]
            return out
        if fn == "report_misbehaviour":
            body = {"pid": self.pid(a["pid"]), "evidenceHash": self.hex64(a["evidence_hash"])}
            out = self._written(self._ok(*self._http(caller, "POST", "/reports", body, fn)))
            out.update(pid=a["pid"], reports=out.get("reportCount", 0))
            return out
        if fn == "request_trace":
            body = {"reqId": self.req(a["req_id"]), "pid": self.pid(a["pid"]), "reason": a["reason"][:128]}
            out = self._written(self._ok(*self._http(caller, "POST", "/traces", body, fn)))
            self._trace_of_pid.setdefault(a["pid"], a["req_id"])
            out.update(reqId=a["req_id"], pid=a["pid"])
            return out
        if fn == "approve_trace":
            status, out = self._http(caller, "POST", f"/traces/{self.req(a['req_id'])}/approve", None, fn)
            if status == 409:      # this RSU already approved, or the trace is no longer pending
                tr = self.call(caller, "get_trace", req_id=a["req_id"]).get("trace") or {}
                return {"txId": "", "commitMs": 0.0, "approvals": len(tr.get("approvals", [])),
                        "approved": bool(tr.get("approved"))}
            tr = self._trace(self._ok(status, out).get("result") or {})
            return {"txId": out.get("txId", ""), "commitMs": float(out.get("commitMs", 0.0)),
                    "approvals": len(tr["approvals"]), "approved": tr["approved"]}
        if fn == "revoke":
            req_id = next((self._trace_of_pid[p] for p in a["pids"] if p in self._trace_of_pid), "none")
            body = {"pids": [self.pid(p) for p in a["pids"]], "reason": (a.get("reason") or "TA")[:128]}
            out = self._ok(*self._http(caller, "POST", f"/traces/{self.req(req_id)}/revoke", body, fn))
            return self._written(out, revoked_count=len(body["pids"]))

        # reads: HTTP 404 means "none"
        if fn == "get_auth":
            pid = self.pid(a["pid_hash"])
            status, out = self._http(caller, "GET", f"/auth-records/{pid}", None, fn)
            if status == 404:
                return {"auth": None}
            rec = self._ok(status, out).get("result") or {}
            back = {v: k for k, v in self._services.items()}
            return {"auth": {"pidHash": a["pid_hash"], "service": back.get(rec.get("service"), rec.get("service")),
                             "class": rec.get("class"), "expiry": self._expiry.get(pid, rec.get("expiry")),
                             "rsu": rec.get("rsuId")}}
        if fn == "is_revoked":
            status, out = self._http(caller, "GET", f"/revoked/{self.pid(a['pid'])}", None, fn)
            if status == 404:
                return {"revoked": False}
            return {"revoked": bool((self._ok(status, out).get("result") or {}).get("revoked"))}
        if fn == "get_revoked_since":
            since = int(a.get("since") or 0)
            items = self._ok(*self._http(caller, "GET", f"/revoked?since={since}", None, fn)).get("result") or []
            cursor = max([since - 1] + [int(r.get("revokedTs", 0)) for r in items]) + 1
            # only this run's pseudonyms map back; the rest belong to other runs
            return {"revoked": [self._pid_back[r["pid"]] for r in items if r.get("pid") in self._pid_back],
                    "cursor": cursor}
        if fn == "get_trace":
            status, out = self._http(caller, "GET", f"/traces/{self.req(a['req_id'])}", None, fn)
            if status == 404:
                return {"trace": None}
            return {"trace": self._trace(self._ok(status, out).get("result") or {})}
        if fn == "get_policy":
            path = f"/policies/{q(self.service(a['service']), safe='')}"
            status, out = self._http(caller, "GET", path, None, fn)
            if status == 404:
                return {"classes": None}
            return {"classes": (self._ok(status, out).get("result") or {}).get("classes")}
        if fn == "get_root":
            epoch = int(a["epoch"])
            status, out = self._http(caller, "GET", f"/roots/{self.epoch_base + epoch}", None, fn)
            if status == 404:
                return {"root": None}
            self._ok(status, out)
            return {"root": self._roots.get(epoch)}
        raise LedgerError(f"unknown function {fn}")


def check_gateway(url: str) -> None:
    """Fail fast with a readable message if nothing (or something else) answers at url."""
    health = url.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(health, timeout=5) as resp:
            body = json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except ValueError:
            body = None
    except (urllib.error.URLError, OSError) as e:
        raise LedgerError(f"no ledger gateway at {url} ({e}). Start one with "
                          f"'make mock' (PORT=... to change the port) or 'make gateway'.") from e
    except ValueError:
        body = None
    if not isinstance(body, dict) or "gateway" not in body:
        raise LedgerError(f"{health} did not answer like a ledger gateway; another service "
                          f"may be using that port. Pick a free port with PORT=...")


def make_client(spec: str, *, report_k: int = 2, trace_threshold: int = 3,
                commit_ms: float = 500.0, seed: int = 1, identity_header: str = "X-Identity"):
    """spec: 'mock' (Person 2's mock, else built-in), 'builtin', or a gateway URL."""
    if spec.startswith("http://") or spec.startswith("https://"):
        check_gateway(spec)
        rsus = [s.strip() for s in os.environ.get("LEDGER_RSU_IDENTITIES", "").split(",") if s.strip()]
        return RestLedgerClient(spec, identity_header, report_k=report_k,
                                trace_threshold=trace_threshold, rsu_identities=rsus)
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
