#!/usr/bin/env python3
"""Small in-memory implementation of the deployed VANET gateway routes."""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
import uuid
from typing import Any, NoReturn

from fastapi import FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse


PID_RE = re.compile(r"^[a-f0-9]{64}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
REQ_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
MAX_SAFE_INTEGER = 9_007_199_254_740_991
ZERO_AUTH = {
    "pid": "",
    "service": "",
    "class": "",
    "expiry": 0,
    "rsuId": "",
    "firstTs": 0,
    "ts": 0,
    "sessionCount": 0,
}


class LedgerError(Exception):
    def __init__(self, status: int, code: str, message: str | None = None):
        super().__init__(message or code)
        self.status = status
        self.code = code
        self.message = message or code


class State:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.config = {
            "K": 2,
            "traceThreshold": 3,
            "maxAuthTtlSec": 3600,
            "demoMode": True,
        }
        self.roots: dict[int, dict[str, Any]] = {}
        self.policies: dict[str, dict[str, Any]] = {}
        self.auths: dict[str, dict[str, Any]] = {}
        self.reports: dict[str, dict[str, dict[str, Any]]] = {}
        self.revocations: dict[str, dict[str, Any]] = {}
        self.traces: dict[str, dict[str, Any]] = {}
        self.activity: list[dict[str, Any]] = []
        self.block_number = 1


state = State()
app = FastAPI(title="VANET mock ledger", docs_url=None, redoc_url=None, openapi_url=None)


def now_ms() -> int:
    return int(time.time() * 1000)


def error(status: int, code: str, message: str | None = None) -> NoReturn:
    raise LedgerError(status, code, message)


def ensure_body(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        error(400, "ERR_BAD_INPUT", "Request body must be a JSON object")
    return value


def required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        error(400, "ERR_BAD_INPUT", f"{field} must be a non-empty string")
    return value


def integer(value: Any, field: str, minimum: int = 0, maximum: int = MAX_SAFE_INTEGER) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        error(400, "ERR_BAD_INPUT", f"{field} must be an integer between {minimum} and {maximum}")
    return value


def valid_pid(value: Any, field: str = "pid") -> str:
    if not isinstance(value, str) or not PID_RE.fullmatch(value):
        error(400, "ERR_BAD_INPUT", f"{field} must be 64 lowercase hexadecimal characters")
    return value


def valid_name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        error(400, "ERR_BAD_INPUT", f"{field} must match {NAME_RE.pattern}")
    return value


def valid_req_id(value: Any) -> str:
    if not isinstance(value, str) or not REQ_ID_RE.fullmatch(value):
        error(400, "ERR_BAD_INPUT", f"reqId must match {REQ_ID_RE.pattern}")
    return value


def free_text(value: Any, field: str) -> str:
    required_string(value, field)
    if len(value) > 128 or "\x00" in value or "\U0010ffff" in value:
        error(400, "ERR_BAD_INPUT", f"{field} must be at most 128 characters and contain no reserved characters")
    return value


def since_value(value: str | None) -> int:
    if value is None:
        return 0
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        error(400, "ERR_BAD_INPUT", "since must be a non-negative integer")
    parsed = int(value)
    return integer(parsed, "since")


def get_identity(header: str | None, default: str = "rsu1") -> tuple[str, str, str]:
    identity = (header or "").strip() or default
    if identity.startswith("ta"):
        return identity, "TA", "Org1MSP"
    if identity.startswith("rsu"):
        return identity, "RSU", "Org2MSP"
    error(400, "ERR_BAD_INPUT", f"Unknown identity: {identity}")


def require_role(identity: tuple[str, str, str], *roles: str) -> str:
    name, role, _msp = identity
    if "ANY" not in roles and role not in roles:
        error(403, "ERR_FORBIDDEN", f"{name} ({role}) may not call this function")
    return name


async def json_body(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except ValueError:
        error(400, "ERR_BAD_INPUT", "Invalid JSON request body")
    return ensure_body(body)


def evaluate(result: Any) -> dict[str, Any]:
    return {"ok": True, "queryMs": 0, "result": result}


def commit_ms() -> int | float:
    value = os.environ.get("MOCK_COMMIT_MS", "600")
    try:
        parsed = float(value)
    except ValueError:
        parsed = 600
    return int(parsed) if parsed.is_integer() else parsed


def write(identity: str, function: str, result: Any, retries: int = 0) -> dict[str, Any]:
    with state.lock:
        state.block_number += 1
        tx_id = str(uuid.uuid4())
        duration = commit_ms()
        block_number = state.block_number
        state.activity.append({
            "ts": now_ms(),
            "identity": identity,
            "fn": function,
            "txId": tx_id,
            "blockNumber": block_number,
            "commitMs": duration,
            "ok": True,
            "code": None,
        })
        del state.activity[:-200]
    return {
        "ok": True,
        "txId": tx_id,
        "blockNumber": block_number,
        "endorseMs": 0,
        "commitMs": duration,
        "totalMs": duration,
        "retries": retries,
        "result": result,
    }


def valid_config(body: dict[str, Any]) -> dict[str, Any]:
    demo_mode = body.get("demoMode")
    if not isinstance(demo_mode, bool):
        error(400, "ERR_BAD_INPUT", "demoMode must be a boolean")
    return {
        "K": integer(body.get("K"), "K", 1, 10),
        "traceThreshold": integer(body.get("traceThreshold"), "traceThreshold", 1, 10),
        "maxAuthTtlSec": integer(body.get("maxAuthTtlSec"), "maxAuthTtlSec", 60, 86400),
        "demoMode": demo_mode,
    }


def zero_auth() -> dict[str, Any]:
    return dict(ZERO_AUTH)


def revoked_record(pid: str, reason: str, reporters: list[str], first_ts: int,
                   revoked_ts: int, source: str, req_id: str = "") -> dict[str, Any]:
    record = {
        "pid": pid,
        "reason": reason,
        "reporters": list(reporters),
        "firstReportTs": first_ts,
        "revokedTs": revoked_ts,
        "source": source,
    }
    if req_id:
        record["reqId"] = req_id
    return record


def auth_is_active(record: dict[str, Any] | None, now: int | None = None) -> bool:
    return bool(record and record["expiry"] > (now if now is not None else now_ms()))


def pseudonym_status(pid: str) -> dict[str, Any]:
    revocation = state.revocations.get(pid)
    reports = state.reports.get(pid, {})
    reporter_ids = sorted(reports)
    if revocation:
        reporter_ids = list(revocation["reporters"])
    return {
        "pid": pid,
        "revoked": revocation is not None,
        "revokedTs": revocation["revokedTs"] if revocation else 0,
        "reportCount": len(reports),
        "reporters": reporter_ids,
        "firstReportTs": (revocation["firstReportTs"] if revocation else
                          min((item["ts"] for item in reports.values()), default=0)),
        "activeAuth": (state.auths[pid] if auth_is_active(state.auths.get(pid)) and not revocation
                       else zero_auth()),
    }


def report_result(pid: str, *, count: int = 0, revoked: bool = False,
                  newly_revoked: bool = False, duplicate: bool = False,
                  already_revoked: bool = False) -> dict[str, Any]:
    return {
        "pid": pid,
        "reportCount": count,
        "K": state.config["K"],
        "revoked": revoked,
        "newlyRevoked": newly_revoked,
        "duplicate": duplicate,
        "alreadyRevoked": already_revoked,
    }


def new_trace(req_id: str, pid: str, reason: str, requester: str) -> dict[str, Any]:
    return {
        "reqId": req_id,
        "pid": pid,
        "reason": reason,
        "requester": requester,
        "status": "PENDING",
        "threshold": state.config["traceThreshold"],
        "approvals": [],
        "revokedPids": [],
        "createdTs": now_ms(),
        "approvedTs": 0,
        "executedTs": 0,
    }


@app.exception_handler(LedgerError)
async def ledger_error_handler(_request: Request, exc: LedgerError) -> JSONResponse:
    details: dict[str, Any] = {"code": exc.code}
    if exc.code != "NOT_DEPLOYED":
        details["message"] = exc.message
    return JSONResponse(status_code=exc.status, content={"ok": False, "error": details})


@app.exception_handler(Exception)
async def internal_error_handler(_request: Request, _exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"ok": False, "error": {"code": "INTERNAL_ERROR", "message": "Internal server error"}},
    )


@app.get("/health")
def health(x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity)
    name, _role, _msp = identity
    return {"gateway": "up", "chaincode": "ok", "identity": name}


@app.get("/whoami")
def whoami(x_identity: str | None = Header(default=None, alias="X-Identity")):
    name, role, msp = get_identity(x_identity)
    return evaluate({"msp": msp, "role": role, "id": name})


@app.get("/config")
def get_config(x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    with state.lock:
        return evaluate(dict(state.config))


@app.put("/config")
async def set_config(request: Request, x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity, "ta1")
    name = require_role(identity, "TA")
    body = await json_body(request)
    config = valid_config(body)
    with state.lock:
        state.config = config
    return write(name, "SetConfig", dict(config))


@app.post("/roots")
async def register_root(request: Request, x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity, "ta1")
    name = require_role(identity, "TA")
    body = await json_body(request)
    epoch = integer(body.get("epoch"), "epoch")
    root = body.get("merkleRoot")
    if not isinstance(root, str) or not PID_RE.fullmatch(root):
        error(400, "ERR_BAD_INPUT", "merkleRoot must be 64 lowercase hexadecimal characters")
    valid_until = integer(body.get("validUntil"), "validUntil", 1)
    current = now_ms()
    if valid_until <= current:
        error(400, "ERR_BAD_INPUT", "validUntil must be in the future")
    with state.lock:
        if epoch in state.roots:
            error(409, "ERR_CONFLICT", f"root epoch {epoch} already exists")
        result = {"epoch": epoch, "merkleRoot": root, "validUntil": valid_until, "registeredTs": current}
        state.roots[epoch] = result
    return write(name, "RegisterRoot", result)


@app.get("/roots")
def list_roots(x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    current = now_ms()
    with state.lock:
        result = [state.roots[key] for key in sorted(state.roots) if state.roots[key]["validUntil"] > current]
    return evaluate(result)


@app.get("/roots/{epoch}")
def get_root(epoch: str, x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", epoch):
        error(400, "ERR_BAD_INPUT", "epoch must be a non-negative integer")
    parsed = integer(int(epoch), "epoch")
    with state.lock:
        result = state.roots.get(parsed)
    if result is None:
        error(404, "ERR_NOT_FOUND", f"root epoch {parsed} was not found")
    return evaluate(result)


@app.put("/policies/{service}")
async def set_policy(service: str, request: Request,
                     x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity, "ta1")
    name = require_role(identity, "TA")
    valid_name(service, "service")
    body = await json_body(request)
    classes = body.get("classes")
    if not isinstance(classes, list) or not all(isinstance(value, str) for value in classes):
        error(400, "ERR_BAD_INPUT", "classes must be an array of class names")
    unique = []
    for value in classes:
        valid_name(value, "class")
        if value not in unique:
            unique.append(value)
    result = {"service": service, "classes": unique, "updatedTs": now_ms()}
    with state.lock:
        state.policies[service] = result
    return write(name, "SetPolicy", result)


@app.get("/policies")
def list_policies(x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    with state.lock:
        result = [state.policies[key] for key in sorted(state.policies)]
    return evaluate(result)


@app.get("/policies/{service}")
def get_policy(service: str, x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    valid_name(service, "service")
    with state.lock:
        result = state.policies.get(service)
    if result is None:
        error(404, "ERR_NOT_FOUND", f'policy for service "{service}" was not found')
    return evaluate(result)


@app.post("/auth-records")
async def record_auth(request: Request, x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity)
    name = require_role(identity, "RSU")
    body = await json_body(request)
    pid = valid_pid(body.get("pid"))
    service = valid_name(body.get("service"), "service")
    vehicle_class = valid_name(body.get("class"), "class")
    expiry = integer(body.get("expiry"), "expiry", 1)
    current = now_ms()
    if expiry <= current:
        error(400, "ERR_BAD_INPUT", "expiry must be in the future")
    with state.lock:
        if pid in state.revocations:
            error(409, "ERR_CONFLICT", "pseudonym revoked")
        policy = state.policies.get(service)
        if policy is None:
            error(404, "ERR_NOT_FOUND", f'policy for service "{service}" was not found')
        if vehicle_class not in policy["classes"]:
            error(403, "ERR_FORBIDDEN", "class not allowed for service")
        if expiry <= current or expiry > current + state.config["maxAuthTtlSec"] * 1000:
            error(400, "ERR_BAD_INPUT", "expiry must be in the future and within maxAuthTtlSec")
        previous = state.auths.get(pid)
        record = {
            "pid": pid,
            "service": service,
            "class": vehicle_class,
            "expiry": expiry,
            "rsuId": name,
            "firstTs": previous["firstTs"] if previous else current,
            "ts": current,
            "sessionCount": previous["sessionCount"] + 1 if previous else 1,
        }
        state.auths[pid] = record
    return write(name, "RecordAuth", record)


@app.get("/auth-records")
def list_auths(since: str | None = None, x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    threshold = since_value(since)
    current = now_ms()
    with state.lock:
        records = [record for pid, record in state.auths.items()
                   if record["ts"] >= threshold and record["expiry"] > current and pid not in state.revocations]
        result = sorted(records, key=lambda record: (record["ts"], record["pid"]))
    return evaluate(result)


@app.get("/auth-records/{pid}")
def get_auth(pid: str, x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    valid_pid(pid)
    current = now_ms()
    with state.lock:
        record = state.auths.get(pid)
        revoked = pid in state.revocations
    if not record or record["expiry"] <= current or revoked:
        error(404, "ERR_NOT_FOUND", f'active authorization for pid "{pid}" was not found')
    return evaluate(record)


@app.get("/access-check")
def check_access(pid: str | None = None,
                 vehicle_class: str | None = Query(default=None, alias="class"),
                 service: str | None = None,
                 x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    pid = valid_pid(pid)
    vehicle_class = valid_name(vehicle_class, "class")
    service = valid_name(service, "service")
    with state.lock:
        revoked = pid in state.revocations
        policy = state.policies.get(service)
        auth = state.auths.get(pid)
        current = now_ms()
        reasons = []
        if revoked:
            reasons.append("REVOKED")
        if policy is None:
            reasons.append("NO_POLICY")
            allowed_class = False
        else:
            allowed_class = vehicle_class in policy["classes"]
            if not allowed_class:
                reasons.append("CLASS_NOT_ALLOWED")
        if not auth_is_active(auth, current) or revoked:
            reasons.append("NO_ACTIVE_AUTH")
            active_auth = zero_auth()
        else:
            active_auth = auth
        result = {"allow": not revoked and policy is not None and allowed_class,
                  "reasons": reasons, "activeAuth": active_auth}
    return evaluate(result)


@app.post("/reports")
async def report_misbehaviour(request: Request,
                              x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity)
    name = require_role(identity, "RSU")
    body = await json_body(request)
    pid = valid_pid(body.get("pid"))
    evidence = body.get("evidenceHash")
    if not isinstance(evidence, str) or not PID_RE.fullmatch(evidence):
        error(400, "ERR_BAD_INPUT", "evidenceHash must be 64 lowercase hexadecimal characters")
    attack = body.get("attackType", "")
    if attack != "":
        valid_name(attack, "attackType")
    with state.lock:
        existing_revocation = state.revocations.get(pid)
        if existing_revocation:
            result = report_result(pid, count=len(existing_revocation["reporters"]), revoked=True,
                                   already_revoked=True)
        else:
            reports = state.reports.setdefault(pid, {})
            if name in reports:
                result = report_result(pid, count=len(reports), duplicate=True)
            else:
                current = now_ms()
                reports[name] = {"pid": pid, "rsuId": name, "evidenceHash": evidence,
                                 "attackType": attack, "ts": current}
                count = len(reports)
                newly_revoked = count >= state.config["K"]
                if newly_revoked:
                    reporters = sorted(reports)
                    state.revocations[pid] = revoked_record(
                        pid, attack or "AUTO_REPORTS", reporters,
                        min(item["ts"] for item in reports.values()), current, "AUTO_REPORTS")
                result = report_result(pid, count=count, revoked=newly_revoked,
                                       newly_revoked=newly_revoked)
    return write(name, "ReportMisbehaviour", result)


@app.get("/pseudonyms/{pid}")
def get_pseudonym_status(pid: str,
                         x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    valid_pid(pid)
    with state.lock:
        result = pseudonym_status(pid)
    return evaluate(result)


@app.get("/revoked")
def list_revoked(since: str | None = None,
                 x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    threshold = since_value(since)
    with state.lock:
        result = [record for record in state.revocations.values() if record["revokedTs"] >= threshold]
        result = sorted(result, key=lambda record: (record["revokedTs"], record["pid"]))
    return evaluate(result)


@app.get("/revoked/{pid}")
def is_revoked(pid: str, x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    valid_pid(pid)
    with state.lock:
        result = pid in state.revocations
    return {"ok": True, "queryMs": 0, "result": {"revoked": result}}


@app.post("/traces")
async def request_trace(request: Request,
                        x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity)
    name = require_role(identity, "TA", "RSU")
    body = await json_body(request)
    req_id = valid_req_id(body.get("reqId"))
    pid = valid_pid(body.get("pid"))
    reason = free_text(body.get("reason"), "reason")
    with state.lock:
        if pid not in state.revocations:
            error(409, "ERR_CONFLICT", "pseudonym must be revoked before trace request")
        if req_id in state.traces:
            error(409, "ERR_CONFLICT", f'trace request "{req_id}" already exists')
        result = new_trace(req_id, pid, reason, name)
        state.traces[req_id] = result
    return write(name, "RequestTrace", result)


@app.get("/traces")
def list_traces(_status: str | None = None,
                x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    error(501, "NOT_DEPLOYED")


@app.get("/traces/{req_id}")
def get_trace(req_id: str, x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    valid_req_id(req_id)
    with state.lock:
        trace = state.traces.get(req_id)
    if trace is None:
        error(404, "ERR_NOT_FOUND", f'trace request "{req_id}" was not found')
    return evaluate(trace)


@app.post("/traces/{req_id}/approve")
def approve_trace(req_id: str,
                  x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity)
    name = require_role(identity, "RSU")
    valid_req_id(req_id)
    with state.lock:
        trace = state.traces.get(req_id)
        if trace is None:
            error(404, "ERR_NOT_FOUND", f'trace request "{req_id}" was not found')
        if trace["status"] != "PENDING":
            error(409, "ERR_CONFLICT", "trace request is not pending")
        if name in trace["approvals"]:
            error(409, "ERR_CONFLICT", f'RSU "{name}" has already approved this trace')
        trace["approvals"].append(name)
        if len(trace["approvals"]) >= trace["threshold"]:
            trace["status"] = "APPROVED"
            trace["approvedTs"] = now_ms()
        result = dict(trace)
    return write(name, "ApproveTrace", result)


@app.post("/traces/{req_id}/shares")
def record_share_release(req_id: str,
                         x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity)
    require_role(identity, "RSU")
    valid_req_id(req_id)
    error(501, "NOT_DEPLOYED")


@app.post("/traces/{req_id}/revoke")
async def revoke_trace(req_id: str, request: Request,
                       x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity, "ta1")
    name = require_role(identity, "TA")
    valid_req_id(req_id)
    body = await json_body(request)
    pids = body.get("pids")
    if not isinstance(pids, list) or not 1 <= len(pids) <= 200:
        error(400, "ERR_BAD_INPUT", "pids must be an array containing between 1 and 200 pseudonyms")
    for index, pid in enumerate(pids):
        valid_pid(pid, f"pids[{index}]")
    reason = free_text(body.get("reason"), "reason")
    unique_pids = list(dict.fromkeys(pids))
    with state.lock:
        trace = state.traces.get(req_id)
        if trace is None:
            error(404, "ERR_NOT_FOUND", f'trace request "{req_id}" was not found')
        if trace["status"] != "APPROVED":
            error(409, "ERR_CONFLICT", "trace request must be approved before revocation")
        if trace["pid"] not in pids:
            error(400, "ERR_BAD_INPUT", "pids must include the traced pid")
        current = now_ms()
        for pid in unique_pids:
            if pid not in state.revocations:
                state.revocations[pid] = revoked_record(pid, reason, [], 0, current, "TRACE", req_id)
        trace["status"] = "EXECUTED"
        trace["revokedPids"] = unique_pids
        trace["executedTs"] = current
        result = dict(trace)
    return write(name, "Revoke", result)


@app.get("/snapshot")
def snapshot(since: str | None = None,
             x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    threshold = since_value(since)
    current = now_ms()
    with state.lock:
        revoked = [record for record in state.revocations.values() if record["revokedTs"] >= threshold]
        auths = [record for pid, record in state.auths.items()
                 if record["ts"] >= threshold and record["expiry"] > current and pid not in state.revocations]
        result = {
            "serverTimeMs": current,
            "since": threshold,
            "revoked": sorted(revoked, key=lambda item: (item["revokedTs"], item["pid"])),
            "auths": sorted(auths, key=lambda item: (item["ts"], item["pid"])),
            "policies": [state.policies[key] for key in sorted(state.policies)],
            "roots": [state.roots[key] for key in sorted(state.roots) if state.roots[key]["validUntil"] > current],
            "config": dict(state.config),
        }
    return evaluate(result)


@app.get("/events/stream")
def event_stream(x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    error(501, "NOT_DEPLOYED")


@app.get("/stats")
def get_stats(x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    error(501, "NOT_DEPLOYED")


@app.get("/chain")
def chain_info(x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    with state.lock:
        height = state.block_number
    current_hash = hashlib.sha256(f"mock-block-{height}".encode()).hexdigest()
    return {"ok": True, "queryMs": 0, "height": height, "currentHash": current_hash}


@app.get("/activity")
def activity(limit: str | None = None,
            x_identity: str | None = Header(default=None, alias="X-Identity")):
    get_identity(x_identity)
    count = 50
    if limit is not None:
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)", limit):
            error(400, "ERR_BAD_INPUT", "limit must be a non-negative integer")
        count = int(limit)
        if count < 1 or count > 200:
            error(400, "ERR_BAD_INPUT", "limit must be between 1 and 200")
    with state.lock:
        result = list(reversed(state.activity[-count:]))
    return evaluate(result)


@app.get("/admin/dump")
def dump_state(x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity, "ta1")
    require_role(identity, "TA")
    error(501, "NOT_DEPLOYED")


@app.post("/admin/reset")
def reset_state(x_identity: str | None = Header(default=None, alias="X-Identity")):
    identity = get_identity(x_identity, "ta1")
    require_role(identity, "TA")
    error(501, "NOT_DEPLOYED")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def route_not_found(path: str):
    del path
    error(404, "ERR_NOT_FOUND", "Route not found")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "3000")),
    )
