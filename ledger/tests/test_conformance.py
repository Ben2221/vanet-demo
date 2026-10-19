import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

LEDGER = os.environ.get("LEDGER", "").lower()
BASE_URL = os.environ.get(
    "LEDGER_URL", os.environ.get("GATEWAY_URL", "http://127.0.0.1:3000")
).rstrip("/")


@pytest.fixture(scope="session", autouse=True)
def require_gateway_backend():
    if LEDGER not in {"gateway", "mock"}:
        pytest.skip("Set LEDGER=gateway or LEDGER=mock to select a conformance backend")


@pytest.fixture(scope="session")
def stage_b_policy(require_gateway_backend):
    service = f"stage-b-{uuid.uuid4().hex[:12]}"
    status, body = request(
        "PUT",
        f"/policies/{service}",
        identity="ta1",
        payload={"classes": ["private", "commercial"]},
    )
    assert status == 200
    assert body["txId"]
    assert isinstance(body["commitMs"], (int, float))
    wait_for_cross_peer_commit()
    return service


@pytest.fixture(scope="session")
def stage_c_environment(stage_b_policy):
    status, before = request("GET", "/config", identity="ta1")
    assert status == 200
    original = before["result"]
    required = {**original, "K": 2, "traceThreshold": 3}
    changed = required != original
    if changed:
        status, written = request("PUT", "/config", identity="ta1", payload=required)
        assert status == 200
        assert written["txId"]
        wait_for_cross_peer_commit()
    yield stage_b_policy
    if changed:
        status, restored = request("PUT", "/config", identity="ta1", payload=original)
        assert status == 200
        assert restored["txId"]


def wait_for_cross_peer_commit():
    time.sleep(0.6)


def request(method, path, identity=None, payload=None):
    headers = {}
    data = None
    if identity:
        headers["X-Identity"] = identity
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        f"{BASE_URL}{path}", data=data, headers=headers, method=method
    )
    try:
        response = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read().decode("utf-8"))


def random_hash():
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()


def create_revoked_pid(pid=None):
    pid = pid or random_hash()
    payload = {"pid": pid, "evidenceHash": random_hash(), "attackType": "sybil"}
    for identity in ("rsu1", "rsu2"):
        status, body = request("POST", "/reports", identity=identity, payload=payload)
        assert status == 200
        assert body["txId"]
        assert isinstance(body["commitMs"], (int, float))
        wait_for_cross_peer_commit()
        payload["evidenceHash"] = random_hash()
    return pid


def request_trace(pid, req_id=None, identity="rsu1"):
    req_id = req_id or f"trace-{uuid.uuid4().hex}"
    status, body = request(
        "POST",
        "/traces",
        identity=identity,
        payload={"reqId": req_id, "pid": pid, "reason": "conformance trace"},
    )
    return req_id, status, body


def approve_trace(req_id, identity):
    return request("POST", f"/traces/{req_id}/approve", identity=identity, payload={})


def test_health_and_whoami_use_selected_identity():
    status, health = request("GET", "/health", identity="rsu2")
    assert status == 200
    assert health == {"gateway": "up", "chaincode": "ok", "identity": "rsu2"}

    status, whoami = request("GET", "/whoami", identity="rsu2")
    assert status == 200
    assert whoami["result"] == {"msp": "Org2MSP", "role": "RSU", "id": "rsu2"}


def test_unknown_identity_is_rejected():
    status, body = request("GET", "/whoami", identity="not-configured")
    assert status == 400
    assert body["error"]["code"] == "ERR_BAD_INPUT"


def test_config_can_be_read_and_set_by_ta():
    status, initial = request("GET", "/config", identity="ta1")
    assert status == 200
    assert initial["result"] == {
        "K": 2,
        "traceThreshold": 3,
        "maxAuthTtlSec": 3600,
        "demoMode": True,
    }

    status, written = request(
        "PUT",
        "/config",
        identity="ta1",
        payload={"K": 2, "traceThreshold": 3, "maxAuthTtlSec": 3600, "demoMode": True},
    )
    assert status == 200
    assert written["txId"]
    assert isinstance(written["commitMs"], (int, float))
    wait_for_cross_peer_commit()

    status, current = request("GET", "/config", identity="rsu1")
    assert status == 200
    assert current["result"] == initial["result"]


def test_rsu_cannot_set_policy():
    status, body = request(
        "PUT", "/policies/conformance", identity="rsu1", payload={"classes": ["private"]}
    )
    assert status == 403
    assert body["error"]["code"] == "ERR_FORBIDDEN"


def test_policy_set_get_and_list():
    service = f"test-{uuid.uuid4().hex[:12]}"
    status, written = request(
        "PUT",
        f"/policies/{service}",
        identity="ta1",
        payload={"classes": ["private", "commercial", "private"]},
    )
    assert status == 200
    assert written["result"]["classes"] == ["private", "commercial"]
    wait_for_cross_peer_commit()

    status, fetched = request("GET", f"/policies/{service}", identity="rsu1")
    assert status == 200
    assert fetched["result"] == written["result"]

    status, listed = request("GET", "/policies", identity="rsu1")
    assert status == 200
    assert any(policy["service"] == service for policy in listed["result"])


def test_root_register_read_and_duplicate_conflict():
    epoch = time.time_ns() % 9_000_000_000
    root = random_hash()
    payload = {
        "epoch": epoch,
        "merkleRoot": root,
        "validUntil": int(time.time() * 1000) + 3_600_000,
    }

    status, written = request("POST", "/roots", identity="ta1", payload=payload)
    assert status == 200
    assert written["result"]["merkleRoot"] == root
    assert written["txId"]
    assert isinstance(written["commitMs"], (int, float))
    wait_for_cross_peer_commit()

    status, fetched = request("GET", f"/roots/{epoch}", identity="rsu1")
    assert status == 200
    assert fetched["result"] == written["result"]

    status, listed = request("GET", "/roots", identity="rsu1")
    assert status == 200
    assert any(item["epoch"] == epoch for item in listed["result"])

    status, conflict = request("POST", "/roots", identity="ta1", payload=payload)
    assert status == 409
    assert conflict["error"]["code"] == "ERR_CONFLICT"


def test_ta_cannot_submit_report():
    status, body = request("POST", "/reports", identity="ta1", payload={})
    assert status == 403
    assert body["error"]["code"] == "ERR_FORBIDDEN"


def test_malformed_pid_is_rejected_by_gateway_validator():
    status, body = request(
        "POST",
        "/auth-records",
        identity="rsu1",
        payload={
            "pid": "ABC",
            "service": "toll",
            "class": "private",
            "expiry": int(time.time() * 1000) + 60_000,
        },
    )
    assert status == 400
    assert body["error"]["code"] == "ERR_BAD_INPUT"


def test_report_endpoint_deduplicates_same_rsu_report():
    pid = random_hash()
    payload = {"pid": pid, "evidenceHash": random_hash(), "attackType": "sybil"}

    status, first = request("POST", "/reports", identity="rsu1", payload=payload)
    assert status == 200
    assert first["result"]["reportCount"] == 1
    assert first["result"]["revoked"] is False
    assert first["txId"]
    assert isinstance(first["commitMs"], (int, float))

    status, duplicate = request(
        "POST",
        "/reports",
        identity="rsu1",
        payload={**payload, "evidenceHash": random_hash()},
    )
    assert status == 200
    assert duplicate["result"]["duplicate"] is True
    assert duplicate["result"]["reportCount"] == 1
    assert duplicate["txId"]
    assert isinstance(duplicate["commitMs"], (int, float))
    wait_for_cross_peer_commit()

    status, revoked = request("GET", f"/revoked/{pid}", identity="rsu2")
    assert status == 200
    assert revoked["result"]["revoked"] is False


def test_skipped_trace_functions_map_to_501():
    status, body = request("GET", "/traces?status=PENDING", identity="rsu1")
    assert status == 501
    assert body == {"ok": False, "error": {"code": "NOT_DEPLOYED"}}

    status, body = request(
        "POST", f"/traces/trace-{uuid.uuid4().hex[:12]}/shares", identity="rsu1"
    )
    assert status == 501
    assert body == {"ok": False, "error": {"code": "NOT_DEPLOYED"}}

    status, body = request("GET", "/events/stream", identity="rsu1")
    assert status == 501
    assert body == {"ok": False, "error": {"code": "NOT_DEPLOYED"}}


def test_record_auth_rejects_disallowed_class(stage_b_policy):
    status, body = request(
        "POST",
        "/auth-records",
        identity="rsu1",
        payload={
            "pid": random_hash(),
            "service": stage_b_policy,
            "class": "emergency",
            "expiry": int(time.time() * 1000) + 600_000,
        },
    )
    assert status == 403
    assert body["error"]["code"] == "ERR_FORBIDDEN"


def test_record_auth_rejects_unknown_service(stage_b_policy):
    status, body = request(
        "POST",
        "/auth-records",
        identity="rsu1",
        payload={
            "pid": random_hash(),
            "service": f"unknown-{uuid.uuid4().hex[:12]}",
            "class": "private",
            "expiry": int(time.time() * 1000) + 600_000,
        },
    )
    assert status == 404
    assert body["error"]["code"] == "ERR_NOT_FOUND"


def test_record_auth_repeated_pid_preserves_first_timestamp(stage_b_policy):
    pid = random_hash()
    payload = {
        "pid": pid,
        "service": stage_b_policy,
        "class": "private",
        "expiry": int(time.time() * 1000) + 600_000,
    }
    status, first = request("POST", "/auth-records", identity="rsu1", payload=payload)
    assert status == 200
    assert first["txId"]
    assert isinstance(first["commitMs"], (int, float))
    wait_for_cross_peer_commit()
    status, fetched = request("GET", f"/auth-records/{pid}", identity="ta1")
    assert status == 200
    assert fetched["result"]["pid"] == pid

    status, second = request("POST", "/auth-records", identity="rsu2", payload=payload)
    assert status == 200
    assert second["result"]["sessionCount"] == 2
    assert second["result"]["firstTs"] == first["result"]["firstTs"]
    assert second["result"]["rsuId"] == "rsu2"
    assert second["txId"]
    assert isinstance(second["commitMs"], (int, float))
    wait_for_cross_peer_commit()

    status, listed = request("GET", "/auth-records?since=0", identity="ta1")
    assert status == 200
    assert isinstance(listed["result"], list)
    assert any(record["pid"] == pid for record in listed["result"])


def test_get_auth_after_expiry_returns_not_found(stage_b_policy):
    pid = random_hash()
    status, written = request(
        "POST",
        "/auth-records",
        identity="rsu1",
        payload={
            "pid": pid,
            "service": stage_b_policy,
            "class": "private",
            "expiry": int(time.time() * 1000) + 5_000,
        },
    )
    assert status == 200
    assert written["txId"]
    assert isinstance(written["commitMs"], (int, float))
    time.sleep(5.5)

    status, body = request("GET", f"/auth-records/{pid}", identity="ta1")
    assert status == 404
    assert body["error"]["code"] == "ERR_NOT_FOUND"


def test_two_distinct_rsus_revoke_and_block_auth(stage_b_policy):
    pid = random_hash()
    auth_payload = {
        "pid": pid,
        "service": stage_b_policy,
        "class": "private",
        "expiry": int(time.time() * 1000) + 600_000,
    }
    status, auth = request("POST", "/auth-records", identity="rsu1", payload=auth_payload)
    assert status == 200
    assert auth["txId"]
    assert isinstance(auth["commitMs"], (int, float))
    wait_for_cross_peer_commit()

    report_payload = {"pid": pid, "evidenceHash": random_hash(), "attackType": "sybil"}
    status, first = request("POST", "/reports", identity="rsu1", payload=report_payload)
    assert status == 200
    assert first["result"]["reportCount"] == 1
    assert first["result"]["newlyRevoked"] is False
    wait_for_cross_peer_commit()

    status, second = request(
        "POST",
        "/reports",
        identity="rsu2",
        payload={**report_payload, "evidenceHash": random_hash()},
    )
    assert status == 200
    assert second["result"]["newlyRevoked"] is True
    assert second["result"]["revoked"] is True
    assert second["txId"]
    assert isinstance(second["commitMs"], (int, float))
    wait_for_cross_peer_commit()

    status, status_body = request("GET", f"/pseudonyms/{pid}", identity="rsu1")
    assert status == 200
    assert status_body["result"]["revoked"] is True
    assert status_body["result"]["reportCount"] == 2
    assert set(status_body["result"]["reporters"]) == {"rsu1", "rsu2"}
    assert status_body["result"]["firstReportTs"] > 0
    assert status_body["result"]["revokedTs"] >= status_body["result"]["firstReportTs"]

    status, blocked = request("POST", "/auth-records", identity="rsu2", payload=auth_payload)
    assert status == 409
    assert blocked["error"]["code"] == "ERR_CONFLICT"

    wait_for_cross_peer_commit()
    status, missing = request("GET", f"/auth-records/{pid}", identity="rsu1")
    assert status == 404
    assert missing["error"]["code"] == "ERR_NOT_FOUND"

    wait_for_cross_peer_commit()
    status, access = request(
        "GET",
        f"/access-check?pid={pid}&class=private&service={stage_b_policy}",
        identity="ta1",
    )
    assert status == 200
    assert access["result"]["allow"] is False
    assert "REVOKED" in access["result"]["reasons"]

    wait_for_cross_peer_commit()
    status, revoked = request("GET", "/revoked?since=0", identity="rsu2")
    assert status == 200
    assert isinstance(revoked["result"], list)
    assert any(item["pid"] == pid for item in revoked["result"])


@pytest.mark.skipif(LEDGER == "mock", reason="Mock backend does not simulate Fabric MVCC retries")
def test_concurrent_reports_retry_and_revoke(stage_b_policy):
    pid = random_hash()
    barrier = threading.Barrier(2)

    def report(identity):
        barrier.wait(timeout=15)
        return request(
            "POST",
            "/reports",
            identity=identity,
            payload={"pid": pid, "evidenceHash": random_hash(), "attackType": "sybil"},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(report, identity) for identity in ("rsu1", "rsu2")]
        responses = [future.result(timeout=90) for future in futures]

    assert all(status == 200 for status, _ in responses)
    assert all(body["txId"] for _, body in responses)
    assert all(isinstance(body["commitMs"], (int, float)) for _, body in responses)
    assert max(body["retries"] for _, body in responses) >= 1

    wait_for_cross_peer_commit()
    status, body = request("GET", f"/revoked/{pid}", identity="ta1")
    assert status == 200
    assert body["result"]["revoked"] is True
def test_auth_write_has_transaction_and_activity_timing(stage_b_policy):
    payload = {
        "pid": random_hash(),
        "service": stage_b_policy,
        "class": "private",
        "expiry": int(time.time() * 1000) + 600_000,
    }
    status, body = request("POST", "/auth-records", identity="rsu1", payload=payload)
    assert status == 200
    assert isinstance(body["txId"], str) and body["txId"]
    assert isinstance(body["commitMs"], (int, float))
    assert body["commitMs"] >= 0

    status, activity = request("GET", "/activity?limit=200", identity="rsu1")
    assert status == 200
    entry = next(item for item in activity["result"] if item["txId"] == body["txId"])
    assert entry["fn"] == "RecordAuth"
    assert entry["commitMs"] == body["commitMs"]


def test_chain_info_is_readable():
    status, body = request("GET", "/chain", identity="rsu1")
    assert status == 200
    assert isinstance(body["height"], int)
    assert body["height"] > 0
    assert len(body["currentHash"]) == 64


def test_trace_request_requires_revocation_and_has_fixed_shape(stage_c_environment):
    pid = random_hash()
    req_id = f"trace-{uuid.uuid4().hex}"
    status, body = request(
        "POST", "/traces", identity="rsu1",
        payload={"reqId": req_id, "pid": pid, "reason": "not revoked"},
    )
    assert status == 409
    assert body["error"]["code"] == "ERR_CONFLICT"

    status, missing = request("GET", f"/traces/{req_id}", identity="ta1")
    assert status == 404
    assert missing["error"]["code"] == "ERR_NOT_FOUND"

    pid = create_revoked_pid()
    req_id, status, created = request_trace(pid)
    assert status == 200
    assert created["txId"]
    assert isinstance(created["commitMs"], (int, float))
    assert created["result"]["status"] == "PENDING"
    assert created["result"]["threshold"] == 3
    assert created["result"]["approvals"] == []
    assert created["result"]["revokedPids"] == []
    assert created["result"]["approvedTs"] == 0
    assert created["result"]["executedTs"] == 0
    wait_for_cross_peer_commit()
    status, fetched = request("GET", f"/traces/{req_id}", identity="ta1")
    assert status == 200
    assert fetched["result"] == created["result"]


def test_trace_approvals_require_three_distinct_rsus(stage_c_environment):
    pid = create_revoked_pid()
    req_id, status, _ = request_trace(pid)
    assert status == 200

    status, first = approve_trace(req_id, "rsu1")
    assert status == 200
    assert first["result"]["status"] == "PENDING"
    status, duplicate = approve_trace(req_id, "rsu1")
    assert status == 409
    assert duplicate["error"]["code"] == "ERR_CONFLICT"

    status, second = approve_trace(req_id, "rsu2")
    assert status == 200
    assert second["result"]["status"] == "PENDING"
    wait_for_cross_peer_commit()
    status, pending = request("GET", f"/traces/{req_id}", identity="ta1")
    assert status == 200
    assert pending["result"]["status"] == "PENDING"
    assert len(pending["result"]["approvals"]) == 2

    status, third = approve_trace(req_id, "rsu3")
    assert status == 200
    assert third["result"]["status"] == "APPROVED"
    assert third["result"]["approvedTs"] > 0
    assert len(third["result"]["approvals"]) == 3


def test_revoke_pending_trace_returns_conflict(stage_c_environment):
    pid = create_revoked_pid()
    req_id, status, _ = request_trace(pid)
    assert status == 200
    status, body = request(
        "POST", f"/traces/{req_id}/revoke", identity="ta1",
        payload={"pids": [pid], "reason": "pending trace"},
    )
    assert status == 409
    assert body["error"]["code"] == "ERR_CONFLICT"


def test_revoke_requires_the_traced_pid(stage_c_environment):
    pid = create_revoked_pid()
    req_id, status, _ = request_trace(pid)
    assert status == 200
    for identity in ("rsu1", "rsu2", "rsu3"):
        status, _ = approve_trace(req_id, identity)
        assert status == 200
    status, body = request(
        "POST", f"/traces/{req_id}/revoke", identity="ta1",
        payload={"pids": [random_hash()], "reason": "missing traced pid"},
    )
    assert status == 400
    assert body["error"]["code"] == "ERR_BAD_INPUT"


def test_rsu_cannot_revoke_an_approved_trace(stage_c_environment):
    pid = create_revoked_pid()
    req_id, status, _ = request_trace(pid)
    assert status == 200
    for identity in ("rsu1", "rsu2", "rsu3"):
        status, _ = approve_trace(req_id, identity)
        assert status == 200
    status, body = request(
        "POST", f"/traces/{req_id}/revoke", identity="rsu1",
        payload={"pids": [pid], "reason": "wrong caller"},
    )
    assert status == 403
    assert body["error"]["code"] == "ERR_FORBIDDEN"


def test_approved_trace_revokes_five_pids_once(stage_c_environment):
    traced_pid = create_revoked_pid()
    pids = [traced_pid, random_hash(), random_hash(), random_hash(), random_hash()]
    req_id, status, _ = request_trace(traced_pid)
    assert status == 200
    for identity in ("rsu1", "rsu2", "rsu3"):
        status, body = approve_trace(req_id, identity)
        assert status == 200
        assert body["txId"]
        assert isinstance(body["commitMs"], (int, float))

    wait_for_cross_peer_commit()
    status, executed = request(
        "POST", f"/traces/{req_id}/revoke", identity="ta1",
        payload={"pids": pids, "reason": "approved trace execution"},
    )
    assert status == 200
    assert executed["txId"]
    assert isinstance(executed["commitMs"], (int, float))
    assert executed["result"]["status"] == "EXECUTED"
    assert executed["result"]["revokedPids"] == pids
    assert executed["result"]["executedTs"] > 0
    wait_for_cross_peer_commit()

    for pid in pids:
        status, result = request("GET", f"/revoked/{pid}", identity="rsu1")
        assert status == 200
        assert result["result"]["revoked"] is True

    status, second = request(
        "POST", f"/traces/{req_id}/revoke", identity="ta1",
        payload={"pids": pids, "reason": "second execution"},
    )
    assert status == 409
    assert second["error"]["code"] == "ERR_CONFLICT"


def test_trace_rejects_invalid_and_oversized_pid_lists(stage_c_environment):
    traced_pid = create_revoked_pid()
    req_id, status, _ = request_trace(traced_pid)
    assert status == 200
    for identity in ("rsu1", "rsu2", "rsu3"):
        status, _ = approve_trace(req_id, identity)
        assert status == 200

    for pids in (["BAD", traced_pid], [traced_pid] + [random_hash() for _ in range(200)]):
        status, body = request(
            "POST", f"/traces/{req_id}/revoke", identity="ta1",
            payload={"pids": pids, "reason": "invalid list"},
        )
        assert status == 400
        assert body["error"]["code"] == "ERR_BAD_INPUT"


def test_concurrent_trace_approvals_keep_all_rsus(stage_c_environment):
    traced_pid = create_revoked_pid()
    req_id, status, _ = request_trace(traced_pid)
    assert status == 200
    barrier = threading.Barrier(3)

    def approve(identity):
        barrier.wait(timeout=15)
        return approve_trace(req_id, identity)

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(approve, identity) for identity in ("rsu1", "rsu2", "rsu3")]
        responses = [future.result(timeout=90) for future in futures]

    assert all(status == 200 for status, _ in responses)
    assert all(body["txId"] for _, body in responses)
    assert all(isinstance(body["commitMs"], (int, float)) for _, body in responses)
    wait_for_cross_peer_commit()
    status, final = request("GET", f"/traces/{req_id}", identity="ta1")
    assert status == 200
    assert final["result"]["status"] == "APPROVED"
    assert set(final["result"]["approvals"]) == {"rsu1", "rsu2", "rsu3"}
    assert len(final["result"]["approvals"]) == 3


def test_snapshot_full_and_incremental_lists(stage_c_environment):
    service = stage_c_environment
    auth_pid = random_hash()
    revoked_pid = random_hash()
    status, auth = request(
        "POST", "/auth-records", identity="rsu1",
        payload={
            "pid": auth_pid,
            "service": service,
            "class": "private",
            "expiry": int(time.time() * 1000) + 600_000,
        },
    )
    assert status == 200
    assert auth["txId"]
    assert isinstance(auth["commitMs"], (int, float))
    create_revoked_pid(revoked_pid)
    wait_for_cross_peer_commit()

    status, full = request("GET", "/snapshot?since=0", identity="rsu1")
    assert status == 200
    result = full["result"]
    assert {"serverTimeMs", "since", "revoked", "auths", "policies", "roots", "config"} <= set(result)
    assert result["since"] == 0
    assert isinstance(result["serverTimeMs"], int)
    assert all(isinstance(result[field], list) for field in ("revoked", "auths", "policies", "roots"))
    assert isinstance(result["config"], dict)
    assert any(record["pid"] == auth_pid for record in result["auths"])
    assert any(record["pid"] == revoked_pid for record in result["revoked"])

    since = int(time.time() * 1000) - 120_000
    status, incremental = request("GET", f"/snapshot?since={since}", identity="rsu1")
    assert status == 200
    delta = incremental["result"]
    assert any(record["pid"] == auth_pid for record in delta["auths"])
    assert any(record["pid"] == revoked_pid for record in delta["revoked"])
    assert all(record["ts"] >= since for record in delta["auths"])
    assert all(record["revokedTs"] >= since for record in delta["revoked"])

    future = int(time.time() * 1000) + 600_000
    status, empty_delta = request("GET", f"/snapshot?since={future}", identity="rsu1")
    assert status == 200
    assert empty_delta["result"]["revoked"] == []
    assert empty_delta["result"]["auths"] == []
