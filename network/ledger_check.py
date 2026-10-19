"""Conformance check for Person 2's ledger (ledger/gateway/README.md).

Runs every call the scenario makes, in the order a run makes them, and checks
the answers have the shape the scenario reads. Run it against the gateway
before an integrated run:

    python -m network.ledger_check http://localhost:3000
    python -m network.ledger_check mock          # ledger/mock_ledger.py (or the built-in stand-in)
    python -m network.ledger_check builtin       # the built-in stand-in (reference behaviour)

Uses fresh ids on every run (a random suffix), so it can run against a ledger
that already holds data. It writes test records; use a test channel.
"""

from __future__ import annotations

import argparse
import secrets
import sys
import time

from network.ledger_client import AccessDenied, LedgerError, make_client

RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, what: str) -> bool:
    RESULTS.append((bool(ok), what))
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    return bool(ok)


def write(client, caller: str, fn: str, **args) -> dict:
    t0 = time.perf_counter()
    try:
        res = client.call(caller, fn, **args)
    except LedgerError as e:
        check(False, f"{caller} {fn}: {e}")
        return {}
    ms = (time.perf_counter() - t0) * 1000
    check(isinstance(res, dict) and "txId" in res and isinstance(res.get("commitMs"), (int, float)),
          f"{caller} {fn} -> txId + numeric commitMs (commitMs {float(res.get('commitMs') or 0):.0f}, call {ms:.0f} ms)")
    return res if isinstance(res, dict) else {}


def denied(client, caller: str, fn: str, **args) -> None:
    try:
        client.call(caller, fn, **args)
        check(False, f"{caller} may not call {fn}, but the ledger accepted it")
    except AccessDenied:
        check(True, f"{caller} {fn} denied (HTTP 401/403)")
    except LedgerError as e:
        check(False, f"{caller} {fn} should be denied with HTTP 401/403, got: {e}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ledger", help="gateway URL, 'mock' or 'builtin'")
    ap.add_argument("--identity-header", default="X-Identity")
    ap.add_argument("--rsus", type=int, default=9, help="RSU identities rsu0..rsuN-1 known to the ledger")
    ap.add_argument("--trace-threshold", type=int, default=None, help="default 2f+1, f = (N-1)//3")
    a = ap.parse_args(argv)
    threshold = a.trace_threshold or 2 * ((a.rsus - 1) // 3) + 1
    client = make_client(a.ledger, report_k=2, trace_threshold=threshold, identity_header=a.identity_header)
    tag = secrets.token_hex(3)
    epoch = int(time.time()) % 1_000_000
    rsus = [f"rsu{i}" for i in range(a.rsus)]
    pid_a, pid_b, pid_c = (secrets.token_hex(8) for _ in range(3))
    print(f"ledger {a.ledger}, RSUs {rsus[0]}..{rsus[-1]}, trace threshold {threshold}, run {tag}")

    print("setup by the TA (before t = 0)")
    write(client, "TA", "register_root", epoch=epoch, merkle_root=secrets.token_hex(32), valid_until=1e9)
    write(client, "TA", "set_policy", service=f"road_access_{tag}", classes=["car", "truck", "emergency"])

    print("authorization record (an RSU, after a ZKP authentication)")
    write(client, rsus[0], "record_auth", pid_hash=pid_a, service=f"road_access_{tag}", cls="car", expiry=42.5)
    rec = client.call(rsus[1], "get_auth", pid_hash=pid_a)
    auth = rec.get("auth", rec) if isinstance(rec, dict) else None
    check(isinstance(auth, dict) and auth.get("class") == "car" and float(auth.get("expiry", -1)) == 42.5,
          "get_auth -> {auth: {pidHash, service, class, expiry}}, expiry kept as given (simulated seconds)")

    print("misbehaviour reports: K = 2 different RSUs revoke")
    r1 = write(client, rsus[0], "report_misbehaviour", pid=pid_b, evidence_hash=secrets.token_hex(32))
    check(not r1.get("revoked", False), "one report does not revoke")
    write(client, rsus[0], "report_misbehaviour", pid=pid_b, evidence_hash=secrets.token_hex(32))
    check(not client.call("TA", "is_revoked", pid=pid_b).get("revoked"),
          "a second report by the same RSU does not revoke")
    r2 = write(client, rsus[1], "report_misbehaviour", pid=pid_b, evidence_hash=secrets.token_hex(32))
    check(r2.get("revoked") is True or "revoked" not in r2,
          "report answer has revoked=true after the K-th RSU (or no 'revoked' field)")
    check(client.call(rsus[2], "is_revoked", pid=pid_b).get("revoked") is True, "is_revoked -> {revoked: true}")
    check(client.call(rsus[2], "is_revoked", pid=pid_c).get("revoked") in (False, None),
          "is_revoked of an unknown pid -> {revoked: false} (or HTTP 404)")

    print("revocation list for the RSU sync")
    first = client.call(rsus[0], "get_revoked_since", since=0)
    ok = isinstance(first.get("revoked"), list) and isinstance(first.get("cursor"), int)
    check(ok, "get_revoked_since(0) -> {revoked: [pid, ...], cursor: int}")
    if ok:
        check(pid_b in first["revoked"], "the revoked pid is in the list")
        again = client.call(rsus[0], "get_revoked_since", since=first["cursor"])
        check(pid_b not in again.get("revoked", []), "since=cursor returns only newer revocations")

    print(f"conditional traceability: {threshold} different RSUs approve")
    req = f"trace-{tag}"
    write(client, rsus[0], "request_trace", req_id=req, pid=pid_b, reason="misbehaviour")
    for i, rsu in enumerate(rsus[:threshold]):
        res = write(client, rsu, "approve_trace", req_id=req)
        if i == 0:
            write_again = client.call(rsu, "approve_trace", req_id=req)
            check(int(write_again.get("approvals", 1)) == 1, "the same RSU approving twice counts once")
        tr = client.call("TA", "get_trace", req_id=req).get("trace")
        shape = isinstance(tr, dict) and isinstance(tr.get("approvals"), list) and "approved" in tr
        if not check(shape, f"get_trace -> {{trace: {{pid, approvals: [...], approved}}}} after {i + 1}"):
            break
        check(tr["approved"] is (i + 1 >= threshold), f"approved={i + 1 >= threshold} after {i + 1} approvals")
    try:
        client.call(rsus[1], "request_trace", req_id=req, pid=pid_b, reason="again")
        check(False, "a second request_trace with the same req_id must fail")
    except LedgerError:
        check(True, "a second request_trace with the same req_id fails")
    check(client.call("TA", "get_trace", req_id=f"none-{tag}").get("trace") is None,
          "get_trace of an unknown id -> {trace: null} (or HTTP 404)")

    print("TA revokes all pseudonyms of the revealed vehicle")
    write(client, "TA", "revoke", pids=[pid_b, pid_a, pid_c], reason=f"trace {req}")   # must include the traced pid
    check(client.call(rsus[3], "is_revoked", pid=pid_c).get("revoked") is True, "revoke -> pids revoked")

    print("access control (caller identity in the header)")
    denied(client, rsus[0], "register_root", epoch=epoch + 1, merkle_root="00" * 32, valid_until=1e9)
    denied(client, rsus[0], "revoke", pids=[pid_c], reason="not allowed")
    denied(client, "TA", "record_auth", pid_hash=pid_c, service="x", cls="car", expiry=1.0)
    denied(client, "TA", "approve_trace", req_id=req)

    failed = [w for ok, w in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
