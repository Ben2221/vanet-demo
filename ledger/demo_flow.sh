#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${GATEWAY_URL:-http://127.0.0.1:3000}"
VISIBILITY_WAIT_SECONDS="${VISIBILITY_WAIT_SECONDS:-0.6}"
service="demo-$(openssl rand -hex 4)"
pid="$(openssl rand -hex 32)"
pid2="$(openssl rand -hex 32)"
pid3="$(openssl rand -hex 32)"
pid4="$(openssl rand -hex 32)"
pid5="$(openssl rand -hex 32)"
root="$(openssl rand -hex 32)"
evidence1="$(openssl rand -hex 32)"
evidence2="$(openssl rand -hex 32)"
now_ms="$(date +%s%3N)"
epoch="$(date +%s)"
valid_until="$((now_ms + 3600000))"
expiry="$((now_ms + 600000))"
req_id="trace-$(openssl rand -hex 8)"

show() {
  printf '\n$ curl -sS -i'
  printf ' %q' "$@"
  printf '\n'
  curl -sS -i "$@"
  printf '\n\n'
}

printf '\n=== Prepare demo policy and trace threshold ===\n'
show -X PUT "$BASE_URL/config" \
  -H 'Content-Type: application/json' -H 'X-Identity: ta1' \
  -d '{"K":2,"traceThreshold":3,"maxAuthTtlSec":3600,"demoMode":true}'
sleep "$VISIBILITY_WAIT_SECONDS"
show -X PUT "$BASE_URL/policies/$service" \
  -H 'Content-Type: application/json' -H 'X-Identity: ta1' \
  -d '{"classes":["private","commercial"]}'
sleep "$VISIBILITY_WAIT_SECONDS"

printf '\n=== Demo step 2: register a vehicle root ===\n'
show -X POST "$BASE_URL/roots" \
  -H 'Content-Type: application/json' -H 'X-Identity: ta1' \
  -d "{\"epoch\":$epoch,\"merkleRoot\":\"$root\",\"validUntil\":$valid_until}"
sleep "$VISIBILITY_WAIT_SECONDS"
show -H 'X-Identity: rsu1' "$BASE_URL/roots/$epoch"
show -H 'X-Identity: rsu1' "$BASE_URL/activity?limit=10"

printf '\n=== Demo step 4: authentication and handover ===\n'
show -X POST "$BASE_URL/auth-records" \
  -H 'Content-Type: application/json' -H 'X-Identity: rsu1' \
  -d "{\"pid\":\"$pid\",\"service\":\"$service\",\"class\":\"private\",\"expiry\":$expiry}"
sleep "$VISIBILITY_WAIT_SECONDS"
show -H 'X-Identity: rsu2' "$BASE_URL/auth-records/$pid"
show -X POST "$BASE_URL/auth-records" \
  -H 'Content-Type: application/json' -H 'X-Identity: rsu2' \
  -d "{\"pid\":\"$pid\",\"service\":\"$service\",\"class\":\"private\",\"expiry\":$expiry}"
sleep "$VISIBILITY_WAIT_SECONDS"
show -H 'X-Identity: ta1' "$BASE_URL/auth-records/$pid"

printf '\n=== Demo step 5: report and revoke a misbehaving pseudonym ===\n'
show -X POST "$BASE_URL/reports" \
  -H 'Content-Type: application/json' -H 'X-Identity: rsu1' \
  -d "{\"pid\":\"$pid\",\"evidenceHash\":\"$evidence1\",\"attackType\":\"sybil\"}"
sleep "$VISIBILITY_WAIT_SECONDS"
show -X POST "$BASE_URL/reports" \
  -H 'Content-Type: application/json' -H 'X-Identity: rsu2' \
  -d "{\"pid\":\"$pid\",\"evidenceHash\":\"$evidence2\",\"attackType\":\"sybil\"}"
sleep "$VISIBILITY_WAIT_SECONDS"
show -H 'X-Identity: rsu1' "$BASE_URL/pseudonyms/$pid"
show -H 'X-Identity: rsu2' "$BASE_URL/revoked/$pid"
show -X POST "$BASE_URL/auth-records" \
  -H 'Content-Type: application/json' -H 'X-Identity: rsu2' \
  -d "{\"pid\":\"$pid\",\"service\":\"$service\",\"class\":\"private\",\"expiry\":$expiry}"

printf '\n=== Demo step 6: approve a trace and revoke five pseudonyms ===\n'
show -X POST "$BASE_URL/traces" \
  -H 'Content-Type: application/json' -H 'X-Identity: rsu1' \
  -d "{\"reqId\":\"$req_id\",\"pid\":\"$pid\",\"reason\":\"demo trace request\"}"
sleep "$VISIBILITY_WAIT_SECONDS"
show -X POST "$BASE_URL/traces/$req_id/approve" -H 'X-Identity: rsu1'
sleep "$VISIBILITY_WAIT_SECONDS"
show -X POST "$BASE_URL/traces/$req_id/approve" -H 'X-Identity: rsu2'
sleep "$VISIBILITY_WAIT_SECONDS"
show -H 'X-Identity: ta1' "$BASE_URL/traces/$req_id"
show -X POST "$BASE_URL/traces/$req_id/approve" -H 'X-Identity: rsu3'
sleep "$VISIBILITY_WAIT_SECONDS"
revoke_pids="[\"$pid\",\"$pid2\",\"$pid3\",\"$pid4\",\"$pid5\"]"
show -X POST "$BASE_URL/traces/$req_id/revoke" \
  -H 'Content-Type: application/json' -H 'X-Identity: ta1' \
  -d "{\"pids\":$revoke_pids,\"reason\":\"demo trace execution\"}"
sleep "$VISIBILITY_WAIT_SECONDS"
show -H 'X-Identity: rsu1' "$BASE_URL/traces/$req_id"
for trace_pid in "$pid" "$pid2" "$pid3" "$pid4" "$pid5"; do
  show -H 'X-Identity: rsu1' "$BASE_URL/revoked/$trace_pid"
done

printf '\n=== Demo step 7: verify caller authorization ===\n'
show -X PUT "$BASE_URL/policies/x" \
  -H 'Content-Type: application/json' -H 'X-Identity: rsu1' \
  -d '{"classes":["private"]}'

printf '\nDumpState is intentionally skipped in the Stage C core scope.\n'
