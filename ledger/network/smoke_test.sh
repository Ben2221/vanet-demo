#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
check_identity() {
  local org="$1" user="$2" expected_role="$3" result
  use_identity "$org" "$user"
  result="$(peer chaincode query -C "$CHANNEL" -n "$CC_NAME" -c '{"Args":["WhoAmI"]}')"
  if ! jq -e --arg msp "Org${org}MSP" --arg role "$expected_role" --arg id "$user" \
      '.msp == $msp and .role == $role and .id == $id' <<<"$result" >/dev/null; then
    echo "Unexpected WhoAmI response for $user: $result" >&2
    return 1
  fi
  echo "$user: $result"
}

check_identity 1 ta1 TA
for rsu in "${RSU_IDS[@]}"; do
  check_identity 2 "$rsu" RSU
done

echo "SMOKE TEST PASSED"
