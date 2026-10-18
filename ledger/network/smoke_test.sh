#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
callers=()

check_identity() {
  local org="$1" user="$2" expected_role="$3" result caller existing
  use_identity "$org" "$user"
  result="$(peer chaincode query -C "$CHANNEL" -n "$CC_NAME" -c '{"Args":["WhoAmI"]}')"
  if [[ "$result" != *"msp=Org${org}MSP"* || "$result" != *"role=$expected_role"* ]]; then
    echo "Unexpected WhoAmI response for $user: $result" >&2
    return 1
  fi

  caller="${result##*caller=}"
  if [[ -z "$caller" || "$caller" == "$result" ]]; then
    echo "WhoAmI response for $user did not include a caller hash: $result" >&2
    return 1
  fi
  for existing in "${callers[@]}"; do
    if [[ "$caller" == "$existing" ]]; then
      echo "Caller hash for $user duplicates another identity: $caller" >&2
      return 1
    fi
  done
  callers+=("$caller")
  echo "$user: $result"
}

check_identity 1 ta1 TA
for n in 1 2 3 4; do
  check_identity 2 "rsu$n" RSU
done

echo "SMOKE TEST PASSED"
