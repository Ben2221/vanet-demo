#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"
use_identity 1 ta1

epoch="$(date +%s)"
root="$(openssl rand -hex 32)"
valid_until="$(( $(date +%s%3N) + 3600000 ))"

printf 'Seeding demo configuration...\n'
inv '{"Args":["SetConfig","2","3","3600","true"]}'
printf 'Seeding traffic-info policy...\n'
inv '{"Args":["SetPolicy","traffic-info","[\"private\",\"commercial\",\"emergency\"]"]}'
printf 'Seeding toll policy...\n'
inv '{"Args":["SetPolicy","toll","[\"private\",\"commercial\"]"]}'
printf 'Seeding emergency-priority policy...\n'
inv '{"Args":["SetPolicy","emergency-priority","[\"emergency\"]"]}'
printf 'Registering demo root...\n'
inv "{\"Args\":[\"RegisterRoot\",\"$epoch\",\"$root\",\"$valid_until\"]}"
printf 'DEMO SEED APPLIED\n'
