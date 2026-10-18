#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/env.sh"

if [[ ! -x "$FABRIC_HOME/bin/fabric-ca-client" ]]; then
  echo "fabric-ca-client not found under $FABRIC_HOME/bin. Install Fabric first." >&2
  exit 1
fi

ORG1_DIR="$TN/organizations/peerOrganizations/org1.example.com"
ORG2_DIR="$TN/organizations/peerOrganizations/org2.example.com"
ORG1_CA_TLS="$TN/organizations/fabric-ca/org1/ca-cert.pem"
ORG2_CA_TLS="$TN/organizations/fabric-ca/org2/ca-cert.pem"

if [[ ! -f "$ORG1_CA_TLS" || ! -f "$ORG2_CA_TLS" ]]; then
  echo "Fabric CA certificates are missing. Start the test network with -ca first." >&2
  exit 1
fi

enroll_identity() {
  local org="$1" name="$2" secret="$3" org_dir="$4" ca_name="$5" ca_port="$6" ca_tls="$7"
  local msp_dir="$org_dir/users/$name@org${org}.example.com/msp"

  if [[ -s "$msp_dir/signcerts/cert.pem" && -d "$msp_dir/keystore" ]]; then
    echo "Identity $name is already enrolled; skipping."
    return
  fi

  export FABRIC_CA_CLIENT_HOME="$org_dir"
  fabric-ca-client register \
    --caname "$ca_name" \
    --id.name "$name" \
    --id.secret "$secret" \
    --id.type client \
    --tls.certfiles "$ca_tls"

  fabric-ca-client enroll \
    -u "https://$name:$secret@localhost:$ca_port" \
    --caname "$ca_name" \
    -M "$msp_dir" \
    --tls.certfiles "$ca_tls"

  cp "$org_dir/msp/config.yaml" "$msp_dir/config.yaml"
}

enroll_identity 1 ta1 "${TA1_SECRET:-ta1pw}" "$ORG1_DIR" ca-org1 7054 "$ORG1_CA_TLS"
for n in 1 2 3 4; do
  enroll_identity 2 "rsu$n" "${RSU_SECRET_PREFIX:-rsu}${n}pw" "$ORG2_DIR" ca-org2 8054 "$ORG2_CA_TLS"
done
