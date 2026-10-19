#!/usr/bin/env bash

_NETWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REPO_ROOT="$(cd "$_NETWORK_DIR/../.." && pwd)"
export FABRIC_HOME="${FABRIC_HOME:-$HOME/fabric/fabric-samples}"
export TN="$FABRIC_HOME/test-network"
export PATH="$HOME/.local/bin:$FABRIC_HOME/bin:$PATH"
export FABRIC_CFG_PATH="$FABRIC_HOME/config"
export CORE_PEER_TLS_ENABLED=true
export CHANNEL="${CHANNEL:-vanetchannel}"
export CC_NAME="${CC_NAME:-vanetauth}"

export ORDERER_CA="$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
export ORG1_TLS="$TN/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"
export ORG2_TLS="$TN/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem"

use_identity() {
  local org="${1:?usage: use_identity <1|2> [user]}"
  local user="${2:-Admin}"

  case "$org" in
    1|2) ;;
    *) echo "Organization must be 1 (TA) or 2 (RSU)." >&2; return 2 ;;
  esac

  export CORE_PEER_LOCALMSPID="Org${org}MSP"
  export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org${org}.example.com/users/${user}@org${org}.example.com/msp"
  if [[ "$org" == 1 ]]; then
    export CORE_PEER_TLS_ROOTCERT_FILE="$ORG1_TLS"
    export CORE_PEER_ADDRESS=localhost:7051
  else
    export CORE_PEER_TLS_ROOTCERT_FILE="$ORG2_TLS"
    export CORE_PEER_ADDRESS=localhost:9051
  fi
}

inv() {
  local transaction="${1:?usage: inv '<chaincode transaction JSON>'}"
  peer chaincode invoke \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" \
    -C "$CHANNEL" -n "$CC_NAME" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_TLS" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_TLS" \
    -c "$transaction"
}
