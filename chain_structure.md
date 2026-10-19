# Hyperledger Fabric Chain Setup: Step-by-Step Plan (VANET Demo)

Scope: bring up the blockchain infrastructure only (network, channel, identities, a deployable chaincode skeleton, scripts). The real `vanetauth` contract logic and the REST gateway come after this plan is done.

Design choices (demo-minimal):

- Fabric **2.5 LTS**, using `fabric-samples/test-network` with Fabric CA (`-ca`)
- **Org1 = TA** (Trusted Authority), **Org2 = RSUOperators**
- 1 peer per org, 1 Raft orderer (as shipped)
- RSUs are **client identities** (`rsu1`..`rsu4`) enrolled under Org2, not separate peers
- Channel: `vanetchannel`, chaincode: `vanetauth`
- LevelDB state database (no CouchDB needed)

---

## 0. End state (what "done" looks like)

1. `./up.sh` starts the network and creates `vanetchannel` in one command.
2. `./deploy_cc.sh` deploys `vanetauth` and `peer chaincode query ... WhoAmI` works.
3. Identities `ta1`, `rsu1`..`rsu4` exist, and `WhoAmI` reports the correct role for each.
4. `./down.sh` wipes everything cleanly, and `up.sh` works again from scratch.
5. Batch timeout is configurable, and a manual invoke shows commit time.

---

## 1. Prerequisites

| Tool | Version | Check command |
|---|---|---|
| Linux / WSL2 (Ubuntu 22.04+) | any recent | `lsb_release -a` |
| Docker Engine | 24+ | `docker --version` |
| Docker Compose v2 | 2.x | `docker compose version` |
| Go | 1.21+ | `go version` |
| Node.js | 22.12+ (fabric-gateway 1.13) | `node -v` |
| jq, curl, git | any | `jq --version` |
| RAM available to Docker | **8 GB** | `docker info \| grep Memory` |

### Steps

1. Install Docker and let your user run it without sudo:
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   docker run hello-world
   ```
2. **WSL2 only:** create `%UserProfile%\.wslconfig` with
   ```
   [wsl2]
   memory=8GB
   processors=4
   ```
   then run `wsl --shutdown` from PowerShell and reopen the terminal.
3. Make sure Docker is running inside the distro (`docker ps` works with no error).
4. Keep ~10 GB of disk free. The images are a few GB, so do the install on a good connection.

**Checkpoint:** `docker run hello-world`, `go version` and `node -v` all succeed.

---

## 2. Install Fabric binaries, images and samples

Pick a working directory outside your repo (it holds large generated files):

```bash
mkdir -p ~/fabric && cd ~/fabric
curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
chmod +x install-fabric.sh
./install-fabric.sh --fabric-version 2.5.16 docker samples binary
```

(Use the latest 2.5.x patch if 2.5.16 is not current; 2.5.15 or newer is required on Docker Engine 29+. Do **not** pick 3.x for this plan.)

This gives you:

- `~/fabric/fabric-samples/` (the test network lives in `test-network/`)
- `~/fabric/fabric-samples/bin/` (`peer`, `configtxgen`, `fabric-ca-client`, ...)
- Docker images `hyperledger/fabric-peer`, `fabric-orderer`, `fabric-ca`, `fabric-tools`, `fabric-ccenv`, `fabric-baseos`

Add to `~/.bashrc`:

```bash
export FABRIC_HOME=$HOME/fabric/fabric-samples
export PATH=$FABRIC_HOME/bin:$PATH
```

**Checkpoint:**
```bash
peer version                 # shows 2.5.x
fabric-ca-client version     # shows 1.5.x
docker images | grep hyperledger
```

---

## 3. Know what you are about to start

Ports and containers created by the test network with `-ca`:

| Container | Role | Host port |
|---|---|---|
| `peer0.org1.example.com` | TA org peer | 7051 |
| `peer0.org2.example.com` | RSU org peer | 9051 |
| `orderer.example.com` | Raft orderer (single node) | 7050 (admin 7053) |
| `ca_org1` | Fabric CA for TA org | 7054 |
| `ca_org2` | Fabric CA for RSU org | 8054 |
| `ca_orderer` | Fabric CA for orderer | 9054 |

Make sure none of these ports are in use:
```bash
ss -ltn | grep -E ':(7050|7051|7053|7054|8054|9051|9054)\s'   # should print nothing
```

Mapping to the project: Org1MSP = TA, Org2MSP = RSUs. Orderer organisation is infrastructure only.

---

## 4. Configure the batch timeout (before creating the channel)

The orderer batch timeout dominates commit latency (default 2 s). It is baked into the channel when it is created, so set it **before** `createChannel`.

```bash
cd $FABRIC_HOME/test-network
cp configtx/configtx.yaml configtx/configtx.yaml.orig        # backup once
grep -n "BatchTimeout" configtx/configtx.yaml                # shows: BatchTimeout: 2s
sed -i 's/BatchTimeout: 2s/BatchTimeout: 500ms/' configtx/configtx.yaml
grep -n "BatchTimeout" configtx/configtx.yaml                # now 500ms
```

To change it later you must `./network.sh down` and recreate the channel (restore the `.orig` file first or re-run `sed` with a new value).

---

## 5. Bring up the network and create the channel

```bash
cd $FABRIC_HOME/test-network
./network.sh down                                   # clean slate
./network.sh up createChannel -c vanetchannel -ca
```

What this does, in order: starts the 3 CAs, enrolls admins and generates crypto material, starts the orderer and two peers, creates the channel genesis block from `configtx.yaml`, joins both peers to `vanetchannel`.

**Checkpoint:**
```bash
docker ps --format '{{.Names}}\t{{.Status}}'
# expect: peer0.org1.example.com, peer0.org2.example.com, orderer.example.com, ca_org1, ca_org2, ca_orderer (all Up)
```
The script output should end with `Channel 'vanetchannel' joined`.

---

## 6. Set up the `peer` CLI environment

Create `~/fabric/env.sh` (or later in the repo at `ledger/network/env.sh`):

```bash
#!/usr/bin/env bash
export FABRIC_HOME=${FABRIC_HOME:-$HOME/fabric/fabric-samples}
export TN=$FABRIC_HOME/test-network
export PATH=$FABRIC_HOME/bin:$PATH
export FABRIC_CFG_PATH=$FABRIC_HOME/config/
export CORE_PEER_TLS_ENABLED=true
export CHANNEL=vanetchannel
export CC_NAME=vanetauth

export ORDERER_CA=$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
export ORG1_TLS=$TN/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem
export ORG2_TLS=$TN/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem

# usage: use_identity <org 1|2> [user]   (default user = Admin)
use_identity () {
  local org=$1 user=${2:-Admin}
  export CORE_PEER_LOCALMSPID=Org${org}MSP
  export CORE_PEER_MSPCONFIGPATH=$TN/organizations/peerOrganizations/org${org}.example.com/users/${user}@org${org}.example.com/msp
  if [ "$org" = "1" ]; then
    export CORE_PEER_TLS_ROOTCERT_FILE=$ORG1_TLS
    export CORE_PEER_ADDRESS=localhost:7051
  else
    export CORE_PEER_TLS_ROOTCERT_FILE=$ORG2_TLS
    export CORE_PEER_ADDRESS=localhost:9051
  fi
}

# invoke helper: endorse on both orgs, wait for commit
inv () {
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C $CHANNEL -n $CC_NAME \
    --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_TLS" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_TLS" \
    -c "$1"
}
```

**Checkpoint:**
```bash
source ~/fabric/env.sh
use_identity 1
peer channel list                        # shows vanetchannel
peer channel getinfo -c vanetchannel     # shows block height (small number)
```

---

## 7. Smoke test with the sample chaincode (proves the network works)

Do this once before writing your own chaincode, so any later failure is clearly yours.

```bash
cd $TN
./network.sh deployCC -c vanetchannel -ccn basic \
  -ccp ../asset-transfer-basic/chaincode-go -ccl go
```

Then:
```bash
source ~/fabric/env.sh
use_identity 1
CC_NAME=basic inv '{"function":"InitLedger","Args":[]}'
peer chaincode query -C vanetchannel -n basic -c '{"Args":["GetAllAssets"]}' | jq
```

**Checkpoint:** you see 6 sample assets and the invoke printed `Chaincode invoke successful. result: status:200`.

Now reset so `vanetauth` starts clean:
```bash
cd $TN && ./network.sh down
```
(Re-run section 5 afterwards. Because the batch timeout edit is in `configtx.yaml`, it persists.)

---

## 8. Create the `vanetauth` skeleton chaincode

Goal: a tiny contract that proves deployment **and** lets you see which identity/role the chaincode sees. The real functions get added later.

Repo location: `vanet-demo/ledger/chaincode/vanetauth/`

```bash
mkdir -p ~/vanet-demo/ledger/chaincode/vanetauth && cd ~/vanet-demo/ledger/chaincode/vanetauth
cp $FABRIC_HOME/asset-transfer-basic/chaincode-go/go.mod .
cp $FABRIC_HOME/asset-transfer-basic/chaincode-go/go.sum .
sed -i 's#^module .*#module vanetauth#' go.mod
```

`main.go`:
```go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type VanetAuth struct {
	contractapi.Contract
}

// WhoAmI reports the caller's MSP, derived role and a short ID hash.
func (c *VanetAuth) WhoAmI(ctx contractapi.TransactionContextInterface) (string, error) {
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}
	id, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", err
	}
	role := "UNKNOWN"
	switch msp {
	case "Org1MSP":
		role = "TA"
	case "Org2MSP":
		role = "RSU"
	}
	h := sha256.Sum256([]byte(id))
	return fmt.Sprintf("msp=%s role=%s caller=%s", msp, role, hex.EncodeToString(h[:4])), nil
}

// Put / Get are throwaway helpers to test writes and reads. Remove later.
func (c *VanetAuth) Put(ctx contractapi.TransactionContextInterface, key, value string) error {
	return ctx.GetStub().PutState(key, []byte(value))
}

func (c *VanetAuth) Get(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	b, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func main() {
	cc, err := contractapi.NewChaincode(&VanetAuth{})
	if err != nil {
		log.Panicf("create chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("start chaincode: %v", err)
	}
}
```

Tidy and compile-check locally before deploying:
```bash
go mod tidy
go build ./...
```

**Checkpoint:** `go build ./...` finishes with no errors.

---

## 9. Deploy `vanetauth`

Bring the network back up first (section 5), then:

```bash
cd $TN
./network.sh deployCC -c vanetchannel -ccn vanetauth \
  -ccp $HOME/vanet-demo/ledger/chaincode/vanetauth -ccl go \
  -ccv 1.0 -ccs 1
```

This packages the chaincode (it runs `go mod vendor`, which needs internet), installs it on both peers, both orgs approve, and it is committed to the channel with the default **majority** endorsement policy (both orgs sign each write).

Optional, faster writes (one org is enough):
```bash
./network.sh deployCC ... -ccep "OR('Org1MSP.peer','Org2MSP.peer')"
```

**Checkpoint:**
```bash
source ~/fabric/env.sh
use_identity 1
peer lifecycle chaincode querycommitted -C vanetchannel -n vanetauth
# Version: 1.0, Sequence: 1, Approvals: [Org1MSP: true, Org2MSP: true]

peer chaincode query -C vanetchannel -n vanetauth -c '{"Args":["WhoAmI"]}'
# msp=Org1MSP role=TA caller=xxxxxxxx
use_identity 2
peer chaincode query -C vanetchannel -n vanetauth -c '{"Args":["WhoAmI"]}'
# msp=Org2MSP role=RSU caller=xxxxxxxx
```

Write test:
```bash
inv '{"function":"Put","Args":["hello","world"]}'
peer chaincode query -C vanetchannel -n vanetauth -c '{"Args":["Get","hello"]}'   # world
```

---

## 10. Create the TA and RSU identities

The sample network only creates `Admin` and `User1` per org. You need named identities: one TA client and four RSU clients. Because we used `-ca`, register them with the Fabric CAs.

### 10.1 TA client (Org1, CA on port 7054)

```bash
cd $TN
export FABRIC_CA_CLIENT_HOME=$TN/organizations/peerOrganizations/org1.example.com/
CA_TLS=$TN/organizations/fabric-ca/org1/ca-cert.pem

fabric-ca-client register --caname ca-org1 --id.name ta1 --id.secret ta1pw \
  --id.type client --tls.certfiles $CA_TLS

fabric-ca-client enroll -u https://ta1:ta1pw@localhost:7054 --caname ca-org1 \
  -M $TN/organizations/peerOrganizations/org1.example.com/users/ta1@org1.example.com/msp \
  --tls.certfiles $CA_TLS

cp $TN/organizations/peerOrganizations/org1.example.com/msp/config.yaml \
   $TN/organizations/peerOrganizations/org1.example.com/users/ta1@org1.example.com/msp/config.yaml
```

### 10.2 RSU clients (Org2, CA on port 8054)

```bash
export FABRIC_CA_CLIENT_HOME=$TN/organizations/peerOrganizations/org2.example.com/
CA_TLS=$TN/organizations/fabric-ca/org2/ca-cert.pem

for n in 1 2 3 4; do
  fabric-ca-client register --caname ca-org2 --id.name rsu$n --id.secret rsu${n}pw \
    --id.type client --tls.certfiles $CA_TLS

  fabric-ca-client enroll -u https://rsu$n:rsu${n}pw@localhost:8054 --caname ca-org2 \
    -M $TN/organizations/peerOrganizations/org2.example.com/users/rsu$n@org2.example.com/msp \
    --tls.certfiles $CA_TLS

  cp $TN/organizations/peerOrganizations/org2.example.com/msp/config.yaml \
     $TN/organizations/peerOrganizations/org2.example.com/users/rsu$n@org2.example.com/msp/config.yaml
done
```

The `config.yaml` copy is what enables the node OUs (client/peer/admin roles). Without it the identity may be rejected.

### 10.3 Verify each identity

```bash
source ~/fabric/env.sh
use_identity 1 ta1
peer chaincode query -C vanetchannel -n vanetauth -c '{"Args":["WhoAmI"]}'   # role=TA
for n in 1 2 3 4; do
  use_identity 2 rsu$n
  peer chaincode query -C vanetchannel -n vanetauth -c '{"Args":["WhoAmI"]}' # role=RSU, caller differs per rsu
done
```

**Checkpoint:** five different `caller=` hashes (1 TA, 4 RSUs), correct roles. This proves the caller rules in the real contract can be enforced from the client identity.

### 10.4 Collect files for the gateway (needed next stage)

For each identity the gateway needs:

- Certificate: `.../users/<name>@<org>/msp/signcerts/cert.pem`
- Private key: `.../users/<name>@<org>/msp/keystore/*_sk`
- Peer TLS CA: `ORG1_TLS` / `ORG2_TLS` from `env.sh`
- Peer endpoint: `localhost:7051` (host alias `peer0.org1.example.com`) or `localhost:9051` (`peer0.org2.example.com`)

---

## 11. Wrap everything in scripts (`ledger/network/`)

Goal: nothing is typed by hand twice.

**`up.sh`**
```bash
#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/env.sh"
BATCH_TIMEOUT=${BATCH_TIMEOUT:-500ms}

cd $TN
[ -f configtx/configtx.yaml.orig ] || cp configtx/configtx.yaml configtx/configtx.yaml.orig
cp configtx/configtx.yaml.orig configtx/configtx.yaml
sed -i "s/BatchTimeout: 2s/BatchTimeout: ${BATCH_TIMEOUT}/" configtx/configtx.yaml

./network.sh down
./network.sh up createChannel -c $CHANNEL -ca
"$(dirname "$0")/deploy_cc.sh"
"$(dirname "$0")/enroll_identities.sh"
"$(dirname "$0")/smoke_test.sh"
```

**`deploy_cc.sh`**
```bash
#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/env.sh"
CC_VERSION=${CC_VERSION:-1.0}
CC_SEQ=${CC_SEQ:-1}
CC_PATH=$(cd "$(dirname "$0")/../chaincode/vanetauth" && pwd)

cd $TN
./network.sh deployCC -c $CHANNEL -ccn $CC_NAME -ccp "$CC_PATH" -ccl go \
  -ccv $CC_VERSION -ccs $CC_SEQ ${CC_EP:+-ccep "$CC_EP"}
```

**`enroll_identities.sh`**: sections 10.1 and 10.2 as a script, skipping an identity if its `msp` directory already exists.

**`smoke_test.sh`**
```bash
#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/env.sh"
use_identity 1 ta1
peer chaincode query -C $CHANNEL -n $CC_NAME -c '{"Args":["WhoAmI"]}' | grep -q "role=TA"
for n in 1 2 3 4; do
  use_identity 2 rsu$n
  peer chaincode query -C $CHANNEL -n $CC_NAME -c '{"Args":["WhoAmI"]}' | grep -q "role=RSU"
done
echo "SMOKE TEST PASSED"
```

**`down.sh`**
```bash
#!/usr/bin/env bash
source "$(dirname "$0")/env.sh"
cd $TN && ./network.sh down
docker volume prune -f
```

Make them executable: `chmod +x *.sh`.

**Checkpoint:** run `./down.sh && ./up.sh` from scratch. It ends with `SMOKE TEST PASSED` and takes a few minutes, not hours.

---

## 12. Redeploying chaincode (you will do this often)

Every chaincode change needs a **new version label and a higher sequence**:

```bash
CC_VERSION=1.1 CC_SEQ=2 ./deploy_cc.sh
CC_VERSION=1.2 CC_SEQ=3 ./deploy_cc.sh
```

Keep a one-line note of the current pair in `ledger/network/VERSION`. For quick iteration, `./down.sh && ./up.sh` is often simpler than upgrading, because the demo has no data worth keeping.

---

## 13. Sanity-check commit latency

Quick manual number before building any benchmark:

```bash
source ~/fabric/env.sh
use_identity 2 rsu1
for i in 1 2 3 4 5; do
  /usr/bin/time -f "%e s" bash -c "source ~/fabric/env.sh; use_identity 2 rsu1; inv '{\"function\":\"Put\",\"Args\":[\"k$i\",\"v\"]}'" 2>&1 | tail -1
done
```

Expect roughly 0.7–1.5 s per write with `BatchTimeout 500ms`, and about 2.5 s or more with the default 2 s (this includes `peer` process startup, so the later gateway numbers will be lower). Re-run `BATCH_TIMEOUT=2s ./up.sh` and `BATCH_TIMEOUT=200ms ./up.sh` to confirm the setting actually moves the number.

---

## 14. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `permission denied` on docker socket | user not in docker group | `sudo usermod -aG docker $USER`, then re-login |
| `address already in use` | old containers or other service on 7050/7051/9051 | `./down.sh`, then check `ss -ltn` |
| containers exit or restart repeatedly | not enough memory | give Docker/WSL2 8 GB, close other apps |
| `go mod vendor` fails during deployCC | no internet or Go proxy blocked | check network, try `GOPROXY=https://proxy.golang.org` |
| `chaincode definition not agreed to by this org` | one org did not approve | rerun `deployCC`, and check both orgs show approvals in `querycommitted` |
| `sequence mismatch` / `requested sequence is X, but new definition must be sequence Y` | redeploy with same sequence | bump `-ccs` by exactly 1 |
| `ENDORSEMENT_POLICY_FAILURE` | invoke endorsed by only one org under majority policy | pass both `--peerAddresses` (the `inv` helper does) or use `-ccep OR(...)` |
| `access denied: ... creator org unknown` or cert errors after restart | stale crypto material from a previous run | `./down.sh`, then `./up.sh` (the script regenerates everything) |
| `identity not valid` for rsuN | `config.yaml` not copied into its `msp` folder | copy it from the org `msp` directory (section 10) |
| Chaincode container fails to build | `go` directive in `go.mod` newer than the builder image supports | keep it equal to the sample chaincode's `go.mod` |
| `Error: endorsement failure ... chaincode vanetauth not found` | chaincode not committed or wrong channel name | `peer lifecycle chaincode querycommitted -C vanetchannel` |
| Changed `BatchTimeout` has no effect | edited after the channel was created | `down`, edit, `up` |

---

## 15. Final checklist before moving to contract and gateway work

- [ ] `./down.sh && ./up.sh` works from scratch on your machine
- [ ] `vanetchannel` exists, `vanetauth` committed with Org1 and Org2 approvals
- [ ] `ta1`, `rsu1`..`rsu4` enrolled, `WhoAmI` returns the right role for each
- [ ] Batch timeout is script-configurable and you saw the latency change
- [ ] Identity file paths and peer endpoints for the gateway are noted (10.4)
- [ ] Scripts are committed under `ledger/network/`, and `fabric-samples` is **not** in the repo
- [ ] A teammate can follow the README and bring it up on their machine

Next stage: replace the `Put`/`Get` skeleton with the real `vanetauth` functions (RegisterRoot, SetPolicy, RecordAuth, ReportMisbehaviour, IsRevoked, trace functions, Revoke), then build the gateway on top of the identities from section 10.