# VANET Fabric Ledger: Implementation and AI Context

This document describes the ledger implementation in this repository, how to run it, what has been verified, and the boundaries of the current prototype. It is intended both as a detailed guide for a developer and as durable context for future AI-assisted work.

## 1. Project purpose and current scope

The ledger is the Hyperledger Fabric infrastructure for the VANET demo. Its current goal is to prove that the network, channel, chaincode lifecycle, CA identities, and client identity visibility all work together.

Implemented now:

- Fabric 2.5 test network with Fabric CA.
- Two member organizations: Org1 as the Trusted Authority (TA), and Org2 as the RSU operator organization.
- Channel `vanetchannel`.
- Go chaincode `vanetauth`, version `1.0`, sequence `1`.
- One TA client identity (`ta1`) and four RSU client identities (`rsu1`–`rsu4`). RSUs are clients, not separate peers.
- Docker-first Go toolchain, installation/bootstrap scripts, network lifecycle scripts, and a smoke test.

Not implemented yet:

- The actual VANET authorization/registration contract logic.
- A REST or other application gateway.
- Production-grade identity, secret, endorsement, availability, or deployment configuration.

The planned contract functions in `chain_structure.md` include `RegisterRoot`, `SetPolicy`, `RecordAuth`, `ReportMisbehaviour`, `IsRevoked`, trace functions, and `Revoke`. They are future work; do not assume the current `Put`/`Get` methods enforce VANET rules.

## 2. Architecture at a glance

```text
TA client: ta1 (Org1MSP) ---- peer0.org1.example.com:7051 ----+
                                                              +-- vanetchannel
RSU clients: rsu1..rsu4 ----- peer0.org2.example.com:9051 ----+       |
                                                                      +-- vanetauth chaincode
Single Raft orderer: orderer.example.com:7050
Fabric CAs: Org1 :7054, Org2 :8054, Orderer :9054
```

Both organizations endorse writes under the default test-network application endorsement policy. The CLI helper `inv` submits an invoke to both peer endpoints. The setup uses LevelDB, the test network's single Raft orderer, and Fabric CA-generated certificates.

| Component | Purpose | Host endpoint |
|---|---|---:|
| `peer0.org1.example.com` | Org1 / TA peer | `localhost:7051` |
| `peer0.org2.example.com` | Org2 / RSU peer | `localhost:9051` |
| `orderer.example.com` | Single-node Raft ordering service | `localhost:7050` |
| Orderer admin endpoint | Orderer administration | `localhost:7053` |
| Org1 CA | Issues TA-org credentials | `localhost:7054` |
| Org2 CA | Issues RSU-org credentials | `localhost:8054` |
| Orderer CA | Issues orderer credentials | `localhost:9054` |

The test-network organization names map to roles as follows:

- `Org1MSP` -> TA.
- `Org2MSP` -> RSU operator organization.
- Orderer organization -> infrastructure only.

## 3. Repository layout and file responsibilities

```text
ledger/
  IMPLEMENTATION_CONTEXT.md      This implementation and AI handoff document
  start.sh                       Main one-command entrypoint
  chaincode/
    vanetauth/
      main.go                    Contract skeleton: WhoAmI, Put, Get
      go.mod                     Go module and Fabric Contract API dependency
      go.sum                     Pinned dependency checksums
      build.sh                   Dockerized tidy, vendor, test, and build
      .gitignore                 Ignores generated vendor tree and local binary
  network/
    start.sh                     Bootstrap Fabric, then start the network
    install_fabric.sh            Install Fabric tools/images and local helpers
    up.sh                        Configure timeout, create network/channel, deploy,
                                 enroll identities, and run smoke test
    down.sh                      Stop/reset the Fabric test network
    deploy_cc.sh                 Build and deploy/upgrade vanetauth
    enroll_identities.sh         Register and enroll ta1 and rsu1..rsu4
    smoke_test.sh                Verify roles and distinct caller hashes
    env.sh                       Fabric CLI environment and helper functions
    go                           Docker-backed Go shim used by Fabric scripts
    VERSION                      Current chaincode version and sequence: 1.0 1
```

Fabric samples, binaries, generated crypto, and channel artifacts are installed outside the repository by default under `~/fabric/fabric-samples/`. Do not copy the Fabric samples tree or generated private identity keys into source control.

## 4. Chaincode behavior

`ledger/chaincode/vanetauth/main.go` registers a Fabric Contract API contract named `VanetAuth`.

### `WhoAmI`

1. Reads the transaction caller's MSP ID and Fabric client identity ID.
2. Derives the display role from the MSP ID (`Org1MSP` -> `TA`, `Org2MSP` -> `RSU`, otherwise `UNKNOWN`).
3. SHA-256 hashes the client identity ID and returns the first four hash bytes as an eight-character hexadecimal caller token.
4. Returns text such as `msp=Org2MSP role=RSU caller=abcd1234`.

This intentionally avoids returning the raw certificate identity. The short hash is only a demo identifier, not a security-grade unique identifier; it is 32 bits and can theoretically collide.

### `Put` and `Get`

- `Put(ctx, key, value)` writes the UTF-8 bytes of `value` to the ledger under `key`.
- `Get(ctx, key)` reads the ledger value and returns it as a string.
- These are temporary ledger read/write checks. They do not check a caller's role or validate key/value semantics.

The contract uses `github.com/hyperledger/fabric-contract-api-go` version `v1.2.2` and the Go `1.20` module language level. Fabric's peer package build was verified with this setup.

## 5. Docker-first Go tooling

No host Go installation is required.

- `build.sh` starts the pinned `golang:1.20` image to run `go mod tidy`, `go mod vendor`, `go test ./...`, and a compile check. The binary check is written under the container's `/tmp`, not into the repository.
- `vendor/` is generated when building/deploying and ignored by the chaincode-local `.gitignore`.
- Fabric's own `network.sh deployCC` packaging step invokes `go` on the host. `install_fabric.sh` links `ledger/network/go` to `~/.local/bin/go`; that shim executes Go commands inside `golang:1.20` and mounts the chaincode module at the same path required by Fabric's packager.
- The `golang:1.20` image is pulled automatically by Docker the first time it is needed.

Keep the shim's Go version aligned with the module's `go` directive and the Fabric 2.5 chaincode builder image. Do not replace the shim with an unpinned host Go version without testing packaging and deployment.

## 6. One-command startup

### Requirements

- Linux or WSL2 with Bash. On Windows, Docker Desktop must be running and WSL integration enabled for the chosen Linux distribution.
- Docker CLI access and Docker Compose v2 from that Linux/WSL shell.
- `curl`; `jq` is downloaded into `~/.local/bin` by the installer if it is not already available. The current jq bootstrap supports x86-64 and ARM64 Linux.
- Internet access for initial downloads and roughly 8 GB of Docker-available memory plus about 10 GB of free disk space.
- Host Go and Node.js are not required by this Go-only chaincode setup.

### Start from WSL

Open the Linux distribution in which Docker integration is enabled, change to the repository root, and run:

```bash
cd /path/to/vanet-demo
./ledger/start.sh
```

For the current Windows checkout the WSL path is:

```bash
cd /mnt/c/Users/lenovo/OneDrive/Desktop/BTP/vanet-demo
./ledger/start.sh
```

### Start from Windows PowerShell

PowerShell can invoke the same script through WSL. Replace the example repository path if the checkout is elsewhere:

```powershell
wsl -d Ubuntu -- bash -lc "cd /mnt/c/Users/lenovo/OneDrive/Desktop/BTP/vanet-demo && ./ledger/start.sh"
```

`ledger/start.sh` forwards to `ledger/network/start.sh`, which:

1. Determines the Fabric install root (`FABRIC_INSTALL_ROOT`, default `~/fabric`) and `FABRIC_HOME`.
2. Runs `install_fabric.sh`. On a fresh machine it installs Fabric 2.5.9 samples/binaries/images, installs jq if missing, and sets up the Docker Go shim. If the expected Fabric binaries and test-network script already exist, it skips the Fabric download.
3. Runs `up.sh`.
4. Sets the orderer `BatchTimeout` (default `500ms`) before creating the channel. The original config is backed up once as `configtx/configtx.yaml.orig` outside the repository; each run restores that backup before applying the requested timeout.
5. Runs the Fabric sample network's `network.sh down`, then starts the Fabric CA network and creates `vanetchannel`.
6. Builds and deploys `vanetauth` with the configured chaincode version and sequence.
7. Registers/enrolls `ta1`, then `rsu1` through `rsu4`.
8. Queries `WhoAmI` using all five identities, checks roles and unique caller hashes, and ends with `SMOKE TEST PASSED`.

**Important:** each start intentionally tears down and recreates the sample network. This removes the previous demo channel/ledger state and regenerates cryptographic material. It is a resettable demo workflow, not a data-preserving restart.

The installer puts Fabric outside the repo by default. To use another install location, set `FABRIC_INSTALL_ROOT=/some/path/fabric`; samples are placed in `$FABRIC_INSTALL_ROOT/fabric-samples`. `FABRIC_HOME` can point directly at an existing `fabric-samples` directory.

## 7. Stop the network

From the repository root in WSL/Linux:

```bash
./ledger/network/down.sh
```

This calls the Fabric sample network's `network.sh down`. It does not run `docker volume prune`, because pruning globally can delete unrelated containers' unused data. Starting again regenerates the Fabric test network and channel.

## 8. Useful CLI operations

Source the helper environment in a WSL/Linux Bash shell:

```bash
source ledger/network/env.sh
```

Select a peer identity with `use_identity <org> [user]`:

```bash
use_identity 1 ta1       # TA client, Org1MSP, peer localhost:7051
use_identity 2 rsu1      # RSU client, Org2MSP, peer localhost:9051
```

Query caller identity and role:

```bash
use_identity 1 ta1
peer chaincode query -C vanetchannel -n vanetauth -c '{"Args":["WhoAmI"]}'

use_identity 2 rsu1
peer chaincode query -C vanetchannel -n vanetauth -c '{"Args":["WhoAmI"]}'
```

Exercise a ledger write and read:

```bash
use_identity 1 ta1
inv '{"function":"Put","Args":["hello","world"]}'
peer chaincode query -C vanetchannel -n vanetauth -c '{"Args":["Get","hello"]}'
```

The query should return `world`. `inv` endorses with both peer addresses and submits the transaction through the TLS-enabled orderer. The `env.sh` helper sets the peer MSP, MSP directory, endpoint, and TLS root certificate for the selected identity.

For identities used by a future gateway, the generated client material is under:

```text
$FABRIC_HOME/test-network/organizations/peerOrganizations/org1.example.com/users/ta1@org1.example.com/msp/
$FABRIC_HOME/test-network/organizations/peerOrganizations/org2.example.com/users/rsuN@org2.example.com/msp/
```

Each identity's sign certificate is in `signcerts/cert.pem`; its private key is in `keystore/`. Treat private keys as secrets and do not commit or expose them. Peer TLS roots and endpoints are exported as `ORG1_TLS`/`ORG2_TLS` and `localhost:7051`/`localhost:9051` by `env.sh`.

## 9. Configuration and chaincode upgrades

- `BATCH_TIMEOUT=500ms ./ledger/start.sh` selects the default. Other examples are `BATCH_TIMEOUT=200ms ./ledger/start.sh` or `BATCH_TIMEOUT=2s ./ledger/start.sh`. The startup script validates the value and channel creation must happen after the config change.
- `CC_VERSION` and `CC_SEQ` control the definition deployed by `deploy_cc.sh`. The current pair is `1.0 1` in `network/VERSION`.
- For an in-place definition upgrade, increment the sequence by exactly one and change the version label, for example: `CC_VERSION=1.1 CC_SEQ=2 ./ledger/network/deploy_cc.sh`.
- `CC_EP` can optionally specify a chaincode endorsement policy. Without it, Fabric uses the channel's default policy.
- `TA1_SECRET` and `RSU_SECRET_PREFIX` can override the demo enrollment secret pattern. Defaults are `ta1pw` and `rsu1pw` through `rsu4pw`.

Do not repeatedly run a same-sequence deployment as an upgrade. For this disposable demo, `./ledger/start.sh` is usually simpler, but it resets all ledger data.

## 10. Security and design limitations

This repository currently implements a local demonstration setup only:

- The network uses one orderer, so it has no orderer high availability or production fault tolerance.
- The default enrollment passwords are simple demo credentials. Change them for a controlled demo and never reuse them in a real deployment.
- `WhoAmI` derives a display role from MSP ID; it does not itself authorize a transaction.
- `Put` and `Get` are unrestricted temporary methods. There are no caller-role checks, attribute checks, replay rules, policy validations, revocation rules, or privacy controls in the contract yet.
- `ta1`/`rsuN` private keys generated by the CA are sensitive.
- A four-byte displayed caller hash is useful for distinguishing this test's identities but is too short for a security identifier.
- There is no gateway, external persistence service, production monitoring, or real VANET business logic in this stage.

## 11. Validation already performed

The documented entrypoint `./ledger/start.sh` was run successfully from the Windows checkout through Ubuntu WSL with Docker Desktop integration. Validation included:

- Fabric peer CLI reported version `2.5.9`.
- Dockerized Go dependency resolution, `go test ./...`, and compilation completed successfully (there are currently no Go unit test files).
- The `vanetchannel` network started with the 500 ms batch timeout.
- `vanetauth` version `1.0`, sequence `1` was committed with approvals from both `Org1MSP` and `Org2MSP`.
- All five identities were enrolled. `WhoAmI` returned `TA` for `ta1`, `RSU` for each RSU, and a distinct caller hash for each identity.
- The ledger `Put`/`Get` check wrote `hello=world` and returned `world`.
- The full startup flow ended with `SMOKE TEST PASSED`.

That validation network was left running at the time this document was written. Its state is local to that machine and is not part of the repository.

## 12. Guidance for future AI/code changes

- Read this document and `chain_structure.md` before changing the ledger design.
- Keep the implementation focused on the stated next stage unless asked to expand scope.
- Keep Fabric samples and generated certificates/private keys outside source control.
- Use `ledger/start.sh` for end-to-end startup validation; it resets demo ledger state.
- Use `ledger/chaincode/vanetauth/build.sh` for a quick Dockerized chaincode validation.
- Keep Go pinned to `1.20` unless the Fabric chaincode runtime/build image is deliberately upgraded too.
- Add authorization and identity checks in the actual contract methods; do not mistake the role string returned by `WhoAmI` for enforcement.
- When implementing the gateway, use the CA-generated identities and TLS roots described above, and never expose keystore files or demo CA secrets.
- Update this file and `README.md` when commands, ports, versions, or the contract's scope change.
