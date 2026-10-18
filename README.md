# BTP: Network Simulation Using NS-3

## Overview

This repository contains the implementation and documentation for our Bachelor Thesis Project (BTP), focused on network simulation using NS-3. It also contains the Hyperledger Fabric ledger setup for the VANET demo, defined in `ledger/` and planned in `chain_structure.md`. For detailed ledger architecture, operation, validation, and AI handoff context, see [`ledger/IMPLEMENTATION_CONTEXT.md`](ledger/IMPLEMENTATION_CONTEXT.md).

## Objectives

- Design and implement network simulation scenarios using NS-3.
- Configure network protocols, traffic patterns, and simulation parameters.
- Evaluate network performance using appropriate metrics.
- Analyse results and document findings.

## Technology Stack

- **Network simulator:** NS-3
- **Programming language:** C++
- **Ledger:** Hyperledger Fabric 2.5
- **Version control:** Git and GitHub

## Fabric prerequisites

- Linux or WSL2 (Ubuntu 22.04+ recommended) with Docker Engine access. On Windows, install Docker Desktop and enable WSL integration for the Ubuntu distribution.
- Docker Compose v2 and `curl`. The Fabric installer adds a private `jq` binary under `~/.local/bin` if needed.
- About 8 GB of memory available to Docker and 10 GB of free disk space.

Go is not required on the host: chaincode dependency resolution, testing, compilation, and Fabric's chaincode packaging commands use the pinned `golang:1.20` Docker image through a small `go` shim installed under `~/.local/bin`. The Fabric installer downloads Fabric 2.5.9 binaries, samples, and images outside this repository to `~/fabric/` by default.

## Start the ledger

From the repository root in a Linux/WSL bash shell, start the complete chain with one command:

```bash
./ledger/start.sh
```

`ledger/start.sh` installs Fabric tools on the first run, then builds the chaincode in Docker, starts the sample Fabric CA network, creates `vanetchannel`, deploys `vanetauth`, enrolls the demo identities (`ta1` and `rsu1`–`rsu4`), and runs the `WhoAmI` smoke test. The installer skips the Fabric download when it is already present. Each start recreates the test network and clears its ledger state. The default orderer batch timeout is 500 ms; override it with, for example, `BATCH_TIMEOUT=2s ./ledger/start.sh`.

The default Fabric location is `~/fabric/fabric-samples`. To install elsewhere, set `FABRIC_INSTALL_ROOT=/path/to/fabric`; samples are placed under its `fabric-samples/` directory. `FABRIC_HOME` may also point directly to an existing `fabric-samples` directory. See `ledger/network/env.sh` for identity and peer CLI helpers.

To stop the network and remove its generated network artifacts:

```bash
./ledger/network/down.sh
```

This intentionally does not run a global Docker volume prune, so unrelated Docker data is left untouched. `up.sh` recreates the Fabric test network. Demo CA passwords in `enroll_identities.sh` are not production credentials; do not reuse them outside this local test environment.

## Chaincode iteration

```bash
./ledger/chaincode/vanetauth/build.sh
CC_VERSION=1.1 CC_SEQ=2 ./ledger/network/deploy_cc.sh
```

Increase the sequence by exactly one for each chaincode definition upgrade. The current version and sequence are recorded in `ledger/network/VERSION`.
