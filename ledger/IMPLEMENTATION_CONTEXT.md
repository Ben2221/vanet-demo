# VANET Fabric Ledger: Current Implementation Context

This is the handoff for the current VANET demo integration. The gateway and
chaincode use an in-memory/demo trust model; do not expose them as production
services.

## Current network and deployment

- Hyperledger Fabric 2.5 test network with Fabric CA; channel `vanetchannel`.
- Chaincode `vanetauth`, version `1.4`, currently committed at **sequence 1** on
the fresh channel created by the final bootstrap. The final source was also
committed as **version 1.4 / sequence 9** on the prior channel before that
intentional fresh reset.
- `ledger/network/VERSION` is `1.4 9`, the in-place upgrade target/release
  lineage. `deploy_cc.sh` ignores it when the channel has no committed
  `vanetauth` and deploys the final source as `1.4 / 1`; on an existing channel it
  uses the version and sequence from `VERSION` (or explicit `CC_VERSION` and
  `CC_SEQ` overrides). Since the current channel is at sequence 1, update
  `VERSION` to the next approved target (for example `1.4 2`) before upgrading
  this fresh channel.
- Sequences 4, 5, and 6 contained defective chaincode packages and should be
ignored. The corrected Stage B release was `1.2.3 / 7`, Stage C core was
`1.3 / 8`, and the final `Put`/`Get` removal was `1.4 / 9`.
- Organizations: `Org1MSP` is TA; `Org2MSP` is the RSU operator. `ta1` and
`rsu0`–`rsu15` are enrolled client identities, not separate peers. `WhoAmI`
returns `{msp, role, id}` where `id` is the certificate CommonName.
- Peer endpoints: Org1 `localhost:7051`, Org2 `localhost:9051`; orderer
`localhost:7050`; CAs use ports 7054 and 8054. The current ordering batch
timeout is `500ms`.
- Fabric samples and identity material are outside the repository at
`~/fabric/fabric-samples` (in WSL Ubuntu on Windows). A Windows gateway points
`FABRIC_HOME` at `//wsl.localhost/Ubuntu/home/<user>/fabric/fabric-samples`.

The most recent fresh bootstrap seeded config `{K:2, traceThreshold:3,
maxAuthTtlSec:3600, demoMode:true}`, policies `traffic-info` (private,
commercial, emergency), `toll` (private, commercial), and
`emergency-priority` (emergency), plus one generated root. `demo_flow.sh` and
the conformance suite were subsequently run, so the current ledger also contains
demo/test records; use the reset/bootstrap command below for a clean ledger.

## Deployed functions and intentionally skipped features

`WhoAmI` plus these 20 business functions are deployed:

- Config: `SetConfig`, `GetConfig`.
- Roots: `RegisterRoot`, `GetRoot`, `ListRoots`.
- Policies: `SetPolicy`, `GetPolicy`, `ListPolicies`.
- Authorization: `RecordAuth`, `GetAuth`, `ListAuthsSince`, `CheckAccess`.
- Reports/revocation: `ReportMisbehaviour`, `IsRevoked`,
  `ListRevokedSince`, `GetPseudonymStatus`.
- Trace core: `RequestTrace`, `ApproveTrace`, `GetTrace`, `Revoke`.

The legacy contract `Put` / `Get` functions and gateway `/kv` routes have been
removed. `ListTraces`, `RecordShareRelease`, `GetStats`, `DumpState`, and
`ResetDemoState` remain intentionally undeployed; their gateway routes return
501 `NOT_DEPLOYED`. The optional `/events/stream` endpoint is also disabled.
Trace event emission and `sharesReleased` are not part of this demo.

Fixed-shape conventions are important: array fields are always `[]`, unset
trace timestamps are `0`, and `activeAuth.pid == ""` means no active
authorization. PIDs and hashes are exactly 64 lowercase hexadecimal characters.
The contract uses Fabric transaction timestamps, not `time.Now()`. A report
range query does not include writes made in the same proposal, so its count
includes the current report explicitly; the gateway creates a fresh proposal on
MVCC/phantom-read retries.

## Repository map and run commands

- `ledger/chaincode/vanetauth/`: Go contract, fixed-schema types, helpers, and
  Go tests. Build uses Go 1.20 and the dependencies in `go.mod`.
- `ledger/network/`: network, deployment, identity enrollment, smoke, and seed
  scripts. To create a clean network with the final source as its first
  chaincode sequence, enroll identities, run the smoke test, and seed demo
  state, run from the repository root:

  ```bash
  ./ledger/network/down.sh && ./ledger/network/up.sh
  ```

  This destroys current ledger state. `up.sh` itself does not tear down an
  already-running network. For a brand-new machine, install Fabric first with
  `./ledger/network/install_fabric.sh` (or `./ledger/start.sh`).
- `ledger/gateway/`: Node.js 20+, Express REST gateway, Fabric Gateway clients,
  route groups, validators, identity configuration, and README. Run `npm ci`
  once, then `FABRIC_HOME=/path/to/fabric-samples npm start` from that directory.
  Default base URL is `http://127.0.0.1:3000`.
- `ledger/mock/mock_ledger_server.py`: FastAPI in-memory mock for the deployed
  gateway paths. Install `ledger/mock/requirements.txt`; start with
  `python ledger/mock/mock_ledger_server.py` (default port 3000, configurable
  with `PORT`). `MOCK_COMMIT_MS` defaults to 600 and is returned without a
  simulated sleep. Restarting the process clears state.
- `ledger/tests/test_conformance.py`: same HTTP conformance suite for gateway or
  mock, selected with `LEDGER` and `LEDGER_URL`.
- `ledger/demo_flow.sh`: curl demo for steps 2, 4, 5, 6, and 7 using fresh
  pseudonyms; the undeployed admin dump is omitted.
- `ledger/bench/load.js`: `RecordAuth` load generator at 5, 10, and 20 tx/s,
  30 seconds per rate.

The gateway reads certificate, private-key, and TLS-root paths from
`ledger/gateway/identities.json`; the key paths point to generated Fabric
material and private keys are read only to sign requests. The gateway does not
log or persist private keys. `X-Identity` chooses the caller and is not
authentication; only use this demo on a trusted local network.

## Gateway integration contract

Deployed paths include `/health`, `/whoami`, `/config`, `/roots`, `/policies`,
`/auth-records`, `/access-check`, `/reports`, `/pseudonyms/:pid`, `/revoked`,
`/traces`, `/snapshot`, `/chain`, and `/activity`. Trace listing, share release,
stats, admin dump/reset, and SSE remain 501 `NOT_DEPLOYED`; `/kv` no longer
exists.

Writes return `{ok, txId, blockNumber, endorseMs, commitMs, totalMs, retries,
result}`. `commitMs` is gateway wall-clock time from submit through the gateway
peer's commit-status response. Error mapping is `ERR_BAD_INPUT` 400,
`ERR_FORBIDDEN` 403, `ERR_NOT_FOUND` 404, `ERR_CONFLICT`/`TX_CONFLICT` 409,
`NOT_DEPLOYED` 501, and peer/orderer unavailable 503. Chaincode error messages
are preserved in `error.message`.

For sync, fetch `/snapshot?since=0` at startup. Then poll with
`since=<last serverTimeMs - 10000>` and merge overlap records idempotently.
Snapshot contains `revoked`, `auths`, `policies`, `roots`, `config`, `since`, and
`serverTimeMs`.

## Verification and handoff status

- Before the `1.4 / 9` deployment, `go fmt ./...`, `go build ./...`,
  `go vet ./...`, and `go test -v ./...` passed, including contract
  construction, reflection return-type checks, and the Contract API schema
  validator tests.
- Immediately after the sequence-9 commit, peer CLI `WhoAmI` passed as `ta1`
  and `rsu1`. The in-place sequence-9 gateway suite passed **27/27**.
- The corrected full `down.sh && up.sh` fresh start completed in **232.27 s**:
  final source deployed as fresh sequence 1, all five identities enrolled,
  JSON `WhoAmI` smoke checks passed, and the seed succeeded without manual
  actions.
- After restarting the gateway against the regenerated peer certificates,
  `demo_flow.sh` completed, and `LEDGER=gateway python -m pytest
  ledger/tests/test_conformance.py -q` passed **27/27** on the fresh network.
- `LEDGER=mock LEDGER_URL=http://127.0.0.1:3001 python -m pytest
  ledger/tests/test_conformance.py -q` passed **26**, skipped **1** (the mock
  does not simulate Fabric MVCC report retries). Trace approval concurrency ran.
- Stage C benchmark at the prior 500 ms batch timeout: 5 tx/s achieved 5.00
  (p50 346 ms, p95 553 ms), 10 tx/s achieved 10.00 (p50 324 ms, p95 546 ms),
  and 20 tx/s achieved 20.00 (p50 255 ms, p95 491 ms); all had zero failures
  and retries. These measurements preceded the final cleanup and fresh reset.

The fresh Fabric network and gateway are running. The mock was tested on port
3001 so it did not replace the gateway on port 3000.
