# VANET ledger REST gateway

This is a demo gateway for the committed Fabric chaincode definition,
`vanetauth` (version `1.4`, sequence `1` on the current fresh channel) on
`vanetchannel`. It uses one Fabric Gateway connection for each identity in
`identities.json` and selects the caller
with `X-Identity`. The Stage C core adds fixed-shape trace requests, approvals,
reads, and one-time TA revocation.

## Setup and start

Requirements: Node.js 20 or newer, npm, and the Fabric network already running.
From the repository root, create a fresh demo network, deploy the final chaincode
as sequence 1, enroll identities, run the smoke check, and apply the seed with:

```bash
./ledger/network/down.sh && ./ledger/network/up.sh
```

This is destructive and resets ledger state. `up.sh` does not tear down an
already-running network. For installation details, see
`ledger/IMPLEMENTATION_CONTEXT.md`.

From `ledger/gateway`, install dependencies once and start the server:

```bash
npm ci
FABRIC_HOME=/path/to/fabric-samples npm start
```

The server listens on `http://127.0.0.1:3000` by default. For the current
Windows checkout where Fabric material is in WSL Ubuntu, Git Bash can use:

```bash
FABRIC_HOME=//wsl.localhost/Ubuntu/home/septhis/fabric/fabric-samples npm start
```

Or from PowerShell:

```powershell
$env:FABRIC_HOME = '\\wsl.localhost\Ubuntu\home\septhis\fabric\fabric-samples'
npm start
```

Change `FABRIC_HOME` to the actual Fabric samples directory on your machine.
The default identity paths in `identities.json` are relative to
`FABRIC_HOME`; `IDENTITIES_FILE` can point at another JSON file with the same
schema. `PORT`, `HOST`, `CHANNEL`, and `CC_NAME` can override the defaults.
Set `HOST=0.0.0.0` only when another machine must reach the demo gateway.

`identities.json` contains certificate, keystore-directory, peer, and TLS-root
paths, not private key material. Each configured keystore directory must
contain exactly one `_sk` file. The gateway reads that key into memory to sign
Fabric requests and never logs it. Do not commit generated keys or certificates.

## Identity and trust boundary

Pass `ta1` or one of `rsu0`–`rsu15` in `X-Identity` (the list is `RSU_IDS` in
`ledger/network/env.sh`). When the
header is omitted, TA-only routes default to `ta1` and other routes default to
`rsu1`. An unknown identity returns 400. This is **not authentication**: a
caller who can reach this demo gateway can select `ta1` in the header. Keep it
on a trusted local/demo network; do not expose it as a production service.

## Deployed endpoints

| Method and path | Behavior |
|---|---|
| `GET /health` | Evaluates `WhoAmI`; returns 503 if Fabric is unreachable |
| `GET /whoami` | Evaluates deployed `WhoAmI` and returns `{msp, role, id}` using the certificate CommonName |
| `GET /config`, `PUT /config` | Deployed `GetConfig` / TA-only `SetConfig` |
| `POST /roots`, `GET /roots`, `GET /roots/:epoch` | Deployed root registration and queries |
| `PUT /policies/:service`, `GET /policies`, `GET /policies/:service` | Deployed TA-only policy update and queries |
| `POST /auth-records`, `GET /auth-records/:pid`, `GET /auth-records?since=` | Deployed RSU auth writes and active-auth queries |
| `GET /access-check?pid=&class=&service=` | Deployed policy, revocation, and auth status decision |
| `POST /reports`, `GET /pseudonyms/:pid`, `GET /revoked?since=`, `GET /revoked/:pid` | Deployed report and revocation functions |
| `POST /traces`, `GET /traces/:id`, `POST /traces/:id/approve`, `POST /traces/:id/revoke` | Deployed Stage C trace core |
| `GET /traces?status=`, `POST /traces/:id/shares` | Intentionally not deployed; return 501 `NOT_DEPLOYED` |
| `GET /snapshot?since=0` | Parallel full/incremental sync snapshot |
| `GET /events/stream` | Intentionally disabled; returns 501 `NOT_DEPLOYED` |
| `GET /stats`, `GET /admin/dump`, `POST /admin/reset` | Intentionally not deployed; return 501 `NOT_DEPLOYED` |
| `GET /chain` | Queries Fabric's `qscc.GetChainInfo` and decodes height/hash |
| `GET /activity?limit=50` | Reads the in-memory ring buffer (up to 200 writes) |

Successful writes return `txId`, numeric `blockNumber`, `endorseMs`,
`commitMs`, `totalMs`, `retries`, and `result`. MVCC and phantom-read commit
conflicts are retried at most three times with a fresh proposal on each attempt;
remaining conflicts return 409 `TX_CONFLICT`.

Example calls (run in another terminal):

```bash
curl -i http://127.0.0.1:3000/health
curl -i -H 'X-Identity: rsu2' http://127.0.0.1:3000/whoami

curl -i http://127.0.0.1:3000/chain
curl -i 'http://127.0.0.1:3000/activity?limit=10'
```

Chaincode-backed routes that target a function not deployed return HTTP 501
with `{"ok":false,"error":{"code":"NOT_DEPLOYED"}}`. Other chaincode errors
map to their planned HTTP status and retain the chaincode message; gateway
validation errors return 400 and caller-role failures return 403.

The deployed Stage C core is `RequestTrace`, `ApproveTrace`, `GetTrace`, and
`Revoke`. `ListTraces`, `RecordShareRelease`, `GetStats`, `DumpState`, and
`ResetDemoState` are intentionally omitted and their chaincode-dependent routes
return 501 `NOT_DEPLOYED`. The optional `/events/stream` is also disabled in this
demo scope. `/snapshot` aggregates config, roots, policies, auths, and
revocations. The legacy `Put` / `Get` contract functions and `/kv` routes have
been removed.

## Conformance tests

With the gateway running and the Fabric network available, run from the
repository root:

```bash
LEDGER=gateway python -m pytest ledger/tests/test_conformance.py -q
```

The suite covers Stage A/B identity, auth, report, and revocation behavior, plus
the deployed trace state machine, concurrent approvals, snapshot sync, and
intentionally unavailable routes. The same suite can target the in-memory mock
with `LEDGER=mock LEDGER_URL=http://127.0.0.1:3001`; see `ledger/mock/README.md`.

## Integration handoff

- **Base URL:** `http://127.0.0.1:3000` (`npm start` from `ledger/gateway`).
- **Caller header:** set `X-Identity` to `ta1` or one of `rsu0`–`rsu15`. This selects a demo identity; it is not authentication.
- **Write response:** `{ok, txId, blockNumber, endorseMs, commitMs, totalMs,
  retries, result}`. `commitMs` is gateway wall-clock time from transaction
  submission until the gateway peer reports commit status; it is not simulated
  time or block time.
- **Errors:** `ERR_BAD_INPUT` 400, `ERR_FORBIDDEN` 403, `ERR_NOT_FOUND` 404,
  `ERR_CONFLICT`/`TX_CONFLICT` 409, `NOT_DEPLOYED` 501, and unavailable peer or
  orderer 503. Chaincode errors retain their own message in `error.message`.
- **Snapshot sync:** fetch `/snapshot?since=0` at startup. Then poll using
  `since=<last serverTimeMs - 10000>` to retain a ten-second overlap; merge by
  pid/service/epoch so the overlap is idempotent.
- **PID format:** exactly 64 lowercase hexadecimal characters.
- **No active authorization:** `activeAuth` is a fixed-shape zero-value object;
  `activeAuth.pid == ""` means there is no active authorization.

```bash
curl -H 'X-Identity: rsu1' http://127.0.0.1:3000/snapshot?since=0
```
