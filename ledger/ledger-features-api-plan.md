# VANET Ledger: Feature List and API Implementation Plan

Stage 2 of the blockchain work (Person 2). Stage 1 (network, channel, identities, chaincode skeleton) is done.
This document has three parts:

1. **What the chain must support**, extracted from the review slides and the team work-split document
2. **The design**: data model, chaincode functions, REST endpoints
3. **The build plan**: order of work, tests, demo mapping

Scope stays demo-minimal: simple state, no pagination machinery, no extra services.

---

## Part 1: Feature inventory (what the documents require)

### 1.1 Sources used

| Source | What it contributes to the chain |
|---|---|
| Work split, *Person 2* section | chaincode function list, caller rules, gateway REST, mock ledger, sync, benchmark, should/could items |
| Work split, *Shared foundations* | LedgerAPI interface (#4): REST + JSON, every write returns transaction ID and measured commit time; "simulated time vs realtime" rule; mock ledger in week 1 |
| Work split, *Person 3* section | RSU checks Merkle path against the **root**; policy and revocation read from **local copy**; `RecordAuth` after authentication; handover checks the shared authorization record; threshold identity escrow gated by `GetTrace` |
| Work split, *Person 4* section | "time from first report to revocation", "honest vehicles wrongly revoked", commit latency and throughput, privacy measure (sessions per pseudonym) |
| Work split, *Demo script and definition of done* | demo steps 1, 2, 5, 6, 7 touch the ledger directly; "no real identity on the ledger" |
| Slides: *Permissioned Blockchain, Why It Fits* | smart-contract role: check service policy, check revocation state, record authorization and revocation events |
| Slides: *Underlying Relations* | block-hash linkage; threshold agreement; access predicate `Access(v,svc)=1 ⇔ Verify(π,y)=1 ∧ pid∉RL ∧ Policy(attr(v),svc)=allow`; only the decision reaches the ledger |
| Slides: *Operational Lifecycle* | registration → authentication → handover; new RSU queries shared state instead of full registration |
| Slides: *Security Architecture* | unauthorized access → contract policy; malicious vehicle → revocation + traceability; ledger tampering and RSU compromise → permissioned shared state |
| Slides: *Experimental Setup* | metrics the ledger must help produce: handover latency, storage overhead, scalability with vehicle count |

### 1.2 Feature list

Priority: **M** = must for the demo, **S** = should, **X** = out of scope (listed so nobody builds it by accident).

| ID | Feature | Pri | Needed because | Delivered by (chaincode / endpoint) |
|---|---|---|---|---|
| F1 | Epoch Merkle root anchor (registration proof of existence, no identities) | M | RSU verifies membership against the root; demo step 2 | `RegisterRoot`, `GetRoot`, `ListRoots` |
| F2 | Per-service policy: which vehicle classes may use a service | M | "service its class may not use", "class it does not have" tests; contract predicate | `SetPolicy`, `GetPolicy`, `ListPolicies` |
| F3 | Authorization record for handover | M | handover accepted without a full re-check | `RecordAuth`, `GetAuth`, `ListAuthsSince` |
| F4 | Access-decision predicate (revocation + policy + active auth) | S | slide predicate; audit and conformance tests | `CheckAccess` |
| F5 | Misbehaviour reports with automatic revocation at K distinct RSUs | M | demo step 5 | `ReportMisbehaviour` |
| F6 | Revocation list and revocation checks | M | every RSU must reject a revoked pseudonym | `IsRevoked`, `ListRevokedSince` |
| F7 | Pseudonym status with report timing | S | metric "time from first report to revocation" | `GetPseudonymStatus` |
| F8 | Conditional traceability: open request, collect approvals, threshold | M | demo step 6 | `RequestTrace`, `ApproveTrace`, `GetTrace`, `ListTraces` |
| F9 | TA revokes all of a vehicle's pseudonyms after an approved trace | M | demo step 6 | `Revoke` |
| F10 | Audit record that an RSU released its escrow key share | S | "enforced identity reveal" | `RecordShareRelease` |
| F11 | Caller rules from the client identity (TA vs RSU) | M | demo step 7; "done when" test | all write functions |
| F12 | Measured commit time on every write | M | LedgerAPI rule; simulated-time bridge | gateway write envelope |
| F13 | RSU cache sync | M | revocation reaches every RSU | `GET /snapshot`, optional event stream |
| F14 | No real identity on the ledger, and a way to show it | M | definition of done; demo step 2 | input validation, `DumpState`, `GET /admin/dump` |
| F15 | Ledger statistics (record counts, bytes) | S | "storage overhead", "scalability" metrics | `GetStats`, `GET /stats` |
| F16 | Runtime config: K, trace threshold, auth TTL | M | team decides K and threshold in week 1 | `SetConfig`, `GetConfig` |
| F17 | Benchmark support (commit latency, throughput, batch-timeout effect) | M | Person 2 results go to Person 4 | `bench/load.js` using the same endpoints |
| F18 | Mock ledger with identical API and caller rules | M | Persons 1, 3, 4 build against it first | `mock_ledger.py` |
| F19 | Demo support: activity feed, chain height, health | S | demo step 1 and 7; optional demo page | `/activity`, `/chain`, `/health` |
| F20 | Experiment reset between runs | S | Person 4 runs many sweeps on one network | `ResetDemoState`, `POST /admin/reset` |
| X1 | Fabric 3.x SmartBFT ordering | X | extension only | none |
| X2 | Private data collections | X | extension only | none |
| X3 | On-chain ZKP verification or Merkle verification | X | proof check stays at the RSU edge ("proof verification stays at the edge") | none |
| X4 | Storing identity, escrow ciphertext or key shares on-chain | X | identity must never be on the ledger | none |

---

## Part 2: Design

### 2.1 Conventions (agree once, then freeze in `docs/interfaces.md`)

| Item | Decision |
|---|---|
| `pid` (pseudonym ID) | 64 lowercase hex chars = SHA-256 of the compressed secp256k1 pseudonym public key. Same value is used everywhere (no separate `pidHash`). **Person 3 must confirm.** |
| `merkleRoot`, `evidenceHash` | 64 lowercase hex chars |
| `epoch` | non-negative integer |
| `service`, `class` | `^[a-z0-9][a-z0-9-]{0,31}$`. Demo classes: `private`, `commercial`, `emergency`. Demo services: `traffic-info`, `toll`, `emergency-priority` |
| `reqId` | `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` |
| time | unix **milliseconds** (integer). Taken from the transaction timestamp inside the chaincode, never `time.Now()` |
| caller role | `Org1MSP` ⇒ `TA`, `Org2MSP` ⇒ `RSU`. Anything else is forbidden |
| caller ID (`rsuId`) | the certificate **CommonName** (the enrollment ID, for example `rsu1`, `ta1`). Read it from `ctx.GetClientIdentity().GetX509Certificate().Subject.CommonName`. This replaces the hashed ID used in the skeleton's `WhoAmI` |
| chaincode arguments | all arguments are strings. Numbers are parsed with `strconv`. Arrays are passed as JSON strings and parsed inside the chaincode |
| chaincode errors | `fmt.Errorf("<CODE>: message")` with codes `ERR_BAD_INPUT`, `ERR_FORBIDDEN`, `ERR_NOT_FOUND`, `ERR_CONFLICT`. The gateway maps the code to an HTTP status |
| defaults | `K = 2`, `traceThreshold = 3` (with 4 enrolled RSUs this is 2f+1 for f = 1), `maxAuthTtlSec = 3600`, `demoMode = true` |

### 2.2 Data model (world state)

All object keys except `config` are composite keys created with `CreateCompositeKey(type, attrs)`, so listing is a clean `GetStateByPartialCompositeKey`.

| Key | Attributes | JSON value |
|---|---|---|
| `config` (plain key) | none | `{K, traceThreshold, maxAuthTtlSec, demoMode}` |
| `root` | `[epoch padded to 10 digits]` | `{epoch, merkleRoot, validUntil, registeredTs}` |
| `policy` | `[service]` | `{service, classes[], updatedTs}` |
| `auth` | `[pid]` | `{pid, service, class, expiry, rsuId, firstTs, ts, sessionCount}` |
| `rep` | `[pid, rsuId]` | `{pid, rsuId, evidenceHash, attackType, ts}` |
| `rev` | `[pid]` | `{pid, reason, reporters[], firstReportTs, revokedTs, source}` where `source` is `AUTO_REPORTS` or `TRACE` and, for `TRACE`, `reqId` is also set |
| `trace` | `[reqId]` | `{reqId, pid, reason, requester, status, threshold, approvals[], sharesReleased[], revokedPids[], createdTs, approvedTs, executedTs}` with `status` in `PENDING`, `APPROVED`, `EXECUTED` |

Rules:

- `ts` fields come from the transaction timestamp, so all endorsers agree.
- `sessionCount` increments each time an RSU re-records the same pid. Person 4 uses it for the "sessions linked per pseudonym" privacy measure.
- `rev.reporters` holds RSU enrollment IDs only. No vehicle identity is ever stored.
- No function accepts free-form text longer than 128 characters (`reason`, `attackType`).

### 2.3 Chaincode layout

```
ledger/chaincode/vanetauth/
  main.go
  types.go        structs and constants
  helpers.go      caller, role checks, time, validation, error helpers, key helpers
  config.go       SetConfig, GetConfig
  roots.go        RegisterRoot, GetRoot, ListRoots
  policy.go       SetPolicy, GetPolicy, ListPolicies
  auth.go         RecordAuth, GetAuth, ListAuthsSince, CheckAccess
  revocation.go   ReportMisbehaviour, IsRevoked, ListRevokedSince, GetPseudonymStatus
  trace.go        RequestTrace, ApproveTrace, GetTrace, ListTraces, RecordShareRelease, Revoke
  ops.go          GetStats, DumpState, ResetDemoState, WhoAmI
```

`helpers.go` essentials:

```go
type Caller struct{ MSP, ID, Role string }

func getCaller(ctx contractapi.TransactionContextInterface) (Caller, error) {
	ci := ctx.GetClientIdentity()
	msp, err := ci.GetMSPID()
	if err != nil { return Caller{}, err }
	cert, err := ci.GetX509Certificate()
	if err != nil { return Caller{}, err }
	c := Caller{MSP: msp, ID: cert.Subject.CommonName}
	switch msp {
	case "Org1MSP": c.Role = "TA"
	case "Org2MSP": c.Role = "RSU"
	}
	return c, nil
}

func requireRole(ctx contractapi.TransactionContextInterface, roles ...string) (Caller, error) {
	c, err := getCaller(ctx)
	if err != nil { return c, err }
	for _, r := range roles { if c.Role == r { return c, nil } }
	return c, errf("ERR_FORBIDDEN", "%s (%s) may not call this function", c.ID, c.Role)
}

func nowMs(ctx contractapi.TransactionContextInterface) int64 {
	t, _ := ctx.GetStub().GetTxTimestamp()
	return t.Seconds*1000 + int64(t.Nanos)/1e6
}
```

Validators (regex): `reHex64`, `reName`, `reReqID`. Reject any argument containing `\x00` or `\U0010FFFF`, because those characters are used by composite keys.

### 2.4 Chaincode function specification

Legend: **Caller** = who may invoke. **Type** = `submit` (changes state) or `evaluate` (read only, no block).

#### Config

| Function | Caller | Type |
|---|---|---|
| `SetConfig(K, traceThreshold, maxAuthTtlSec, demoMode)` | TA | submit |
| `GetConfig()` | any | evaluate |

- Validate `1 ≤ K ≤ 10`, `1 ≤ traceThreshold ≤ 10`, `60 ≤ maxAuthTtlSec ≤ 86400`.
- `GetConfig` returns the defaults from §2.1 when nothing has been set, so the system works without calling `SetConfig`.
- Changes affect only future reports and future trace requests. A trace stores the threshold it was opened with.

#### Roots (F1)

| Function | Caller | Type |
|---|---|---|
| `RegisterRoot(epoch, merkleRoot, validUntil)` | TA | submit |
| `GetRoot(epoch)` | any | evaluate |
| `ListRoots()` | any | evaluate |

- `RegisterRoot`: validate hex64, `validUntil > now`; reject if the epoch already exists (`ERR_CONFLICT`). Roots are append-only and never overwritten.
- `ListRoots` returns all roots with `validUntil > now`, ordered by epoch. RSUs cache this list.

#### Policy (F2)

| Function | Caller | Type |
|---|---|---|
| `SetPolicy(service, classesJson)` | TA | submit |
| `GetPolicy(service)` | any | evaluate |
| `ListPolicies()` | any | evaluate |

- `classesJson` is a JSON array such as `["private","commercial"]`. Each class is validated with `reName`; duplicates are removed.
- An empty array is allowed and means "nobody may use this service".
- `SetPolicy` overwrites (idempotent).

#### Authorization records (F3, F4)

| Function | Caller | Type |
|---|---|---|
| `RecordAuth(pid, service, class, expiry)` | RSU | submit |
| `GetAuth(pid)` | any | evaluate |
| `ListAuthsSince(sinceMs)` | any | evaluate |
| `CheckAccess(pid, class, service)` | any | evaluate |

`RecordAuth` steps:

1. `requireRole(RSU)`; validate inputs.
2. Reject if `rev[pid]` exists (`ERR_CONFLICT: pseudonym revoked`).
3. Load `policy[service]`; reject if missing (`ERR_NOT_FOUND`) or if `class` is not in it (`ERR_FORBIDDEN: class not allowed for service`).
4. Require `now < expiry ≤ now + maxAuthTtlSec*1000`.
5. Read the existing `auth[pid]`. If present, keep `firstTs` and set `sessionCount += 1`; otherwise `firstTs = now`, `sessionCount = 1`.
6. Write `auth[pid]` with `rsuId = caller.ID`. Return the stored record.

`GetAuth` returns the record only if it exists, `expiry > now` and the pid is not revoked; otherwise `ERR_NOT_FOUND`. This is "the active authorization, if any".

`ListAuthsSince` scans `auth`, filters `ts ≥ sinceMs`, returns at most 1000 records, active ones only.

`CheckAccess` returns `{allow, reasons[], activeAuth}`. Reason codes: `REVOKED`, `NO_POLICY`, `CLASS_NOT_ALLOWED`, `NO_ACTIVE_AUTH` (informational, does not flip `allow`). This is the slide predicate minus the proof check, which stays at the RSU.

#### Misbehaviour and revocation (F5, F6, F7)

| Function | Caller | Type |
|---|---|---|
| `ReportMisbehaviour(pid, evidenceHash, attackType)` | RSU | submit |
| `IsRevoked(pid)` | any | evaluate |
| `ListRevokedSince(sinceMs)` | any | evaluate |
| `GetPseudonymStatus(pid)` | any | evaluate |

`ReportMisbehaviour` steps:

1. `requireRole(RSU)`; validate `pid`, `evidenceHash` (hex64), `attackType` (optional, `reName`).
2. If `rev[pid]` exists, return `{alreadyRevoked: true}` and write nothing. This keeps RSUs with a stale cache from getting errors.
3. If `rep[pid, caller.ID]` exists, return `{duplicate: true, reportCount}` and write nothing. One RSU can never count twice.
4. Write `rep[pid, caller.ID]`.
5. Count reports: iterate `GetStateByPartialCompositeKey("rep", [pid])` and add 1 for the report just written (a range query does **not** see writes made in the same transaction).
6. If `count ≥ K`: write `rev[pid]` with `source = AUTO_REPORTS`, `reporters`, `firstReportTs` (earliest report ts), `revokedTs = now`; call `SetEvent("PseudonymRevoked", {pid, revokedTs})`.
7. Return `{pid, reportCount, K, revoked, newlyRevoked}`.

Concurrency note: two RSUs reporting the same pid at once cause one transaction to fail with a phantom-read conflict (the range query changed). This is expected and correct. The gateway retries (see §2.6).

`GetPseudonymStatus` returns `{pid, revoked, revokedTs, reportCount, reporters[], firstReportTs, activeAuth}`. Person 4 gets time-to-revocation as `revokedTs − firstReportTs`.

`ListRevokedSince` scans `rev` and filters `revokedTs ≥ sinceMs`, up to 1000 records.

#### Traceability (F8, F9, F10)

| Function | Caller | Type |
|---|---|---|
| `RequestTrace(reqId, pid, reason)` | RSU or TA | submit |
| `ApproveTrace(reqId)` | RSU | submit |
| `GetTrace(reqId)` | any | evaluate |
| `ListTraces(status)` | any | evaluate |
| `RecordShareRelease(reqId)` | RSU | submit |
| `Revoke(reqId, pidsJson, reason)` | TA | submit |

State machine:

```
RequestTrace ──► PENDING ──(approvals ≥ threshold)──► APPROVED ──Revoke──► EXECUTED
                  ▲ ApproveTrace (distinct RSUs only)       ▲ RecordShareRelease (audit only)
```

- `RequestTrace`: pid must be revoked (`ERR_CONFLICT` otherwise); `reqId` must be new. Store `threshold = config.traceThreshold` at creation, `requester = caller.ID`.
- `ApproveTrace`: status must be `PENDING`; `caller.ID` must not already be in `approvals` (`ERR_CONFLICT`). Append; when `len(approvals) ≥ threshold`, set `APPROVED`, `approvedTs`, and `SetEvent("TraceApproved", {reqId, pid})`. The requester does not count as an approval unless it also calls `ApproveTrace`.
- `RecordShareRelease`: status must be `APPROVED` or `EXECUTED`; append `caller.ID` to `sharesReleased` (no duplicates). It is an audit entry only. The actual key share never touches the ledger.
- `Revoke`: caller TA; status must be `APPROVED` (`ERR_CONFLICT` if `PENDING` or already `EXECUTED`); `pidsJson` must contain the traced pid, have at most 200 entries, and each must pass hex64. Write a `rev` record (`source = TRACE`, `reqId`) for every pid not already revoked; set status `EXECUTED`, `revokedPids`, `executedTs`; `SetEvent("TraceExecuted", {reqId, count})`. A trace can be used once, so one approved trace cannot revoke arbitrary pseudonyms later.
- `ListTraces(status)`: empty `status` means all.

#### Operations (F14, F15, F20)

| Function | Caller | Type |
|---|---|---|
| `GetStats()` | any | evaluate |
| `DumpState()` | TA | evaluate |
| `ResetDemoState()` | TA | submit |
| `WhoAmI()` | any | evaluate |

- `GetStats`: per object type, the count and total value bytes; plus a grand total. Feeds the storage-overhead metric.
- `DumpState`: every key and value (max 5000), for showing reviewers that no real identity is stored.
- `ResetDemoState`: only if `config.demoMode` is true. Deletes up to 500 keys per call (everything except `config`) and returns `{deleted, remaining}`. The gateway loops until `remaining = 0`. The block history is not erased; only world state is.
- `WhoAmI` now returns `{msp, role, id}` where `id` is the certificate CN.

### 2.5 Access matrix

| Function group | TA | RSU | Anyone (any enrolled client) |
|---|---|---|---|
| `SetConfig`, `RegisterRoot`, `SetPolicy`, `Revoke`, `DumpState`, `ResetDemoState` | yes | no | no |
| `RecordAuth`, `ReportMisbehaviour`, `ApproveTrace`, `RecordShareRelease` | no | yes | no |
| `RequestTrace` | yes | yes | no |
| All `Get*`, `List*`, `IsRevoked`, `CheckAccess`, `WhoAmI` | yes | yes | yes |

### 2.6 Gateway design

Stack: Node.js, Express, `@hyperledger/fabric-gateway`, `@grpc/grpc-js`.

```
ledger/gateway/
  server.js          app setup, routes mounted, error handler
  config.js          env vars and identities.json loader
  fabricClient.js    connections, evaluate(), submit() with timing and retry
  errors.js          chaincode error to HTTP mapping
  validators.js      same regex rules as the chaincode (fail fast with 400)
  activityLog.js     in-memory ring buffer of recent writes
  routes/            config.js roots.js policies.js auth.js reports.js traces.js snapshot.js ops.js
  identities.json    name -> { mspId, certPath, keyPath, peerEndpoint, tlsCertPath, hostAlias }
```

**Identity selection:** header `X-Identity: rsu2`. Missing header defaults to `ta1` for admin routes and `rsu1` otherwise. At startup the gateway opens one gRPC client and one `Gateway` per identity in `identities.json`. Unknown names return 400. No real authentication; the report must say that this is a demo trust boundary.

**Write path** (this produces `commitMs`):

```js
async function submit(identity, fn, args) {
  for (let attempt = 0; attempt <= 3; attempt++) {
    const t0 = Date.now();
    const proposal = contract(identity).newProposal(fn, { arguments: args });
    const tx = await proposal.endorse();            // chaincode errors surface here
    const t1 = Date.now();
    const sent = await tx.submit();
    const status = await sent.getStatus();           // waits for the commit
    const t2 = Date.now();
    if (status.successful) {
      return { txId: status.transactionId, blockNumber: Number(status.blockNumber),
               endorseMs: t1 - t0, commitMs: t2 - t1, totalMs: t2 - t0,
               retries: attempt, result: parse(tx.getResult()) };
    }
    // validation codes: 11 = MVCC_READ_CONFLICT, 12 = PHANTOM_READ_CONFLICT
    if (![11, 12].includes(status.code) || attempt === 3) throw commitError(status);
    await sleep(50 + Math.random() * 100 * (attempt + 1));   // new proposal each retry
  }
}
```

`commitMs` is the time from handing the endorsed transaction to the orderer until the commit status arrives. Report `endorseMs` and `totalMs` as well. Reads use `proposal.evaluate()` and return `queryMs`.

**Response envelopes**

Write success: `{ "ok": true, "txId": "...", "blockNumber": 12, "endorseMs": 140, "commitMs": 610, "totalMs": 750, "retries": 0, "result": { ... } }`

Read success: `{ "ok": true, "queryMs": 8, "result": { ... } }`

Error: `{ "ok": false, "error": { "code": "ERR_FORBIDDEN", "message": "rsu1 (RSU) may not call this function" } }`

**Error mapping**

| Chaincode code or failure | HTTP |
|---|---|
| `ERR_BAD_INPUT` or gateway validation failure | 400 |
| `ERR_FORBIDDEN` | 403 |
| `ERR_NOT_FOUND` | 404 |
| `ERR_CONFLICT` | 409 |
| conflict persisting after retries | 409 with `code: "TX_CONFLICT"` |
| peer or orderer unreachable, timeout | 503 |
| anything else | 500 |

The gateway finds the code by matching `ERR_[A-Z_]+` in the endorse error message or its `details`.

**Timeouts:** evaluate 5 s, endorse 15 s, submit 5 s, commit status 60 s.

**Activity log:** every successful and failed write is pushed to a ring buffer of 200 entries `{ts, identity, fn, txId, blockNumber, commitMs, ok, code}`. This feeds `/activity` for the demo page.

### 2.7 REST endpoint specification

Base URL `http://localhost:3000`. Header `X-Identity` selects the caller. All bodies are JSON.

#### System

| Method and path | Identity | Chaincode | Notes |
|---|---|---|---|
| `GET /health` | any | `WhoAmI` | returns `{gateway: "up", chaincode: "ok", identity}`; 503 if the peer is unreachable |
| `GET /whoami` | any | `WhoAmI` | shows role and ID for the chosen identity |
| `GET /config` | any | `GetConfig` | |
| `PUT /config` | TA | `SetConfig` | body `{K, traceThreshold, maxAuthTtlSec, demoMode}` |

#### Roots and policies

| Method and path | Identity | Chaincode | Body or query |
|---|---|---|---|
| `POST /roots` | TA | `RegisterRoot` | `{epoch, merkleRoot, validUntil}` |
| `GET /roots` | any | `ListRoots` | |
| `GET /roots/:epoch` | any | `GetRoot` | |
| `PUT /policies/:service` | TA | `SetPolicy` | `{classes: ["private","commercial"]}` |
| `GET /policies` | any | `ListPolicies` | |
| `GET /policies/:service` | any | `GetPolicy` | |

#### Authorization

| Method and path | Identity | Chaincode | Body or query |
|---|---|---|---|
| `POST /auth-records` | RSU | `RecordAuth` | `{pid, service, class, expiry}` |
| `GET /auth-records/:pid` | any | `GetAuth` | 404 when none is active |
| `GET /auth-records?since=` | any | `ListAuthsSince` | |
| `GET /access-check?pid=&class=&service=` | any | `CheckAccess` | |

#### Misbehaviour and revocation

| Method and path | Identity | Chaincode | Body or query |
|---|---|---|---|
| `POST /reports` | RSU | `ReportMisbehaviour` | `{pid, evidenceHash, attackType?}` |
| `GET /pseudonyms/:pid` | any | `GetPseudonymStatus` | |
| `GET /revoked?since=` | any | `ListRevokedSince` | |
| `GET /revoked/:pid` | any | `IsRevoked` | `{revoked: true/false}` |

#### Traces

| Method and path | Identity | Chaincode | Body or query |
|---|---|---|---|
| `POST /traces` | RSU or TA | `RequestTrace` | `{reqId, pid, reason}` |
| `GET /traces?status=` | any | `ListTraces` | |
| `GET /traces/:id` | any | `GetTrace` | |
| `POST /traces/:id/approve` | RSU | `ApproveTrace` | no body |
| `POST /traces/:id/shares` | RSU | `RecordShareRelease` | no body |
| `POST /traces/:id/revoke` | TA | `Revoke` | `{pids: [...], reason}` |

This replaces the earlier idea of a standalone `POST /revocations`, so that `Revoke` is always tied to an approved trace.

#### Sync, metrics and demo support

| Method and path | Identity | Source | Notes |
|---|---|---|---|
| `GET /snapshot?since=` | any | `ListRevokedSince`, `ListAuthsSince`, `ListPolicies`, `ListRoots`, `GetConfig` (parallel evaluates) | `{serverTimeMs, since, revoked[], auths[], policies[], roots[], config}`. `since=0` returns everything |
| `GET /events/stream` (optional) | any | chaincode event listener | Server-Sent Events for `PseudonymRevoked`, `TraceApproved`, `TraceExecuted` |
| `GET /stats` | any | `GetStats` | record counts and bytes |
| `GET /chain` | any | `qscc` `GetChainInfo` | block height and current hash; decode with `@hyperledger/fabric-protos` |
| `GET /activity?limit=` | any | gateway ring buffer | recent writes with timings |
| `GET /admin/dump` | TA | `DumpState` | |
| `POST /admin/reset` | TA | `ResetDemoState` in a loop | returns total deleted |

**Pagination:** none. Lists cap at 1000 items. That is far more than the demo needs.

### 2.8 How RSU caches stay in sync (the contract with Person 1)

1. At startup each RSU app calls `GET /snapshot?since=0` and builds its local copy of revocations, authorizations, policies, roots and config.
2. Every 1 simulated second it calls `GET /snapshot?since=<lastServerTimeMs − 10000>` and merges by `pid` / `service` / `epoch`. The 10-second overlap covers transactions that were created before the previous poll but committed after it. Merging is idempotent, so the overlap is harmless.
3. When an RSU writes, it applies the write to its **own** cache immediately, and other RSUs see it after `commitMs` of simulated time (the rule in the work-split document).
4. Reads never call the gateway during a vehicle's authentication; they use the cache.

### 2.9 Mock ledger parity (F18)

`ledger/mock_ledger.py` implements the same functions as a Python class:

```python
class MockLedger:
    def __init__(self, commit_ms=lambda: 600): ...
    def call(self, identity: str, fn: str, **args) -> dict   # same envelope as the gateway
```

Rules:

- Same state model, same validation, same error codes (raise `LedgerError(code, message)`).
- Role from identity name: `ta*` is TA, `rsu*` is RSU.
- `commitMs` comes from a configurable function (constant or random) so simulated-time behaviour can be exercised.
- A thin `GatewayClient` with the same `call()` method sends HTTP to the gateway. Consumers switch with one setting: `LEDGER=mock|gateway`.

---

## Part 3: Build plan

### 3.1 Test plan

Write the cases once in `ledger/tests/test_conformance.py` (pytest) and run them against both backends with `LEDGER=mock|gateway`. Add a small number of Go unit tests for pure helpers (validators, key builders).

| # | Case | Expected | Covers |
|---|---|---|---|
| 1 | `rsu1` calls `PUT /policies/x` | 403 `ERR_FORBIDDEN` | F11, demo step 7 |
| 2 | `ta1` calls `POST /reports` | 403 | F11 |
| 3 | TA registers a root; reading it back returns the same | match | F1 |
| 4 | Registering the same epoch again | 409 | F1 |
| 5 | Malformed pid (too short, uppercase) | 400 | F14 |
| 6 | `RecordAuth` for a class not allowed for the service | 403 | F2 |
| 7 | `RecordAuth` for an unknown service | 404 | F2 |
| 8 | `RecordAuth` twice for the same pid | `sessionCount == 2` | F3 |
| 9 | `GetAuth` after expiry | 404 | F3 |
| 10 | One RSU reports twice | still not revoked, `reportCount == 1` | F5 |
| 11 | Two different RSUs report | revoked, `newlyRevoked == true` | F5, done-when |
| 12 | Two reports sent **concurrently** | revoked; gateway shows `retries ≥ 1` on one | F5 |
| 13 | After revocation `RecordAuth` for that pid | 409 | F6 |
| 14 | After revocation `GetAuth` and `CheckAccess` | 404 / `allow:false`, reason `REVOKED` | F4, F6 |
| 15 | `GET /revoked?since=` on a fresh cache | contains the pid | F6, F13 |
| 16 | `RequestTrace` for a non-revoked pid | 409 | F8 |
| 17 | Trace stays `PENDING` at 2 approvals, `APPROVED` at 3 | status checks | F8, done-when |
| 18 | Same RSU approves twice | 409 | F8 |
| 19 | TA `Revoke` on a `PENDING` trace | 409 | F9 |
| 20 | TA `Revoke` on `APPROVED` trace without the traced pid in the list | 400 | F9 |
| 21 | TA `Revoke` on `APPROVED` trace with 5 pids | all 5 revoked, trace `EXECUTED` | F9 |
| 22 | Second `Revoke` on the same trace | 409 | F9 |
| 23 | `RecordShareRelease` on a `PENDING` trace | 409 | F10 |
| 24 | `DumpState` (TA) contains no field other than the documented ones | schema check | F14 |
| 25 | `ResetDemoState` clears state but keeps `config` | counts zero | F20 |
| 26 | Every write response has `txId` and numeric `commitMs` | present | F12 |

### 3.2 Order of work

Dates assume the first full run on the mock by Oct 31 and real Fabric in by Nov 17.

| Step | Dates | Work | Done when |
|---|---|---|---|
| 1 | Oct 18–20 | Freeze §2.1 conventions with the team; write the endpoint table into `docs/interfaces.md`; implement `mock_ledger.py` with all functions and the conformance tests (run against the mock) | Persons 1, 3, 4 can import the mock; tests 1–26 pass on the mock |
| 2 | Oct 21–24 | Chaincode core: `types.go`, `helpers.go`, `config.go`, `roots.go`, `policy.go`; extend `WhoAmI`; redeploy | `peer chaincode` calls succeed for TA, and fail for RSU, on config, roots, policies |
| 3 | Oct 25–28 | `auth.go` and `revocation.go` (`RecordAuth`, `GetAuth`, `ListAuthsSince`, `CheckAccess`, reports, revoked list, status) | tests 5–15 pass when called through the `peer` CLI scripts |
| 4 | Oct 29–Nov 2 | Gateway core: `fabricClient.js` (identities, evaluate, submit, timing, retry), error mapping, routes for config, roots, policies, auth, reports, revoked | curl works for every endpoint in those groups; **mock-based first end-to-end run by Oct 31** (this step does not block it) |
| 5 | Nov 3–7 | `trace.go` and `routes/traces.js`; share-release and `Revoke` | tests 16–23 pass |
| 6 | Nov 8–11 | `ops.go`, `/snapshot`, `/stats`, `/chain`, `/activity`, `/admin/*`, optional `/events/stream` | tests 24–26 pass; snapshot returns in under 200 ms with ~1000 records |
| 7 | Nov 12–14 | Run the conformance suite against the gateway; fix differences from the mock; benchmark (`bench/load.js`) with batch timeouts 2 s, 500 ms, 200 ms | all 26 tests green on both backends; CSV results handed to Person 4 |
| 8 | Nov 15–17 | Integration: Person 1's scenario on real Fabric; demo rehearsal of ledger steps | "Real Fabric in" milestone |
| 9 | Nov 18–25 | Demo page (optional), report chapter, rehearsal | demo script runs twice without intervention |

Per-function routine to keep each step small: write the Go function, `go build ./...`, redeploy with the next version and sequence, call it with the `peer` CLI as TA and as an RSU, then add the gateway route, then add the test.

### 3.3 Benchmark (F17)

`bench/load.js` (Node, uses the gateway directly or HTTP):

- Operation: `RecordAuth` with unique random pids (write-heavy, no key conflicts).
- Rates: 5, 10, 20, 50 tx/s, 60 s each, after a 20-second warm-up.
- Batch timeouts: 2 s, 500 ms, 200 ms (restart with `BATCH_TIMEOUT=... ./up.sh`).
- Output CSV: `batchTimeout, targetRate, achievedTps, p50Ms, p95Ms, failures, retries`.
- A second small run: concurrent `ReportMisbehaviour` against one pid, to show the retry behaviour.

### 3.4 Demo script mapping

| Demo step | What the ledger side does | Calls |
|---|---|---|
| 1. Start the blockchain | peers, channel, chaincode shown | `GET /health`, `GET /chain`, `peer lifecycle chaincode querycommitted` |
| 2. Register vehicles | TA publishes root, then the transaction is shown with no identity | `POST /roots`, `GET /activity`, `GET /admin/dump` |
| 4. Authentication and handover | RSU 1 records auth, RSU 2 reads it and records its own session | `POST /auth-records` (rsu1), `GET /auth-records/:pid` (rsu2), `POST /auth-records` (rsu2) |
| 5. Catch an attacker | two RSUs report, pseudonym revoked, next auth rejected | `POST /reports` (rsu1, rsu2), `GET /pseudonyms/:pid`, `POST /auth-records` expecting 409 |
| 6. Reveal the owner | open trace, three approvals, release shares, TA revokes all pseudonyms | `POST /traces`, `POST /traces/:id/approve` ×3, `POST /traces/:id/shares`, `POST /traces/:id/revoke` |
| 7. Access control | an RSU calls a TA-only function | `PUT /policies/x` with `X-Identity: rsu1` returns 403 |
| 8. Results | commit latency, throughput, ledger size | benchmark CSV, `GET /stats` |

Keep a `demo_flow.sh` in `ledger/scripts/` that runs steps 2 to 7 with `curl`, printing the response of each call. It doubles as a smoke test after a reset.

### 3.5 Open decisions to settle with the team (this week)

| Decision | Recommended default | Who |
|---|---|---|
| `pid` format | SHA-256 of compressed pseudonym public key, hex64 | Person 3 |
| Merkle root format | hex64 (SHA-256) | Person 3 |
| Epoch meaning and length | integer; one epoch per demo run is enough | Person 3 |
| `K` for auto-revocation | 2 | team |
| `traceThreshold` | 3 with 4 RSU identities | team |
| Vehicle classes and services | see §2.1 | team |
| Auth TTL | 3600 s max; RSUs usually pick 300 s | Persons 1, 3 |
| RSU naming | `rsu1` … `rsu4` matching `rsuId` in the protocol and ns-3 | Persons 1, 3 |
| Max pseudonyms per vehicle for `Revoke` | 200 | Person 3 |

### 3.6 Inconsistencies found in the source documents

| Issue | Decision here |
|---|---|
| The work split writes both `POST /authrecords` and `GET /auth-records/{pid}` | use `/auth-records` for both |
| `Revoke(pids, reason)` has no link to the approved trace | added `reqId`, and the endpoint is `POST /traces/:id/revoke` |
| The work split says "at least 3 peers standing in for RSUs", but the test network has one peer per org | RSUs are enrolled client identities; the 2f+1 rule counts distinct RSU IDs in the chaincode. Mention this in the report |
| Slides say `n ≥ 3f+1` validators for consensus | Fabric 2.5 Raft is crash-fault tolerant only; the Byzantine-style threshold exists only at the application level (trace approvals). BFT ordering is extension X1 |
| Two slides are both numbered 13 | not a ledger issue; fix before the review |

### 3.7 Final checklist

- [ ] Conventions in §2.1 agreed and copied into `docs/interfaces.md`
- [ ] All chaincode functions in §2.4 deployed; access matrix §2.5 verified by tests 1 and 2
- [ ] Every endpoint in §2.7 answers with `curl`, writes return `txId` and `commitMs`
- [ ] Conformance tests 1–26 pass on both `mock` and `gateway`
- [ ] Two RSU reports revoke a pid and the revocation appears in `/snapshot` for every RSU
- [ ] A trace is approved only at the threshold and can be executed once
- [ ] `DumpState` shows no identity, only pids, hashes, roots, policies and RSU IDs
- [ ] Benchmark CSV delivered to Person 4
- [ ] `demo_flow.sh` runs end to end after `down.sh && up.sh`
