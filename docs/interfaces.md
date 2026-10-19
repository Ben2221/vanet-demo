# Interfaces between the parts

Agreed in week 1. Change only when everyone agrees. Sections 1, 3 and 6 are
owned by Person 1 and are implemented. Sections 2, 4 and 5 are owned by Persons
3, 2 and 4; what is written there is what Person 1's scenario expects today,
so the owners can confirm or change it.

## 1. Mobility trace (Person 1 → Persons 1, 4)

Built by `python mobility/build_scenario.py --vehicles N --duration T --seed S`
into `mobility/out/<net>_v<N>_d<T>_s<S>/`:

| File | Content |
|---|---|
| `fcd.xml` | SUMO floating-car data, 1 s samples |
| `trace.ns2` | ns-2 mobility file for `Ns2MobilityHelper`, node ids `0..N-1` |
| `node_map.csv` | `sumo_id,node_id,first_seen,last_seen` |
| `rsus_<spacing>m.csv`, `rsus.csv` | `rsu_id,node_id,x,y,range_m`; RSU node ids follow the vehicles (`N..N+R-1`) |
| `trace_traceexporter.ns2` | SUMO's own traceExporter output, only with `--traceexporter` |

- Coordinates are SUMO network coordinates in metres.
- Vehicle node ids follow departure order.
- A vehicle that is not on the road is parked at `(-3000, -3000)`, 3 km
  outside the map and out of radio range of every road, and its applications are stopped
  (`first_seen` ≤ active < `last_seen`).

## 2. Protocol messages (Person 3 → Person 1)

The network treats every message as opaque bytes; the byte length is the UDP
payload size in ns-3. The scenario needs only:

- the first byte is the message type:
  `1 BEACON, 2 AUTH_REQ, 3 AUTH_RESP, 4 HANDOVER_REQ, 5 PREAUTH, 6 BSM`
  (or the protocol module provides `message_type(data) -> str`)
- `BSM` and `BEACON` are sent on EDCA AC_VO, everything else on AC_BE.

Implemented in `protocol/messages.py`: `[type u8][version u8][tagged binary fields]`,
and `protocol.message_type(data)`. Typical sizes with 500 pseudonyms per epoch
(Merkle depth 9): BEACON ~160 B, AUTH_REQ ~530 B (+36 B per extra Merkle level),
AUTH_RESP ~210 B, HANDOVER_REQ ~290 B, PREAUTH ~280 B, BSM ~330 B (signed, with ticket).
PREAUTH goes over the RSU backbone (`node.backbone_send`), not the radio.

## 3. Node hooks (Person 1 → Person 3)

Person 3's package `protocol/` must expose (module level):

```python
def create_vehicle(node, env) -> app      # one object per vehicle
def create_rsu(node, env) -> app          # one object per RSU
def setup(env) -> None                    # optional: TA registration before the run
def message_type(data: bytes) -> str      # optional: names for the logs
```

Each `app` implements

```python
app.on_receive(node, data: bytes, sim_time: float)     # required (may also take src=: sender node id)
app.on_start(node)                                      # optional: RSU at t=0, vehicle on entering the road
app.on_stop(node)                                       # optional: vehicle leaving the road
app.make_bsm(node, sim_time, state) -> bytes            # optional, vehicles: build + sign the 10 Hz BSM
```

`state` for `make_bsm` is the claimed kinematics:
`{"seq", "t", "x", "y", "speed", "heading", "vx", "vy"}` (already falsified for
attacker vehicles). Without `make_bsm` a plain unsigned 200-byte BSM is sent.
The BSM goes on air after `node.processing_delay(app.bsm_sign_op)` (default op
`"bsm_sign"`), the time to sign it.

Protocol code calls only (from `network.hooks`):

```python
send(node, destination, data)             # destination: BROADCAST or a node id
schedule(delay, callback, *args)
node.send(destination, data, delay=0.0)   # same, with a processing delay
node.schedule(delay, callback, *args)
node.backbone_send(rsu, data, delay=0.0)  # RSUs only: wired RSU-to-RSU link, --backbone-ms latency
```

Order at start-up: `create_vehicle` for every vehicle, then `create_rsu` for every
RSU, then `setup(env)`, then the RSUs' `on_start` at t = 0.

Useful attributes and helpers on `node`:

| | |
|---|---|
| `node.id`, `node.name`, `node.kind` | node id (network address), `"veh12"` / `"rsu3"`, `"vehicle"` / `"rsu"` |
| `node.last_sender` | node id of the sender of the message being handled (reply address); valid only inside `on_receive`, so save it (or use the `src` argument) before scheduling a later reply |
| `node.ledger` | RSUs only: local ledger copy, see below |
| `node.detector` | Person 4's `check(bsm, history)` or `None` |
| `node.position()`, `node.velocity()`, `node.speed()`, `node.heading()` | true kinematics |
| `node.nearby_rsus(radius=None)` | `[(rsu_node, distance)]`, closest first, for make-before-break |
| `node.processing_delay(op)` | seconds for an operation from `--compute-times` (0 if unknown), see below |
| `node.log(event, nbytes, latency_ms, result)` | one row in the metrics CSV |
| `node.env` | shared: `vehicles`, `rsus`, `bridge`, `ta_ledger`, `rng`, `config`, `shared` |

Protocol code never imports ns-3.

### Processing delays (`--compute-times`)

`python -m protocol.measure` times Person 3's real implementation on this machine
(`--scale k` for slower vehicle hardware) and writes `protocol/compute_times.json`;
`python experiments/measure_ecdsa.py --merge protocol/compute_times.json` adds the
ECDSA baseline as `experiments/compute_times_all.json`. `run_scenario.py` uses the
first of these two files that exists unless `--compute-times` is given
(`--compute-times none` for zero delays). The file used is in `config.json`.

| op | charged where (protocol/sim_app.py) |
|---|---|
| `verify_sig` + `prove` | vehicle: check the beacon signature, then the Schnorr ZKP, before AUTH_REQ |
| `merkle_check` + `verify` (+ `sign`) | RSU: membership + ZKP check (+ ticket signature) before AUTH_RESP |
| `verify_sig` + `sign` | vehicle: target beacon check + request signature before HANDOVER_REQ |
| 2 × `verify_sig` | RSU: ticket + request signature before the handover answer |
| `sign` per neighbour | RSU: each PREAUTH note |
| `bsm_sign` | vehicle: every BSM |
| `ecdsa_sign`, `ecdsa_verify` | the ECDSA baseline (experiments/baselines) |

### Local ledger copy for RSUs (`node.ledger`)

Reads are instant in simulated time: `get_auth(pid_hash)`, `is_revoked(pid)`,
`revoked()`, `get_trace(req_id)`, `traces()` (all trace requests), `get_policy(service)`,
`get_root(epoch)`, `current_root()`.

Writes return at once and become visible to every RSU after the commit time
reported by the ledger: `record_auth(pid_hash, service, cls, expiry)`,
`report_misbehaviour(pid, evidence_hash)`, `request_trace(req_id, pid, reason)`,
`approve_trace(req_id)`. Each takes an optional `on_commit(result)` callback.
The TA writes through `env.ta_ledger` (`register_root`, `set_policy`, `revoke`);
setup-time writes that must be visible at t = 0 go through
`env.bridge.preload("TA", "register_root", epoch=..., merkle_root=..., valid_until=...)`.

## 4. Ledger API (Person 2 → Persons 3, 4)

The gateway contract is Person 2's: [ledger/gateway/README.md](../ledger/gateway/README.md)
(the same routes run in memory in `ledger/mock/mock_ledger_server.py`).
Check a gateway with `python -m network.ledger_check <url>`.

The scenario calls the ledger through `call(caller, fn, **args)`, with `fn` the
chaincode function in snake_case. Writes return `{"txId", "commitMs", ...}`.
`network/ledger_client.py:RestLedgerClient` translates each call to the gateway:

| fn | args | REST (gateway) |
|---|---|---|
| `register_root` | `epoch, merkle_root, valid_until` | `POST /roots` |
| `set_policy` | `service, classes` | `PUT /policies/{service}` |
| `record_auth` | `pid_hash, service, cls, expiry` | `POST /auth-records` (`pid`, `class`) |
| `get_auth` | `pid_hash` | `GET /auth-records/{pid}` |
| `report_misbehaviour` | `pid, evidence_hash` | `POST /reports` → `revoked`, `reportCount` |
| `is_revoked` | `pid` | `GET /revoked/{pid}` |
| `get_revoked_since` | `since` | `GET /revoked?since=` (ms) → `{"revoked": [...], "cursor": n}` |
| `request_trace` | `req_id, pid, reason` | `POST /traces` (pid must already be revoked) |
| `approve_trace` | `req_id` | `POST /traces/{reqId}/approve` |
| `get_trace` | `req_id` | `GET /traces/{reqId}` → `{"trace": {..., "approvals": [...], "approved": bool}}` |
| `revoke` | `pids, reason` | `POST /traces/{reqId}/revoke` (the approved trace of one of the pids) |

- The caller identity travels in the HTTP header `X-Identity` (change with
  `--identity-header`): `TA` is sent as `ta1`, RSUs as `rsu0`, `rsu1`, ... The
  Fabric gateway only knows the identities in `ledger/gateway/identities.json`
  (`rsu0`–`rsu15`, enough for every grid config). For maps with more RSUs, set
  `LEDGER_RSU_IDENTITIES=rsu0,rsu1,...` to fold the scenario's RSUs onto them
  (RSUs sharing an identity then count as one reporter). A wrong caller gets HTTP 403.
- The gateway wants 64-hex pids, wall-clock ms times and `[a-z0-9-]` service names.
  The client hashes pids (salted per run, so runs never collide), turns simulated
  seconds into future ms and returns the scenario's own values on reads.
- On its first call the client sets the gateway config (`PUT /config`) to the
  scenario's `--report-k` and `--trace-threshold`.
- `ledger/mock_ledger.py` should expose `MockLedger` with either
  `call(caller, fn, **args)` or one method per fn taking `caller` first. Until it
  exists, `--ledger mock` falls back to `network/ledger_client.py:InMemoryLedger`.
- Team decision (week 1): K = 2 reports for auto-revocation; trace threshold
  2f+1 RSUs with f = ⌊(R−1)/3⌋.

## 5. Detector (Person 4 → Person 3)

`detection/detector.py` exposes `check(bsm, history) -> (flagged, features)`.
The stand-in protocol passes `bsm` as a dict
`{"pid", "seq", "t", "x", "y", "speed", "heading", "rsu_x", "rsu_y", "rx_time", "sender"}`
and `history` as the list of earlier dicts from the same pseudonym (newest last).
Reporting rule: report a pseudonym after K flagged messages out of its last W.

## 6. Metrics log (everyone → Person 4)

`<run>/metrics.csv`, one row per event:

```
sim_time,node,event,bytes,latency_ms,result
```

Events written by the network layer: `TX_<TYPE>`, `RX_<TYPE>` (with the
one-way delay as `latency_ms`; BSMs and beacons only with `--log-bsm`), `CBR` (each RSU,
every second, ratio in `result`), `ENTER`, `LEAVE`, `ATTACK_START`,
`BEACON_RATE`, `LEDGER_SUBMIT` (commit time), `LEDGER_VISIBLE` (time until
other RSUs see the write), `LEDGER_DENIED`, `LEDGER_ERROR`, `REVOKED_VISIBLE`.
Protocol events are written by protocol code with `node.log(...)`.

Next to it: `summary.json` (PDR overall and by distance, delays per message
type, CBR per RSU, ledger commit times, FlowMonitor totals), `config.json`
(every parameter), `attackers.csv` (ground truth), `flowmon.xml`, `netanim.xml`.
