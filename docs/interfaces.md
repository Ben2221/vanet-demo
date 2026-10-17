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
app.on_receive(node, data: bytes, sim_time: float)     # required
app.on_start(node)                                      # optional: RSU at t=0, vehicle on entering the road
app.on_stop(node)                                       # optional: vehicle leaving the road
app.make_bsm(node, sim_time, state) -> bytes            # optional, vehicles: build + sign the 10 Hz BSM
```

`state` for `make_bsm` is the claimed kinematics:
`{"seq", "t", "x", "y", "speed", "heading", "vx", "vy"}` (already falsified for
attacker vehicles). Without `make_bsm` a plain unsigned 200-byte BSM is sent.

Protocol code calls only (from `network.hooks`):

```python
send(node, destination, data)             # destination: BROADCAST or a node id
schedule(delay, callback, *args)
node.send(destination, data, delay=0.0)   # same, with a processing delay
node.schedule(delay, callback, *args)
```

Useful attributes and helpers on `node`:

| | |
|---|---|
| `node.id`, `node.name`, `node.kind` | node id (network address), `"veh12"` / `"rsu3"`, `"vehicle"` / `"rsu"` |
| `node.last_sender` | node id of the sender of the message being handled (reply address) |
| `node.ledger` | RSUs only: local ledger copy, see below |
| `node.detector` | Person 4's `check(bsm, history)` or `None` |
| `node.position()`, `node.velocity()`, `node.speed()`, `node.heading()` | true kinematics |
| `node.nearby_rsus(radius=None)` | `[(rsu_node, distance)]`, closest first, for make-before-break |
| `node.processing_delay(op)` | seconds for `"prove"`, `"verify"`, `"sign"`, ... from `--compute-times` |
| `node.log(event, nbytes, latency_ms, result)` | one row in the metrics CSV |
| `node.env` | shared: `vehicles`, `rsus`, `bridge`, `ta_ledger`, `rng`, `config`, `shared` |

Protocol code never imports ns-3.

### Local ledger copy for RSUs (`node.ledger`)

Reads are instant in simulated time: `get_auth(pid_hash)`, `is_revoked(pid)`,
`revoked()`, `get_trace(req_id)`, `get_policy(service)`, `get_root(epoch)`,
`current_root()`.

Writes return at once and become visible to every RSU after the commit time
reported by the ledger: `record_auth(pid_hash, service, cls, expiry)`,
`report_misbehaviour(pid, evidence_hash)`, `request_trace(req_id, pid, reason)`,
`approve_trace(req_id)`. Each takes an optional `on_commit(result)` callback.
The TA writes through `env.ta_ledger` (`register_root`, `set_policy`, `revoke`);
setup-time writes that must be visible at t = 0 go through
`env.bridge.preload("TA", "register_root", epoch=..., merkle_root=..., valid_until=...)`.

## 4. Ledger API (Person 2 → Persons 3, 4)

The scenario calls the ledger through `call(caller, fn, **args)`, with `fn` the
chaincode function in snake_case. Writes must return `{"txId", "commitMs"}`.

| fn | args | REST (gateway) |
|---|---|---|
| `register_root` | `epoch, merkle_root, valid_until` | `POST /roots` |
| `set_policy` | `service, classes` | `POST /policies` |
| `record_auth` | `pid_hash, service, cls, expiry` | `POST /auth-records` |
| `get_auth` | `pid_hash` | `GET /auth-records/{pidHash}` |
| `report_misbehaviour` | `pid, evidence_hash` | `POST /reports` → may include `revoked` |
| `is_revoked` | `pid` | `GET /revoked/{pid}` |
| `get_revoked_since` | `since` | `GET /revoked?since=` → `{"revoked": [...], "cursor": n}` |
| `request_trace` | `req_id, pid, reason` | `POST /traces` |
| `approve_trace` | `req_id` | `POST /traces/{reqId}/approve` |
| `get_trace` | `req_id` | `GET /traces/{reqId}` → `{"trace": {..., "approvals": [...], "approved": bool}}` |
| `revoke` | `pids, reason` | `POST /revocations` |

- The caller identity (`TA`, `rsu0`, `rsu1`, ...) travels in the HTTP header
  `X-Identity` (change with `--identity-header`); the gateway maps it to that
  identity's Fabric certificate. A wrong caller gets HTTP 403.
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
one-way delay as `latency_ms`; BSMs only with `--log-bsm`), `CBR` (each RSU,
every second, ratio in `result`), `ENTER`, `LEAVE`, `ATTACK_START`,
`BEACON_RATE`, `LEDGER_SUBMIT` (commit time), `LEDGER_VISIBLE` (time until
other RSUs see the write), `LEDGER_DENIED`, `LEDGER_ERROR`, `REVOKED_VISIBLE`.
Protocol events are written by protocol code with `node.log(...)`.

Next to it: `summary.json` (PDR overall and by distance, delays per message
type, CBR per RSU, ledger commit times, FlowMonitor totals), `config.json`
(every parameter), `attackers.csv` (ground truth), `flowmon.xml`, `netanim.xml`.
