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
  (`7 QUARANTINE` with `--fast-revocation`, backbone only)
  (or the protocol module provides `message_type(data) -> str`)
- `BSM` and `BEACON` are sent on EDCA AC_VO, everything else on AC_BE.

Implemented in `protocol/messages.py`: `[type u8][version u8][tagged binary fields]`,
and `protocol.message_type(data)`. Typical sizes with 500 pseudonyms per epoch
(Merkle depth 9): BEACON ~160 B, AUTH_REQ ~530 B (+36 B per extra Merkle level),
AUTH_RESP ~210 B, HANDOVER_REQ ~290 B, PREAUTH ~280 B, BSM ~330 B (signed, with ticket).
PREAUTH goes over the RSU backbone (`node.backbone_send`), not the radio.

Opt-in compact forms (`run_scenario.py`, group "real protocol options"; the
defaults send exactly the messages above):

| Option | Effect | BSM bytes |
|---|---|---|
| (default) | `payload = {pid, fields, ticket}`, signature `{R, s}` | 333 |
| `--bsm-ticket digest [--ticket-every N]` | `ticket_digest` = first 8 bytes of SHA-256(canonical JSON of `{payload, signature: {R, s}}` of the ticket; other keys are ignored) instead of `ticket`, inside the signed payload. The full ticket is attached to the first BSM after a new ticket or handover, after a beacon from an RSU not heard for 1 s, and to every N-th BSM (default 10, must be ≥ 1) | 172 (333 with ticket) |
| `--compact-wire` | `payload = {pid, k, ticket}`: `k` is 18 bytes, J2735-style (`make_bsm` requires exactly seq, t, x, y, speed, heading): seq u16 (mod 65536, unwrapped at the RSU against the pseudonym's previous seq), t u32 ms (mod 2^32, unwrapped at the RSU near the receive time), x/y i32 cm, speed u16 0.02 m/s (clamped), heading u16 0.0125° (mod 360); signature is one 64-byte BIP340 hex field over a tagged SHA-256 of the canonical payload, verified with the x-only form of the ticket's `pk`; beacons carry no `public_key` (162 → 125 B) | 283 |
| both | | 122 (283 with ticket) |

RSUs in digest mode keep an LRU (5000) of digest → ticket payload, filled only
with tickets whose RSU signature was checked: tickets they issue, PREAUTH notes,
handover requests and full-ticket BSMs. A digest the RSU does not know is
rejected with `BSM_REJECT ...:unknown_ticket_digest` (logged once per pid);
signature, pid, expiry, revocation and detector checks are unchanged. The
detector gets the decoded `k` with the usual keys (quantized as above).

**Session-MAC BSMs** (`--bsm-auth mac [--anchor-every N] [--adaptive-anchor]`,
defaults `sig`, 10, off). `mac` implies the `--bsm-ticket digest` schedule and the
RSU digest cache. After the vehicle holds a ticket, a BSM is either

- a **MAC BSM**: `{payload: {pid, fields|k, ticket_digest}, tags: {rsu_id: tag}}`, no
  `signature`. `tag` = first 8 bytes of HMAC-SHA256(key, canonical JSON of `payload`),
  key = SHA-256("VANET-BSM-MAC" ‖ ECDH(pseudonym secret, RSU public key) ‖ 8-byte
  digest); the RSU computes the same key as ECDH(RSU secret, ticket `pk`), so no
  handshake beyond the ZKP authentication is needed. Tags go to at most 3 trusted
  RSUs: the current RSU first, then the RSUs heard in the last 0.35 s, newest first.
  115 B with one tag (ids like `rsu6`), +16 B per further tag (74 B / +16 with
  `--compact-wire`).
- a signed **ANCHOR**, exactly the digest-mode BSM above (172 B, or 333 B with the full
  ticket; 122 / 283 with `--compact-wire`): every N-th BSM, every BSM that carries the
  full ticket (so `--ticket-every` also bounds the anchor gap), and every BSM when no
  trusted RSU is known.

An RSU accepts a MAC BSM only if it knows the digest (`unknown_ticket_digest`
otherwise), the ticket's pid matches, `tags` has an entry under its own id
(`bsm_mac_not_for_rsu`) and that tag verifies (`invalid_bsm_mac`); expiry,
revocation and the detector are as for signed BSMs. Keys are cached per (pid, digest).
Trade-offs: a MAC BSM is verifiable only by the RSUs it addresses (no V2V
verifiability; an RSU that was not heard recently drops it), and an addressed RSU could
compute the tag itself, so a MAC is no evidence for anyone else (no non-repudiation).
Anchors keep both properties.

The vehicle chooses its anchor schedule, so the RSU enforces it (all rejects are
`BSM_REJECT`, logged once per pid and reason):

- `anchor_overdue`: more than 4 anchor gaps of MAC BSMs from one pid since its last
  accepted anchor (gap = min(N, `--ticket-every`), 2N with `--adaptive-anchor`; 40 by
  default). The next anchor lifts it.
- `anchor_required`: the pid has K flagged messages in its last W (MAC or anchor) but no
  flagged anchor among them. Only anchors are taken from it until it is reported or
  the window drops below K flags, so a lie has to be signed to keep going.
- An anchor counts as evidence only if the detector flags it against the pid's earlier
  anchors alone (all signed), not against MAC history an addressed RSU could forge.
  A pseudonym is reported when K of its last W messages are flagged and one of them is
  such an anchor; the evidence hash is that anchor's, and the previous anchors let a
  third party re-check it. Cost: an attacker lying only in MAC BSMs is not reported but
  gets at most K-1 lies in per window; an honest vehicle with K flagged MAC BSMs loses
  its MAC BSMs at that RSU for up to W anchors (in sig mode it would be reported).

In mac mode each RSU keeps the per-pid detector state (history, flags, anchor
bookkeeping) in an LRU of 5000 pseudonyms. Vehicles in digest/mac mode pick MAC targets
and the "new RSU" full ticket only from beacons whose signature they verified (re-checked
at most every 0.2 s per RSU), so a spoofed beacon cannot take a tag slot.

`--adaptive-anchor` sets N from the vehicle's own `node.channel_busy_ratio()` before each
BSM: N // 2 (at least 2, at most N) below 0.2, N up to 0.4, 2N above (10 → 5 / 10 / 20),
with 0.02 hysteresis around each threshold and at most one change per second. 2N only
takes effect with `--ticket-every` ≥ 2N, since full-ticket BSMs are anchors.
Each change is logged as `ANCHOR_PERIOD` (`result` = `old->new cbr=x.xx`). MAC BSMs
charge the op `bsm_mac` (0 unless in `--compute-times`) instead of `bsm_sign`.

**Latency, handover and revocation options** (same group; defaults reproduce the runs above):

| Option | Effect |
|---|---|
| `--auth-timeout S` (1.0) | a vehicle gives up on an AUTH_REQ / HANDOVER_REQ after S s (`AUTH_TIMEOUT`, checked on the next beacon) and retries on that beacon |
| `--handover-hysteresis` | the current RSU counts as lost after 1.0 s without its beacon (not 0.35 s); a handover to X starts only if X's beacons were heard ≥ 3 times in the last 0.5 s; for 1.0 s after a `HANDOVER_OK` no further handover unless the current RSU is lost. Handovers no longer count as pseudonym sessions (only full authentications do), so ping-pong does not burn pseudonyms; cost: one pseudonym covers more road. MAC tag targets still use the 0.35 s window |
| `--fast-revocation` | two-tier revocation, see QUARANTINE below |
| `--profile {baseline,v2,v2-mac}` | defaults for the options of this group: `v2` = `--bsm-ticket digest --compact-wire --auth-timeout 0.2 --handover-hysteresis --fast-revocation`, `v2-mac` = `v2` + `--bsm-auth mac --adaptive-anchor`. Options given explicitly override the profile; `config.json` records the effective values |

**QUARANTINE** (type 7, ~148 B, `--fast-revocation`): when an RSU reports a pid to the
ledger it also sends `{pid, evidence, reporter, timestamp, signature}` (evidence = the
report's evidence hash, Schnorr signature of the reporter RSU over canonical JSON of
the other four fields) with `node.backbone_send` to its neighbours (the PREAUTH list,
RSUs within 2.5 × `--rsu-range`); notes are not forwarded. A receiver accepts a note from
a trusted RSU key with a valid signature, at most 5 s old (`untrusted_reporter`,
`invalid_quarantine_signature`, `stale_quarantine`, `malformed_quarantine` otherwise;
logged as `QUARANTINE_REJECT`). Per pid it keeps the set of distinct reporters (valid
notes plus its own report); when that reaches `--report-k` (the ledger's K) the pid is
rejected there for 30 s with reason `quarantined` (AUTH_REJECT, HANDOVER_CHECK and
BSM_REJECT, once per pid), each new reporter restarting the 30 s, until the ledger
shows the pid revoked; then the usual `revoked` checks apply. Trade-off: this applies
the ledger's K-of-RSUs rule locally before the commit is visible, without the ledger's
ordering or audit trail; fewer than K RSUs still cannot block anyone, but K colluding
RSUs can block a pid for a TTL without a ledger record. A blocked vehicle sees its
AUTH_REQ rejected and changes pseudonym, as on revocation.

### v3 options

All off by default. Profiles:

| Profile | Options |
|---|---|
| `v3-fast` | v2 + `--bsm-auth tesla --adaptive-auth --tesla-interval 0.025 --tesla-key-msgs --implicit-cert --cluster-size 2 --batch-verify --dr-bsm --revocation-filter --trust-weighted --ticket-period 2 --ticket-renewal --rssi-check` |
| `v3-private` | v3-fast + `--credential bbs --mix-zones` |
| `v3` | the first v3 evaluation (fixed TESLA, BBS, mix zones, no adaptive mode / renewal), kept for comparison |

`--rsu-cpu`, `--v2v-verify`, `--obu-scale` and `--privacy-log` are measurement options,
not part of a profile; the v3 comparison configs set them for every variant.

| Option | Mechanism | Code |
|---|---|---|
| `--bsm-auth tesla [--tesla-interval 0.05 --tesla-delay 2]` | TESLA broadcast authentication: between signed anchors a BSM carries `ti` (interval), `tm` (8-byte MAC under H'(K_ti)) and `kd` (disclosed chain key K_{ti-d}). Anchors sign `tc` = [j, K_j] (chain commitment). Every receiver (RSU or vehicle) can verify, ~1-2 beacon periods after sending; a BSM after a hard deceleration (> 3 m/s²) is a signed anchor, accepted at once. With `--dr-bsm` a `TESLA_KEY` message (type 8, ~35 B) discloses a key no BSM would disclose in time | `protocol/tesla.py` |
| `--implicit-cert` | ECQV implicit-certificate tickets (SEC 4): `pu` (33 B) instead of `pk` + RSU signature, ticket ~90 B instead of ~160 B. AUTH_REQ adds `cert_req` (bound into the ZKP context), AUTH_RESP adds `r`. BSMs and handover requests are signed with the derived ticket secret d_U; an RSU caches an implicit ticket only after such a signature (or from a signed PREAUTH) | `protocol/ecqv.py` |
| `--cluster-size N` | RSUs in N x N blocks of the RSU grid form a cluster (`cl` in the ticket). Inside a cluster the vehicle does not hand over (logged as `CLUSTER_SWITCH`, 0 ms); a handover into another cluster re-issues the ticket for it (`reason` `cluster_ticket`). PREAUTH goes only to neighbours in other clusters | `rsu.py`, `sim_app.py` |
| `--batch-verify` | Load-triggered batching at RSUs (and vehicles with `--v2v-verify`): a signature that finds the processor idle is verified at once; signatures that arrive while it is busy are verified as one batch (at most 32) the moment it is free, so an idle processor adds no wait. The batch equation and binary splitting are real (`batch_verify`, `find_invalid`); the time is the measured single verification divided by the speedup measured with the same pure-Python arithmetic (`batch_speedup_n`: 1.2x at 2, 2.0x at 64) | `protocol/batch.py`, `sim_app.py` (CpuQueue) |
| `--adaptive-auth` | With `--bsm-auth tesla`: every BSM is signed (accepted at once) while the vehicle's own channel busy ratio is below 0.20; TESLA above 0.30, with 1 s hold-down (`AUTH_MODE` events). In sign mode the chain commitment `tc` rides on every 10th BSM only | `sim_app.py` |
| `--tesla-key-msgs` | Send each TESLA key in a `TESLA_KEY` message the moment it may be disclosed, instead of in the next BSM (with `--tesla-interval 0.025`: accepted 25-50 ms after sending) | `sim_app.py` |
| `--ticket-renewal` | Before a ticket expires the vehicle sends a `HANDOVER_REQ` with `renew` (signed with the ticket key, bound to a fresh beacon nonce, `cert_req` with `--implicit-cert`) and gets a new ticket for the same pseudonym (`reason` `renewed`, `RENEW_OK` / `RENEW_FALLBACK`); no ZKP or BBS proof. Revocation, quarantine and policy are checked as at authentication. Counts as a pseudonym session | `rsu.py`, `vehicle.py` |
| `--rssi-check` | RSUs give the detector a distance estimate from received power: the scenario's log-distance path loss plus 4 dB log-normal shadowing, inverted with the same model (modelled, not read from the ns-3 PHY). Rule `rssi_dist`: \|ln(claimed / estimated distance)\| > 4 sigma and > 100 m apart (feature `rssi_z`) | `detection/detector.py`, `sim_app.py` |
| `--detector-mode {rules,ml,hybrid} [--detector-model F]` | Rules, a trained model (`ThresholdModel`, its own threshold), or rules OR model. `--detector-log` writes `detector_log.npz` (features + ground truth of every BSM an RSU checked) for `python -m detection.train_sim`. Trained on the grid, the model reported honest vehicles on LuST, so no profile uses it | `detection/` |
| `--dr-bsm [--dr-threshold 1 --dr-max-gap 1]` | A BSM only when the receivers' dead-reckoning estimate is more than 1 m off, speed changed by > 0.5 m/s, heading by > 4°, or 1 s passed (ETSI CAM-like triggers) | `sim_app.py` |
| `--revocation-filter` | Every 5th RSU beacon (2 Hz) carries `rf`, a Bloom filter (10 bits per entry, 7 hashes, ~1 % false positives) of pseudonyms revoked or quarantined within the last ticket lifetime, inside the signed payload. Vehicles drop BSMs of listed senders | `protocol/bloom.py`, `v2v.py` |
| `--mix-zones` | Cooperative pseudonym change at junctions: within 30 m of a junction with >= 3 vehicles within 50 m, the vehicle and every neighbour whose pseudonym is older than 10 s change together, each silent until it has left the zone and at least 0.5-1.5 s (at most 5 s). 20 pseudonyms per vehicle (Merkle mode); session-count changes are off | `sim_app.py` |
| `--credential bbs [--bbs-j 32]` | BBS anonymous credential on (hidden sk_v, class, epoch), issued blindly. AUTH_REQ carries `nym` (48 B), `j` and a 304-byte `bbs_proof` instead of the Merkle path and Schnorr proof; pid = H(nym), nym = H(epoch, j)^sk_v, j < J. The ledger's epoch root is the TA's BBS public key. Escrow records list all J pids, so a trace revokes them all | `protocol/bbs.py` |
| `--trust-weighted` | Revocation when the *weights* of the distinct reporters sum to `--report-k` (weights start at 1.0; plain K-of-RSUs until then). After each identity reveal the TA's investigation updates every reporter's weight w = min(1, 2 (tp+1)/(tp+fp+2)) (`set_weight`, chaincode `SetReporterWeight`, gateway `PUT /weights/:rsuId`); a vehicle found honest keeps its other pseudonyms. The quarantine of `--fast-revocation` uses the same weights. In the simulator the investigation outcome is the ground truth of attackers.csv | `ledger_client.py`, `weights.go` |
| `--faulty-rsus F` | A fraction F of the RSUs (compromised) report a random recently heard pseudonym every 5 s from t = 10 s | `sim_app.py` |
| `--ticket-period S` | digest mode: full ticket also at least every S s (vehicles learn tickets of senders before they come close) | `vehicle.py` |
| `--rsu-cpu` | RSU cryptography on one processor in arrival order: BSM acceptance latency includes queueing; a BSM that would wait > 100 ms is dropped | `sim_app.py` (CpuQueue) |
| `--v2v-verify [--v2v-radius 100 --obu-scale 1]` | Vehicles verify BSMs of senders within 100 m on their own processor (`--obu-scale` x the measured times; the v3 configs use 5) and learn tickets from full-ticket BSMs heard farther away | `protocol/v2v.py` |
| `--mobility-step S` | SUMO step and ns-2 waypoint period (default 1 s; 0.1 s gives smooth acceleration, which matters for dead reckoning) | `mobility/build_scenario.py` |
| `--real lust:{low,mid,peak}` | Scenario cut from LuST (Luxembourg, 24 h, calibrated demand): the densest 1.35 km square at 08:00 (city centre), 900 s warm-up, then `--duration` s; low = 06:00 (~150 vehicles in the box at once), mid = 14:00 (~260), peak = 08:00 (~525). 3 x 3 RSUs inside the box. `mobility/get_lust.sh` downloads LuST | `mobility/real_scenario.py` |
| `--mix-k N`, `--mix-silent-max S` | Mix zones: neighbours needed for a change (3), longest silence after it (5 s) | `sim_app.py` |
| `--privacy-log` | `observed_bsms.csv`: every BSM as a global eavesdropper hears it; `experiments/tracker.py` links pseudonyms | `sim_app.py` |

`protocol_stats.json` (end of every real-protocol run): RSU and V2V acceptance counts,
reasons and acceptance latency (send to accept, ms), CPU load per kind of node,
dead-reckoning error, BSMs sent and suppressed, TESLA key messages, mix-zone changes,
cluster switches, faulty reports, trust weights, revocation-filter size.
`experiments/collect.py` turns it, the traffic counters and the tracker into the
columns of runs.csv / aggregate.csv; `experiments/report.py` into report.md.

New events: `RENEW_OK` / `RENEW_FALLBACK` (vehicle, ms), `AUTH_MODE` (`sign|tesla cbr=..`), `CLUSTER_SWITCH` (vehicle, rsu, 0 ms), `FAULTY_REPORT` (a compromised RSU's
report, also logged as `REPORT`), `TRUST_UPDATE` (`rsu:weight`), `INVESTIGATION_HONEST`
(pid), `PSEUDONYM_CHANGE` with `mix ...` / `forced` / `mix joined`.

Emergency vehicles (`--emergency-ratio R`, `--emergency-priority`, `--attack fake_emergency`;
protocol/sim_app.py has the details): the vehicle class is fixed at registration, the service
`emergency-priority` is allowed to class `emergency` only, and a BSM may carry `"ev": 1` in its
signed payload (siren on), which receivers honour only under a ticket of class `emergency`
(else reason `fake_emergency`; a signed one is reported at once). New events: `EMERGENCY_ROLE`
(vehicle), `FAKE_EMERGENCY` (RSU, pid it reported), `FAKE_EMERGENCY_LOGIN` (vehicle, rsu).
`protocol_stats.json` gets an `emergency` block; collect.py the `ev_*` and `fake_*` columns.
Wire format: `"ev"`, `"emergency-priority"`, `"fake_emergency"` are appended to the interned names.

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
| `bsm_sign` | vehicle: every signed BSM (`bsm_mac` for MAC BSMs with `--bsm-auth mac`, `tesla_mac` for TESLA BSMs) |
| `bsm_verify_one`, `hmac`, `ecdh`, `tesla`, `ecqv_*`, `bbs_verify` | RSU / vehicle with `--rsu-cpu` / `--v2v-verify`: the operations the verifier reports in `ops` |
| `bbs_prove` | vehicle: BBS credential proof (`--credential bbs`) instead of `prove` |
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
Protocol events are written by protocol code with `node.log(...)`. With
`--fast-revocation` RSUs also log `QUARANTINE_SENT` (`result` = `pid:neighbours`),
`QUARANTINE_BLOCK` (first local block of a pid at that RSU, `result` = pid) and
`QUARANTINE_REJECT` (`result` = reason). `experiments/collect.py` reports
`report_to_block_s_mean` (first REPORT of a pid to its first QUARANTINE_BLOCK or
REVOKED_VISIBLE, whichever comes first; equal to `report_to_revocation_s_mean` without
`--fast-revocation`) and `handovers_per_auth` (HANDOVER_OK / AUTH_OK).

Next to it: `summary.json` (PDR overall and by distance, delays per message
type, CBR per RSU, ledger commit times, FlowMonitor totals), `config.json`
(every parameter), `attackers.csv` (ground truth), `flowmon.xml`, `netanim.xml`.
