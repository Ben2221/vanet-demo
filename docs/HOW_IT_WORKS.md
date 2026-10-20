# How the whole system works (study guide)

This is the one document to read before a review or viva. It follows a single vehicle
through the system, explains every mechanism and why it is there, and ends with the
questions examiners usually ask. File references point to the code that does each step.

---

## 1. The problem in one paragraph

Vehicles broadcast **Basic Safety Messages** (BSMs: position, speed, heading) 10 times a
second. Receivers must be able to trust them (**authentication**), but a car that signs
with a fixed identity can be tracked everywhere it drives (**privacy**). A car that is
authenticated can still lie in its BSMs (**misbehaviour**), so it must be found and thrown
out (**revocation**), and in serious cases its real owner must be identified
(**accountability**), but no single party should be able to unmask anyone at will.
Our system gives all five properties at once, and measures what they cost on a real
802.11p channel.

## 2. The actors

| Actor | What it is | Code |
|---|---|---|
| **TA** (Trusted Authority) | Registers vehicles before they drive. Knows real identities, but cannot reveal one on its own. | `protocol/registration.py`, `protocol/escrow.py`, `protocol/sim_app.py: setup, _ta_loop` |
| **Vehicle (OBU)** | Holds 5 pseudonyms (key pairs). Authenticates, signs BSMs, changes pseudonym. | `protocol/vehicle.py`, `VehicleApp` in `sim_app.py` |
| **RSU** | Roadside unit. Beacons, verifies proofs, issues tickets, checks every BSM, runs the detector, reports, votes on traces, holds an escrow key share. | `protocol/rsu.py`, `RsuApp` in `sim_app.py` |
| **Ledger** | Hyperledger Fabric channel shared by TA and RSU organisations. Holds Merkle roots, policies, authorisations, misbehaviour reports, revocations, trace votes. **Never** real identities. | `ledger/chaincode/vanetauth/*.go`; in simulation `network/ledger_client.py` |
| **Detector** | Plausibility checks on every BSM at the RSU. | `detection/detector.py` |
| **Simulator** | SUMO (roads, traffic) + ns-3 or the lite backend (802.11p radio). | `mobility/`, `network/` |

## 3. One vehicle's life, step by step

### Step 0 — Registration (before driving), `registration.py`
1. The vehicle (or TA for it) creates 5 pseudonyms. Each is a secp256k1 key pair
   `(x, Y = x·G)` with a random 8-byte id `pid`.
2. The TA builds a **Merkle tree** over all pseudonyms of all vehicles. Each leaf is
   `H(pid ‖ public key ‖ vehicle class)`, and leaves are **shuffled**, so the position in
   the tree says nothing about which vehicle a leaf belongs to.
3. Only the **Merkle root** goes on the ledger (`RegisterRoot`). One 32-byte value stands for
   every registered pseudonym; the ledger needs no per-pseudonym record, and leaks no list.
4. Each vehicle gets its **Merkle path** (sibling hashes, depth 9 for 500 leaves).
5. **Identity escrow** (`escrow.py`): the TA encrypts the record
   `{vehicle, node id, all pids}` with AES-256-GCM under a fresh key, then splits that key
   with **Shamir secret sharing** into one share per RSU organisation, threshold
   `t = 2f+1` with `f = ⌊(n−1)/3⌋` (9 RSUs → t = 5). The TA keeps only the ciphertext.
   Any `t` RSUs together can rebuild the key; `t−1` learn nothing.
6. The TA sets the **access policy** on the ledger (`SetPolicy`: service `road_access`
   allows classes car, truck, emergency).

### Step 1 — RSU beacon, `RSU.beacon`
Every 100 ms each RSU broadcasts `{rsu_id, nonce (16 random bytes), timestamp}` signed
with its Schnorr key. The vehicle checks the signature against the RSU keys it trusts
(fake RSUs are ignored). The nonce makes every authentication fresh.

### Step 2 — Anonymous authentication with a zero-knowledge proof, `Vehicle.make_auth_request`, `RSU.authenticate`
The vehicle sends `AUTH_REQ` with: pid, public key Y, class, epoch, Merkle path, the
beacon's nonce and timestamp, and a **Schnorr proof of knowledge** of `x` such that
`Y = x·G`:

```
prover:   r random, R = r·G                      (R precomputed while idle: CommitmentPool)
          c = H("SCHNORR-FS-v1" ‖ R ‖ Y ‖ ctx)   (Fiat–Shamir: the hash replaces the verifier's challenge)
          s = r + c·x  mod n
verifier: s·G == R + c·Y ?
ctx = rsu_id ‖ nonce ‖ timestamp ‖ service ‖ pid ‖ class
```

The RSU checks, in order: the nonce is one it issued in the last second and not used
by this pid (anti-replay) → timestamp fresh (5 s) → the epoch's root exists and is valid →
**Merkle membership** of `H(pid ‖ Y ‖ class)` (the pseudonym is registered, and class/pid
cannot be swapped) → **ZKP verifies** (the sender owns the key) → pid **not revoked** →
**policy** allows the class. Then it issues a **ticket**.

*Why this is zero-knowledge:* the transcript `(R, c, s)` can be simulated without `x`,
so the RSU learns only "the sender knows the key of a registered pseudonym", never which
vehicle it is. *Why the context is hashed in:* a proof made for RSU A, nonce N cannot be
replayed to RSU B or later.

### Step 3 — The ticket and the shared authorisation
The ticket is `{pid, pk, service, class, issuer, issued_at, expiry = now+30 s}` signed by
the RSU. The RSU writes `RecordAuth` to the ledger, and immediately sends a signed
**PREAUTH** note with the ticket to its neighbouring RSUs over the wired backbone
(2 ms). The ledger commit takes ~0.5 s (Fabric block time); PREAUTH means the neighbour
can accept a handover **before** the commit is visible.

### Step 4 — Signed safety messages, `Vehicle.make_bsm`, `RSU.verify_bsm`
Every BSM is `{pid, fields: seq, t, x, y, speed, heading, ticket | ticket_ref}` plus a
Schnorr signature with the pseudonym key. The RSU checks the ticket's RSU signature (cached
after the first time), that the BSM pid equals the ticket pid, the BSM signature with the
ticket's key, expiry and revocation. **Ticket digest (this branch):** the full ~150-byte ticket
is sent in every 10th BSM (once a second) and right after a new ticket or handover; the
other BSMs carry only its 8-byte SHA-256 digest (`ticket_ref`), the same idea as the
IEEE 1609.2 certificate digest. An RSU accepts a digest only for a ticket it verified
itself (from a BSM, AUTH, handover or PREAUTH). BSMs fall from 330 to 172 bytes.

### Step 5 — Handover, `make_before_break_handover`, `RSU.handover`
When the vehicle is past 80 % of the current RSU's range and a closer RSU beacons, it sends
`HANDOVER_REQ {ticket, target RSU, target's beacon nonce, timestamp}` signed with the
pseudonym key (**proof of possession**: a sniffed ticket alone is useless). The new RSU
checks the ticket signature, the request signature, freshness, the nonce, and that a
**shared authorisation** exists: on the ledger, or else in its PREAUTH cache. No ZKP and
no Merkle path, so a handover is smaller and cheaper than a full authentication
(make-before-break: the old RSU still serves the vehicle meanwhile). If it fails, the
vehicle falls back to full authentication.

### Step 6 — Pseudonym change (privacy)
After 3 sessions (authentications + handovers) the vehicle switches to its next pseudonym,
drops the old ticket and authenticates again. Different pseudonyms are unlinkable for the
ledger and for other RSUs. *Limitation to state honestly:* the RSU that sees the switch
sees the old pid stop and a new pid start at the same spot from the same radio; real
deployments also change the MAC address and use silent periods / mix zones.

### Step 7 — Misbehaviour detection, `detection/detector.py`
For every valid BSM the RSU runs plausibility checks against that pseudonym's recent
history (VeReMi-style):

| Check | Fires when | Catches |
|---|---|---|
| `range` | claimed position > 450 m from the receiving RSU | position falsification |
| `pos_jump` | implied speed between two messages > 60 m/s | random position |
| `pos_speed` | claimed speed vs. speed implied by the path over 0.8–3 s differs by > 8 m/s | const/random speed, const position |
| `speed_cons` | acceleration > 25 m/s² (scenario profile) | sudden stop, random speed |
| `speed_range` | speed < 0 or > 60 m/s | |
| `heading` | 150°+ flip in < 1 s while moving | |
| `msg_rate` | > 13 messages/s from one pseudonym | flooding |
| `replay` | time/seq goes backwards, or the pid is sent by another radio | replay |
| `sybil` | one radio alternates between pseudonyms A,B,A,B | ghost vehicles |
| `sudden_appear` + `overlap` (weak, need both) | a new pid appears near the RSU on top of another vehicle | ghost vehicles |

**K-of-W reporting** (`RSU.verify_bsm`): a pseudonym is reported to the ledger after
K = 3 flagged BSMs among its last W = 10, once per RSU, with the hash of the evidence BSM.
One noisy flag never reports anyone.

### Step 8 — Revocation on the ledger (`ReportMisbehaviour`)
The chaincode revokes a pid when **K = 2 different RSUs** reported it. A single
compromised or faulty RSU therefore cannot revoke anyone. All RSUs see the revocation
after the commit (~0.5 s) and reject that pid's BSMs, handovers and authentications.

### Step 9 — Trace, threshold reveal, full exclusion (`_ledger_duties`, `_ta_loop`)
1. The reporting RSU opens a **trace request** on the ledger (`RequestTrace`).
2. RSU organisations **approve** it (`ApproveTrace`); it is approved at the trace threshold.
3. Each RSU releases its escrow key share **only if `GetTrace` shows the request approved**
   (`RSUEscrowAgent.release_share`).
4. The TA combines `t` shares (Lagrange interpolation), decrypts the identity record,
   and calls `Revoke` on **all** pseudonyms of that vehicle. Switching pseudonym no longer
   helps the attacker; after its last pseudonym is rejected it stops (`ALL_PSEUDONYMS_REVOKED`).

**Separation of power:** RSUs can revoke a pseudonym (2 must agree) but don't know who it
is; the TA can decrypt only with `t` RSU shares, and only after an on-ledger approval that
everyone can audit.

## 4. The cryptography, in one table

| Primitive | Where | Why this one |
|---|---|---|
| secp256k1 Schnorr proof (Fiat–Shamir) | AUTH_REQ | ZK proof of key ownership, 1 EC mult with precomputed `R` |
| Schnorr signatures | beacons, tickets, BSMs, handover, PREAUTH | small (65 B), fast, same curve |
| SHA-256 Merkle tree | registration | one root on the ledger stands for every pseudonym; O(log n) proof |
| Shamir (t, n) over GF(2²⁵⁶+297) | identity escrow | no single party can unmask |
| AES-256-GCM | identity escrow | authenticated encryption of the identity record |
| `coincurve` (libsecp256k1) | all EC operations | constant-time, the library Bitcoin uses |

Measured compute times (`protocol/compute_times.json`): prove 0.043 ms (with precomputed
commitment), verify 0.084 ms, sign 0.084 ms, Merkle check 0.007 ms. The simulator adds
these as processing delays (`node.processing_delay(op)`).

## 5. The ledger and simulated time

* Chaincode `vanetauth` (Go): `RegisterRoot/GetRoot`, `SetPolicy/GetPolicy`,
  `RecordAuth/GetAuth`, `ReportMisbehaviour/IsRevoked/ListRevokedSince`,
  `RequestTrace/ApproveTrace/GetTrace/Revoke`, `SetConfig` (K, trace threshold).
  Access control by MSP: TA on Org1, RSUs on Org2.
* The Node.js gateway (`ledger/gateway/`) exposes it over REST; the simulator can use it
  (`--ledger http://localhost:3000`) or an in-memory copy with the same rules (`--ledger mock`).
* **Ledger bridge** (`network/ledger_bridge.py`): reads are instant from each RSU's local copy;
  a write becomes visible to *other* RSUs only after the commit time (500 ms mock, or the real
  Fabric time). Vehicles never wait for a block; the effect of commit delay shows up exactly
  where it matters (handover before commit, time to revoke).

## 6. The simulation

* **Mobility:** SUMO on a 5×5 grid, 250 m blocks (1 km²), random trips, 1 s samples;
  converted to an ns-2 trace that parks inactive vehicles 3 km outside the map.
* **RSUs:** grid of 450 m snapped to roads → 9 RSUs, 300 m service range.
* **Radio:** IEEE 802.11p, 10 MHz, 6 Mb/s, 20 dBm, −85 dBm sensitivity (≈ 400 m range),
  EDCA: BSM/beacons on AC_VO, the rest on AC_BE. ns-3 for final numbers; the lite backend
  (same parameters, pure Python) for development.
* **Attackers:** a fraction of vehicles falsify BSMs from `attack_start`: `const_pos`
  (+150–300 m offset), `random_pos`, `const_speed` (+10–25 m/s), `random_speed`,
  `sudden_stop`, `flood` (10× rate). Ground truth goes to `attackers.csv`, never to the protocol.
* **Baselines** (`experiments/baselines/`): ECDSA pseudonym certificates (IEEE 1609.2 style,
  no shared state) and a central authority (20 ms round trip per request), run in the same
  scenario.

## 7. How results are produced and what each number means

```bash
python experiments/run.py --config experiments/configs/presentation.json --jobs 4
# -> experiments/results/presentation/{runs.csv, aggregate.csv, plots/*.png, REPORT.md}
```

Every run writes `metrics.csv` (one row per event). `experiments/collect.py` turns it into one
row of numbers; `run.py` averages over ≥ 3 seeds with 95 % confidence intervals;
`plots.py` draws every figure; `report.py` writes `REPORT.md` with the headline table.

| Metric | Measured as |
|---|---|
| auth latency | vehicle sends AUTH_REQ → receives ticket (radio + queueing + crypto), ms |
| handover latency | HANDOVER_REQ → accept, ms |
| auth / handover success | honest vehicles' AUTH_OK / AUTH_REQ; accepted / requested handovers |
| handovers via PREAUTH | share of handovers accepted before the ledger record was visible |
| BSM PDR | broadcast BSMs received / receivers within 300 m |
| channel busy ratio | PHY busy time per second at the RSUs |
| security bytes / BSM | mean BSM size − 45 B plain BSM |
| attackers reported / revoked | attackers with ≥ 1 report / with a pseudonym revoked on the ledger |
| first lie → report | from the first moment the attacker could send an authenticated lying BSM (attack start, or its first ticket if it arrived later) to the first report |
| report → revocation | first report → revocation visible at the RSUs |
| first lie → identity reveal | until the TA has unmasked it and revoked all its pseudonyms |
| honest flagged / reported / revoked | false positives at each of the three stages |

## 8. What this branch changed, and why the numbers got better

| Change | Before | After | Files |
|---|---|---|---|
| Experiments use the real protocol | configs ran the stand-in `stub` | `protocol: real` everywhere; compare_schemes = ours vs ECDSA vs central | `experiments/configs/*.json` |
| Time to first report measured from when the attacker could lie | counted from `attack_start` even for cars that entered the road later (reported 14–31 s) | from its first authenticated lying BSM (0.2–1.1 s) | `experiments/collect.py` |
| Pseudonym change no longer looks like a ghost vehicle | own old/new pid at the same spot fired `overlap` + `sudden_appear` | overlap ignores pseudonyms from the same radio (alternating ones are still caught by `sybil`) | `detection/detector.py` |
| Lite radio no longer "teleports" leaving cars | the 0.1 s position table interpolated the jump to the parking spot, so far RSUs heard the car and flagged `range` | jumps are held, not interpolated | `network/ns2_mobility.py` |
| Ticket digest in BSMs | full ticket in every BSM: 330 B, 288 security bytes | full ticket once a second, 8-byte digest otherwise: ~190 B mean | `protocol/vehicle.py`, `rsu.py`, `--full-ticket-every` |
| Parallel sweeps no longer fail | runs sharing a SUMO scenario built it at the same time; runs failed at random | scenarios built once before the parallel runs | `experiments/run.py` |
| Auth rejections counted correctly | RSU + vehicle rows counted twice; revoked attackers counted as failures | split into `auth_rejected_revoked` / `_other`; success ratio over honest vehicles | `experiments/collect.py` |
| New metrics and figures | — | revocation rate, time to exclusion, honest flagged, auth/handover success, handovers via PREAUTH, which checks fired | `collect.py`, `plots.py`, `report.py` |
| Explainable flags | DETECT_FLAG said only the pid | `pid:check+check` | `protocol/sim_app.py` |

Results for these changes are in [`docs/results/README.md`](results/README.md).

## 9. Limitations to state before someone else does

* **Revocation needs two RSUs.** An attacker seen by only one RSU before it leaves is
  reported but not revoked (const_pos runs: ~2/3 revoked within 120 s). This is the price of
  "one RSU cannot revoke anyone"; `sweep_report_k.json` shows the trade-off (K = 1 revokes
  faster but trusts every single RSU).
* **const_pos inside radio range** is the hardest attack: a constant offset that keeps the
  position plausible is invisible to kinematic checks until it crosses the range limit.
  Remedies: RSU angle-of-arrival / RSSI-vs-distance checks, cooperation between neighbouring RSUs.
* **Detector numbers on generated data are optimistic.** The VeReMi NextGen loader exists but
  has not been checked against the real dataset (see `detection/README.md`).
* **Mock ledger commit time is a setting (500 ms), not a measurement.** Real Fabric numbers come
  from `ledger/bench/load.js` and `--ledger http://...`.
* **Lite backend vs ns-3.** Final numbers should come from ns-3 (`--backend ns3`, Docker on
  Windows); the lite backend is calibrated to the same range (tests check 100/300 m arrive,
  450 m fail) but has a simpler MAC.
* **Linkability at pseudonym change** by the RSU that sees it (section 3, step 6).
* **Baselines** reuse the stand-in message flow and model sizes, compute costs and round trips,
  not certificate expiry or queueing at a central authority.

## 10. Questions you will be asked (and short answers)

**Why a zero-knowledge proof and not just a signature with a certificate?**
A certificate names the pseudonym's issuer chain and must be checked against a CRL; our
proof shows membership in a set committed by one Merkle root plus key ownership, so the
ledger stores one root per epoch instead of per-pseudonym certificates, and the RSU learns
nothing beyond "registered and owns this key". Revocation stays a single lookup.

**Isn't a Schnorr proof just a signature?** Mathematically it is the same equation; what
makes it a proof here is what the challenge is bound to: the RSU's fresh nonce, timestamp,
service, pid and class. That gives freshness and prevents replay to another RSU.

**What does the blockchain add over a database?** No single operator: TA and RSU
organisations each run peers, every write (report, revocation, trace vote) is endorsed and
auditable, and the rules (K = 2 reports, trace threshold) are enforced by chaincode that no
single party can change. The identity reveal depends on an on-ledger approval that everyone sees.

**Doesn't the 0.5 s block time slow authentication down?** No: authentication never waits
for the ledger. Reads are local; the ticket is issued immediately; neighbours get PREAUTH in
2 ms over the backbone. The ledger delay only affects how fast *other* RSUs see a record and
how fast a revocation propagates.

**How do you prevent replay?** Beacon nonces valid for 1 s and usable once per pid; the nonce
and timestamp are inside the ZKP context; handover requests are signed with the pseudonym key and
carry the target RSU's nonce; BSMs carry seq/time and the detector flags backwards time and copies
from another radio.

**What if an RSU is malicious?** It cannot revoke alone (K = 2 different RSUs), cannot unmask
(needs t = 2f+1 key shares and a ledger-approved trace), and cannot forge a vehicle's proof.
It can refuse service or report falsely; a false report without a second RSU does nothing.

**What if the TA is malicious?** It cannot decrypt identities without t RSU shares; it never
puts identities on the ledger; registering fake pseudonyms is visible as a root change on the ledger.

**How is privacy preserved?** Pseudonyms are unlinkable keys in a shuffled Merkle tree; the ledger
sees pids only; vehicles change pseudonym every 3 sessions; tickets are short-lived (30 s).

**Why K-of-W reporting?** Sensor noise and lost packets produce occasional flags on honest cars;
requiring 3 flagged messages out of 10 before reporting removes them (our runs: 0 honest
vehicles reported) at the cost of ~0.2–0.3 s more detection delay.

**Why threshold 2f+1?** With n RSU organisations of which at most f = ⌊(n−1)/3⌋ are faulty, 2f+1
shares guarantee that an honest majority of the approvers took part (BFT-style bound).

**What does the ticket digest change for security?** Nothing an attacker can use: the digest is
inside the signed payload, an RSU maps it only to a ticket whose RSU signature it verified, and
the BSM must still verify with that ticket's key and pid. The cost is that an RSU that has not
seen the ticket drops up to one second of that vehicle's BSMs.

**How do you know the numbers are right?** ≥ 3 seeds, 95 % CIs, 89 unit/integration tests
(`pytest protocol/tests network/tests detection/tests experiments/tests`), the position trace is
checked against SUMO (max error 0.002 m), the radio range is checked against the path-loss model.
