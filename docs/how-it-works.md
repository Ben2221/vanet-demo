# How this project works, from zero

This guide assumes no background in vehicular networks, cryptography or blockchains. Read it
top to bottom once, then use it as a reference. Commands are run from the `vanet-demo` folder.

## 1. The problem in one paragraph

Future cars broadcast a short safety message about 10 times a second: "I am here, going this
fast, in this direction". Nearby cars use these messages to warn about collisions before the
driver can see the danger. This only works if the messages can be **trusted** (a fake car
reporting a fake position could cause a crash). It also only works if they **don't let anyone
track you** (your car would otherwise broadcast where you are all day). And it has to be **fast
and small**, because the radio channel is shared by every car around. This project designs and
measures a system that gets all three at once.

## 2. Words you will see everywhere

| Word | Meaning |
|---|---|
| **VANET** | Vehicular Ad-hoc NETwork: cars and roadside boxes talking to each other by radio, no mobile network needed |
| **OBU** | On-Board Unit: the radio computer inside each car |
| **RSU** | Road-Side Unit: a fixed radio box at a junction, connected to the internet by cable. Our maps have 9 of them |
| **BSM** | Basic Safety Message: the "here I am" broadcast, about 10 per second per car |
| **802.11p** | The Wi-Fi variant made for cars (5.9 GHz). This is the radio we simulate |
| **Pseudonym** | A random temporary ID the car uses instead of its real identity. It changes often |
| **Authentication** | Proving you are a legitimate, registered car |
| **Zero-knowledge proof (ZKP)** | Proving you know a secret (your registration key) without revealing the secret, or which car you are. We use a **Schnorr** proof |
| **Merkle tree / root** | A way to compress the list of all registered cars into one 32-byte fingerprint (the root). A car can prove it is "in the list" with a short path of hashes |
| **Ticket** | After a car proves itself, the RSU gives it a short-lived signed pass. Showing the ticket is much cheaper than proving again |
| **Handover** | The car drives into the next RSU's range and shows its ticket there |
| **Revocation** | Officially banning a pseudonym (or a whole car) so nobody accepts its messages any more |
| **Blockchain / ledger** | A shared database that several organisations keep together, where nobody can secretly change history. We use **Hyperledger Fabric**, a business blockchain (no cryptocurrency) |
| **Chaincode** | Fabric's word for the program that runs on the blockchain (our rules: register, report, revoke, reveal) |
| **Raft / BFT** | Two ways Fabric's servers agree on the next block. Raft is fast but trusts the servers; BFT (SmartBFT) tolerates some servers lying |
| **Threshold reveal** | Finding out which real car was behind a pseudonym needs several RSUs to agree (here 5 of 9). No single party can unmask anyone |
| **Misbehaviour detection** | Checking whether what a car says is physically possible (it can't jump 300 m in 0.1 s) |
| **ns-3** | A widely used network simulator. It models radio signals, collisions and delays realistically |
| **SUMO** | A traffic simulator. It decides where every car drives |
| **LuST** | Luxembourg SUMO Traffic: a real, published map and 24-hour traffic of Luxembourg City |
| **VeReMi Extension** | A public dataset of 3.2 million labelled V2X messages with 19 attack types, used to test detectors |
| **PDR** | Packet Delivery Ratio: of the messages that should have arrived, the share that did (higher is better) |
| **CBR** | Channel Busy Ratio: the share of time the radio channel is occupied (lower is better; above ~0.6 messages start colliding badly) |

## 3. The story of one car

This is what `make live` narrates.

1. **Before driving (once):** the car is registered with the transport authority. It gets a
   secret key, and the authority adds it to the Merkle tree of registered cars. Only the tree's
   root goes on the blockchain. The car also gets a batch of pseudonyms.
2. **Entering an RSU's range:** every RSU broadcasts a beacon ("I am RSU 4"). The car answers
   with a zero-knowledge proof: "I am in the registered tree, and this is my current pseudonym".
   The RSU checks the proof against the root from the blockchain and issues a **ticket**. In
   v3-fast this takes about **1.6 ms**.
3. **Driving:** the car broadcasts BSMs. Every BSM is authenticated so that receivers know it
   comes from a ticket holder. Neighbouring cars and RSUs check each one before believing it.
4. **Next junction:** the car shows its ticket to the next RSU (a **handover**), which is cheaper
   than proving again. Tickets expire, so the car **renews** them.
5. **Attack:** suppose the car is an attacker and starts lying about its position. The RSU's
   **detector** sees an impossible jump and **flags** it. The RSU then does two things:
   - **Quarantine:** it immediately tells neighbouring RSUs "drop this pseudonym" (within about
     0.2 s).
   - **Report:** it writes the report to the blockchain.
6. **Revocation:** once **2 different RSUs** report the same pseudonym, the chaincode revokes it.
   A single report does nothing, which protects honest cars from one RSU's mistake. Every RSU
   sees the revocation, and in v3 the RSUs put a compact list of revoked pseudonyms (a **Bloom
   filter**) into their beacons, so cars stop believing the attacker too.
7. **Unmasking:** 5 of the 9 RSUs combine their key shares to reveal which real car was behind
   the pseudonym. All its spare pseudonyms are then revoked, so it can't just switch to a fresh
   one. Its next login attempt is rejected, and the attacker is **shut out**.

## 4. Phase I and v3: what changed

**Phase I** is the design in the review PDF: the ZKP, the tickets, the blockchain and the
threshold reveal. It is secure, but every BSM carries a full signature plus the ticket
(333 bytes, 10 times a second), so the channel fills up as traffic grows.

**v3** keeps Phase I's security model and adds mechanisms that make it faster and smaller.
They come in two profiles.

**v3-fast** adds these mechanisms:

| Mechanism | Plain-English idea | What it saves |
|---|---|---|
| TESLA | Sign with a cheap secret code now and publish the key a moment later, instead of a costly signature on every message | message size, CPU |
| Adaptive mode | Use TESLA when the channel is busy and signatures when it's quiet | best of both |
| Compact format and implicit certificates (ECQV) | Smaller encoding; the public key is folded into the certificate | bytes per BSM (333 → 154) |
| RSU clusters | One ticket is valid at 2 neighbouring RSUs | handovers |
| Batch verification | When an RSU is overloaded, it checks many signatures at once | RSU CPU under load |
| Dead reckoning | Send an extra BSM only when the receivers' prediction of your position would be wrong | messages per second |
| Revocation filter in beacons | Cars learn who is revoked, not only RSUs | revoked senders still believed: 100% → 0.07% |
| Quarantine | Neighbouring RSUs drop an attacker before the blockchain commits | reaction time |
| Trust-weighted reports | RSUs whose reports turned out right count more | resists lying RSUs |
| Ticket renewal | Refresh a ticket without a new proof | latency |
| Signal-strength check | A message claiming to be 50 m away but received as if from 400 m is suspicious | detection |

**v3-private** is v3-fast plus two privacy mechanisms:
- **BBS credentials:** an unlinkable proof each time, so two RSUs can't tell they saw the same car.
- **Cooperative mix zones:** cars at a junction change pseudonyms together and stay silent
  briefly, so an eavesdropper loses track of them.

It is slower: a ticket takes 7.5 ms instead of 1.6 ms. That is the price of privacy.

## 5. How the experiments work

```
SUMO (where cars drive) ──► ns-3 (802.11p radio: who hears what, when, collisions)
                                   │
                                   ▼
          protocol/ (our Python code inside every car and RSU)
                                   │
                         ledger (blockchain: mock or real Fabric)
                                   │
                                   ▼
        metrics.csv (one row per event) → summary.json → collect → reports, plots, page
```

- One **run** = one map, one number of cars, one random seed, one protocol, 60–120 simulated
  seconds. Its folder holds `metrics.csv` (every event), `summary.json` and `config.json`.
- One **sweep** = many runs: each protocol × 50/100/150 cars × 5 seeds. The **seeds** change
  the randomness. Reporting the mean ± 95% confidence interval over seeds shows that a
  difference is real and not luck. The **p-value** column tests exactly that: p < 0.05 means
  significant.
- **Computation time is measured, not guessed:** `protocol/measure.py` times every crypto
  operation on this PC, and the simulator charges those times (×5 for a car's slower
  processor) on a per-device CPU queue. Latency therefore includes both radio time and
  compute time.
- **Baselines** for comparison:
  - **ECDSA-PKI:** today's standard, with certificates signed by a central authority.
  - **Central-TA:** every login is checked by one central server.

## 6. Where things are in the code

| Folder | What lives there |
|---|---|
| `protocol/` | The scheme itself: `vehicle.py`, `rsu.py`, `crypto.py`, `messages.py`, plus `tesla.py`, `ecqv.py`, `bbs.py`, `bloom.py`, `batch.py`, `v2v.py`; `sim_app.py` connects them to the simulator |
| `network/` | `run_scenario.py` (start here; `--help` lists every option), the ns-3 and lite radio backends, the `metrics.csv` logger |
| `mobility/` | Building the maps: the synthetic grid, and the real LuST Luxembourg cut (`get_lust.sh`, `real_scenario.py`), RSU placement |
| `detection/` | The misbehaviour detector (rules, ML, hybrid), the VeReMi benchmark, training scripts |
| `ledger/` | Hyperledger Fabric network (`network/up.sh`), the Go chaincode, the REST gateway the simulator calls, a mock for fast runs |
| `experiments/` | Sweep configs (`configs/`), runner (`run.py`), `collect.py`, `report.py`, `plots.py`, `dashboard.py`, `tracker.py` (the eavesdropper), `live.py` (narration) |
| `experiments/results/` | Every output |

## 7. Everything you can run and show

| Command | Time | What you see |
|---|---|---|
| `make live` | ~30 s | One ns-3 run narrated live in the terminal: cars joining, the attack, detection, quarantine, blockchain revocation, the attacker shut out, and a status line every 5 s |
| `make live CARS=100 SIM_TIME=300 RSU_SPACING=333 PACE=1` | 5 min | Change the scenario: 100 cars, 300 simulated s, 16 RSUs, shown in real time. Also `ATTACKERS=0.2`, `ATTACK_TYPE=const_speed`, `ATTACK_AT=30`, `MAP=lust:mid` (real Luxembourg traffic) |
| `make live PROFILE=Phase-I` | ~40 s | The same for the original design. Compare the "BSM bytes" in the status lines |
| `make replay RUN=experiments/results/demo/v3-fast SPEED=2` | adjustable | Replays a finished run, no simulation; `SPEED=0` prints it all at once |
| `make demo` | ~3 min | Three schemes on ns-3, then a side-by-side table |
| `make test` | ~25 s | 171 automated tests: crypto, protocol, detector, ledger rules |
| `make show` | instant | Key numbers of every run and sweep |
| `make fabric-up`, `make gateway` (second terminal), then `GATEWAY_URL=http://127.0.0.1:3100 ledger/demo_flow.sh` | ~3 min | The real Hyperledger Fabric blockchain answering register, report, revoke and reveal requests, with each HTTP request and reply printed |
| `make detector-benchmark` | ~10 min | The detector on the VeReMi Extension dataset |
| Results page (claude.ai artifact) | – | All sweeps as charts and tables in a browser |
| `experiments/results/compare_v3/report.md`, `plots/` | – | Final numbers with confidence intervals and p-values, and figures for the thesis |

`metrics.csv` in any run folder is the raw truth: every number on the page can be recomputed
from it.

## 8. The main results (ns-3, 150 cars, 5 seeds)

| | Phase-I | v3-fast | ECDSA-PKI | Central-TA |
|---|---|---|---|---|
| Time to get a ticket | 2.54 ms | **1.62 ms** | 1.92 ms | 22.5 ms |
| Safety bytes per car per second | 3,100 | **301** | 1,170 | 1,170 |
| Channel busy ratio | 0.258 | **0.047** | 0.148 | 0.147 |
| Delivery ratio | 0.959 | **0.995** | 0.977 | 0.977 |
| Revoked senders still believed by cars | 100% | **0.07%** | – | – |
| Attackers caught | 100% | 100% | 100% | 100% |

Detection on VeReMi Extension: F1 rose from 0.718 (rules) to 0.963.

## 9. Honest limitations (say these before someone else does)

- Radio and traffic are simulated. ns-3 and SUMO are the accepted standard for this, but they
  are not a road test.
- A car's processor is assumed to be 5× slower than this PC. Real OBU hardware was not measured.
- The grid sweeps use a mock blockchain with a 500 ms commit time. Real Fabric was benchmarked
  separately (Raft vs BFT) and runs in the live demo flow.
- The machine-learning detector trained on one dataset did not transfer to another city, so
  the v3 profiles use rules plus the signal-strength check.
- In `make live`, some honest cars get a single false flag. No action follows, because
  revocation needs 2 reports, and **0 honest cars were revoked** across the runs.
- Batch verification only helps when an RSU is overloaded.

## 10. How much more can be done

This list is ordered roughly by value for a thesis or paper.

1. **Real hardware timings:** run `protocol/measure.py` on a Raspberry Pi or a real OBU, so the
   ×5 assumption becomes a measurement.
2. **Real blockchain in every run:** use the Fabric gateway instead of the mock for a full sweep
   (slow, but it removes a limitation).
3. **Formal security proof:** model the authentication and revocation protocol in Tamarin or
   ProVerif and prove secrecy and authentication automatically.
4. **Stronger attackers:**
   - Sybil (one car, many identities), replay and colluding attackers.
   - Flooding an RSU.
   - Several compromised RSUs (the trust sweep starts this).
5. **A detector that transfers between cities:** train on VeReMi plus several maps, or use
   sequence models over a car's history; cars could also vote together.
6. **C-V2X / 5G sidelink:** the newer cellular car radio, simulated with ns-3's 5G-LENA module,
   next to 802.11p.
7. **Post-quantum signatures** (Falcon or Dilithium): measure the size cost, likely combined
   with TESLA, which hides most of it.
8. **Standards format:** encode messages as IEEE 1609.2 / ETSI TS 103 097, and compare with the
   US SCMS design.
9. **Larger scale:** 500–1,000 cars, a full LuST day, and the InTAS map (Ingolstadt).
10. **Stronger privacy measurement:** an ML-based tracker and entropy-based anonymity metrics.
