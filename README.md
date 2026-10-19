# VANET Authentication Demo

Vehicles drive on real roads in SUMO and talk over IEEE 802.11p in ns-3. They
authenticate anonymously to roadside units (RSUs) with zero-knowledge proofs;
authorization, revocation and identity-reveal approvals live on Hyperledger
Fabric.

This repository contains the implementation and documentation for our Bachelor Thesis Project (BTP), focused on network simulation using NS-3. It also contains the Hyperledger Fabric ledger setup for the VANET demo, defined in `ledger/` and planned in `chain_structure.md`. For detailed ledger architecture, operation, validation, and AI handoff context, see [`ledger/IMPLEMENTATION_CONTEXT.md`](ledger/IMPLEMENTATION_CONTEXT.md).

## Quick start

Linux (Fedora, Ubuntu) or WSL2:

```bash
git clone <repo> && cd vanet-demo
./setup.sh          # .venv with Python 3.11-3.13, all requirements, ns-3, gateway npm packages
make test           # all tests
make run            # one scenario with the real protocol (100 vehicles, 120 s)
make show           # key numbers of every run
```

`setup.sh` finds a Python 3.11–3.13 (and installs 3.13 with
[uv](https://docs.astral.sh/uv/) if the system only has 3.14, e.g. Fedora 43).
The first ns-3 install compiles cppyy (~10 min, needs `g++`); `./setup.sh --no-ns3`
skips it. `make help` lists every target; variables override the defaults, e.g.
`make run VEHICLES=150 DURATION=300 BACKEND=ns3`.

Manual setup, if you prefer:

```bash
python3.13 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install ns3            # ns-3 3.44+ Python bindings (Linux x86_64 only)
```

On Windows without WSL2 or on macOS, either use the Docker image
(`docker build -t vanet-demo .`, see `Dockerfile`; on Apple Silicon add
`--platform linux/amd64`) or skip ns-3: every script
then falls back to the **lite backend**, a small pure-Python 802.11p model with
the same radio parameters. Use it for development and tests; final results
come from ns-3 (`--backend ns3`).

## Outputs

Every run writes a folder under `experiments/results/<name>/`:

| File | What |
|---|---|
| `summary.json` | PDR, one-hop delay per message type, channel busy ratio, bytes per message type, ledger commit times |
| `metrics.csv` | one row per event: `sim_time,node,event,bytes,latency_ms,result`. `AUTH_OK` / `HANDOVER_OK` rows carry the end-to-end auth and handover latency |
| `attackers.csv`, `config.json` | who lied, and the exact options of the run |
| `flowmon.xml`, `netanim.xml` | ns-3 only (`--netanim`); open `netanim.xml` in NetAnim |

`make show` (`python experiments/show.py [dirs]`) prints the key numbers of all
runs and sweeps as one table. Sweeps (`make quick`, `make compare`,
`experiments/run.py --config ...`) also write `runs.csv`, `aggregate.csv` (mean and
95 % CI) and `plots/*.png`.

## Real ledger (Hyperledger Fabric)

Needs Docker and Node.js 22.12+:

```bash
make fabric-up              # installs Fabric 2.5.16 into ~/fabric, starts it, deploys the chaincode
make gateway PORT=3100      # REST gateway (terminal 2)
make run LEDGER=http://127.0.0.1:3100
make fabric-down
```

Without Fabric, `make mock PORT=3100` starts the in-memory mock with the same REST
API; `--ledger mock` (the default) needs no server at all.

## Run the scenario

```bash
python network/run_scenario.py --vehicles 100 --duration 300 --seed 1
```

This builds (or reuses) the SUMO scenario, runs it and writes
`experiments/results/<name>/metrics.csv`, `summary.json`, `config.json`,
`attackers.csv`, plus `flowmon.xml` and `netanim.xml` with ns-3.

Main options (all have defaults; `--help` lists everything):

| Option | Default | |
|---|---|---|
| `--vehicles N` | 100 | vehicles in the SUMO scenario |
| `--duration S` | 300 | simulated seconds |
| `--seed N` | 1 | seed for SUMO, ns-3 and the applications |
| `--rsu-spacing M` | 450 | RSU grid spacing in metres |
| `--data-rate R` | 6 | Mb/s (802.11p, 10 MHz) |
| `--beacon-rate HZ` | 10 | BSM rate |
| `--congestion-control` | off | halve the beacon rate when the channel busy ratio > 0.6 |
| `--protocol` | `stub` | `stub` (stand-in auth flow), `echo`, `real` (Person 3's `protocol/`) |
| `--ledger` | `mock` | `mock`, or the gateway URL for real Fabric, e.g. `http://localhost:3000` |
| `--attacker-ratio F`, `--attack A` | 0, `const_pos` | vehicles that lie in their BSMs |
| `--backend` | `auto` | `ns3`, `lite`, or `auto` (ns-3 if installed) |
| `--netanim` | off | write `netanim.xml` (ns-3) |
| `--net`, `--osm` | grid | a SUMO `.net.xml` (e.g. an InTAS cut) or an OSM extract |
| `--mobility` | `trace` | `trace` (exported ns-2 file) or `traci` (live SUMO coupling) |

Switching to the real parts later is one option each:
`--protocol real --ledger http://localhost:3000`.

## Person 1 checks and results

```bash
python mobility/build_scenario.py --vehicles 100 --duration 300 --seed 1 --traceexporter
python mobility/verify_positions.py mobility/out/grid5x5_250m_v100_d300_s1   # ns-2 vs SUMO positions
python network/range_test.py           # arrive at 100/300 m, fail at 450 m
python network/density_test.py --plot  # PDR and delay for 10..160 vehicles in range
python network/density_sweep.py --vehicles 50 100 150 200 --seeds 1 2 3 --duration 120
pytest network/tests
```

The scenario pipeline and the parameter table are in
[`docs/chapters/simulation_setup.md`](docs/chapters/simulation_setup.md).

## ns-3 on Windows (Docker)

```bash
docker build -t vanet-demo .
docker run --rm -v "$PWD:/work" vanet-demo python network/range_test.py --backend ns3
docker run --rm -v "$PWD:/work" vanet-demo python network/run_scenario.py --backend ns3 --netanim
```

Open `netanim.xml` in NetAnim to watch the run. ns-3 prints harmless
`runStaticInitializersOnce` warnings from cppyy at start-up.

## Scenario from a real map

```bash
python $SUMO_HOME/tools/osmWebWizard.py           # export an area, gives osm.osm.xml.gz
python mobility/build_scenario.py --osm path/to/osm.osm.xml.gz --vehicles 150
python network/run_scenario.py --osm path/to/osm.osm.xml.gz --vehicles 150
```
