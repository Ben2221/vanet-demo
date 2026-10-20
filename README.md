# VANET Authentication Demo

Vehicles drive on real roads in SUMO and talk over IEEE 802.11p in ns-3. They
authenticate anonymously to roadside units (RSUs) with zero-knowledge proofs;
authorization, revocation and identity-reveal approvals live on Hyperledger
Fabric.

**New here? Read [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md)** (the whole mechanism, step by
step, with the questions reviewers ask) and [`docs/results/README.md`](docs/results/README.md)
(current results and how to present them).

This repository contains the implementation and documentation for our Bachelor Thesis Project (BTP), focused on network simulation using NS-3. It also contains the Hyperledger Fabric ledger setup for the VANET demo, defined in `ledger/` and planned in `chain_structure.md`. For detailed ledger architecture, operation, validation, and AI handoff context, see [`ledger/IMPLEMENTATION_CONTEXT.md`](ledger/IMPLEMENTATION_CONTEXT.md).

## Setup

Linux (Fedora, Ubuntu) or WSL2, Python 3.11–3.13:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install ns3            # ns-3 3.44+ Python bindings (Linux only)
```

On Windows without WSL2, either use the Docker image
(`docker build -t vanet-demo .`, see `Dockerfile`) or skip ns-3: every script
then falls back to the **lite backend**, a small pure-Python 802.11p model with
the same radio parameters. Use it for development and tests; final results
come from ns-3 (`--backend ns3`).

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
| `--protocol` | `stub` | `stub` (stand-in auth flow), `echo`, `real` (Person 3's `protocol/`; all experiment configs use `real`) |
| `--full-ticket-every N` | 10 | real protocol: full ticket in every N-th BSM, 8-byte digest otherwise (1 = always full) |
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

A real city is in the repository: central Monaco from OpenStreetMap (see `mobility/maps/README.md`).

```bash
python network/run_scenario.py --net mobility/maps/monaco_centre.net.xml --vehicles 100 --protocol real
python experiments/run.py --config experiments/configs/realmap_schemes.json --jobs 4
```

Your own city (cut a 1–3 km² centre with `--bbox minlon,minlat,maxlon,maxlat`):

```bash
python $SUMO_HOME/tools/osmWebWizard.py           # export an area, gives osm.osm.xml.gz
python mobility/build_scenario.py --osm path/to/osm.osm.xml.gz --vehicles 150
python network/run_scenario.py --osm path/to/osm.osm.xml.gz --vehicles 150
```
