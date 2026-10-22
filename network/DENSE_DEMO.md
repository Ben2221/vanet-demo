# Dense presentation: 250 cars in 1 km²

A separate high-density demo using the existing live browser UI, **ns-3 IEEE
802.11p**, **SUMO/TraCI** and the **real v3-fast protocol**. The small visibility
demo and the original simulation files are unchanged.

## Launch from Windows

From PowerShell in the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\network\start_dense_demo.ps1
```

The Windows browser opens **http://localhost:8766**. This uses the Ubuntu WSL
Python environment already installed at `~/.local/share/vanet-demo-venv`.

The default run is **30 simulated seconds**, paced at 1× when your machine can
keep up. With 250 vehicles, real radio events and cryptography can make it run
**slower than real time**. The displayed simulation clock is authoritative.
The final state stays available until **Ctrl+C**. Relaunch to replay.

On this machine, a short development run took about **10 wall seconds per
simulated second**. The full live preview exceeded a five-minute execution
limit before finishing 30 simulated seconds, although the UI showed all 250
cars and detection events. Budget several minutes for the default presentation;
selecting a faster UI speed cannot overcome the simulation's compute cost.
The PowerShell launcher does not impose that five-minute limit.

For a longer presentation:

```powershell
powershell -ExecutionPolicy Bypass -File .\network\start_dense_demo.ps1 -Duration 60
```

## Population and map

| Item | Configuration |
|---|---|
| Road footprint | 1,000 m × 1,000 m: exactly 1 km² |
| Roads | 5 × 5 junctions, 250 m blocks, two lanes in each direction |
| Vehicles on the map | **250 from time zero, throughout the run** |
| Ordinary vehicles | **200**, `veh50`–`veh249` |
| Emergency vehicles | **25**, `veh25`–`veh49`, registered emergency class and priority |
| Attackers | **25**, `veh0`–`veh24` |
| RSUs | **9**, 450 m spacing, 300 m nominal service range |
| Attack | Random-position spoofing, starting at **10 s** |
| Mobility coupling | Live TraCI updates every **0.1 s** |
| Ledger | Built-in mock with delayed commit visibility; no Fabric server needed |

Unlike a random-trip run that gradually inserts 250 vehicles, this starts with
all 250 distributed over separated road/lane positions. Valid repeated block
routes keep them on the map. The SUMO builder checks the actual population at
every timestep and refuses to run if it is not exactly 250.

## What to show

1. **0–10 s:** full-density traffic, real authentication, emergency-class logins
   and emergency priority.
2. **From 10 s:** attackers falsify their positions. Watch detection reports,
   quarantine and ledger revocation in the event feed. Actual outcomes depend
   on reception, evidence and thresholds; detection is not staged.
3. Click ordinary, emergency and attacker vehicles to inspect their pseudonym,
   RSU, ticket and recent events. Click an RSU to inspect CPU backlog and load.
4. Keep **ranges** and **show attackers** enabled; leave **labels** off until
   selecting a vehicle to avoid clutter. The existing legend identifies each
   category, including revoked vehicles.
5. Pause, pan and zoom using the existing UI controls.

RSU CPU queues, V2V verification, measured crypto delays, RSSI/rule detection,
privacy logging, fast revocation and emergency priority are enabled. Only
clustering is disabled in this preset so crossings can demonstrate handovers.
Emergency priority here is protocol/radio/verification priority, not automatic
traffic-light preemption. All SUMO vehicles respect passenger road permissions.

## WSL command and options

From the repository directory inside Ubuntu:

```sh
~/.local/share/vanet-demo-venv/bin/python network/dense_demo.py --open-browser
```

- `--duration 60`: 60 simulated seconds instead of 30.
- `--attack fake_emergency`: use fake-emergency attackers instead of position
  spoofers; the 25 legitimate emergency vehicles remain separate.
- `--attack flood`: use the existing flooding attack instead.
- `--attack-start 15`: delay attack onset.
- `--viz-port 8767`: use another local port.
- `--netanim`: also record NetAnim movement, with role colors. Packet tracing is
  intentionally off to avoid an enormous animation file at this density.
- `--hold-seconds 15`: close the UI server 15 seconds after completion.
- `--build-only`: build and verify the populated SUMO map without running ns-3.
- `--no-viz`: run without the live UI.

Each run uses one selected attack type; it does not claim to combine every
attack model simultaneously. Ground-truth attacker colors are for the audience
only and are not used by the detector.

## Saved results

Every launch now creates a **new UTC-timestamped run folder**; previous runs are
never overwritten:

```text
experiments/results/dense_presentation_250/
  reference.json                 points to the existing 3-second development result
  latest.json                    points to the latest successfully completed run
  runs.csv                       one row per completed run, using the project collector
  runs/<timestamp>_v250_d30_s1/
    run_status.json              running / completed / interrupted / failed / built
    run.log                      console messages and Python errors
    config.json                  actual simulation settings and crypto cost values
    summary.json                 final network measurements, only after completion
    results.json                 derived metrics from experiments/collect.py
    metrics.csv                  standard per-event CSV
    attackers.csv
    vehicle_roles.csv
    protocol_stats.json
    observed_bsms.csv
    flowmon.xml
    progress.json                last saved simulated time, updated every second
    ui_state.json                final browser state, when the UI is enabled
    ui_network.json              roads and RSUs used by the browser
    ui_feed.json                 final retained event feed
    mobility/                    SUMO config, routes, road map, FCD and trace
```

The original flat result files are retained as a reference. They represent the
completed **3-second** development run, **not** a completed 30-second experiment.
The interrupted 30-second preview cannot be reconstructed into a complete result.

Completed runs use the same `config.json`, `summary.json`, `metrics.csv` and
`attackers.csv` format as the other experiments. `results.json` and `runs.csv`
reuse the existing collector rather than inventing a new metric schema. A
single seed is not treated as a multi-seed experiment: no artificial averages
or confidence intervals are generated.

A failed or interrupted run keeps its own logs, config and available events,
but does **not** replace `latest.json` or appear as completed in `runs.csv`.
A hard process kill may leave its status as `running`; a missing completion
record means it must not be treated as a completed measurement. A build-only
run has state `built` and no network result. Results remain Git-ignored, matching
the repository's existing policy; they are saved on disk, not committed.
