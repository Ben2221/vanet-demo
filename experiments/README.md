# Experiments and results (Person 4)

One command runs Person 1's scenario over a grid, with several seeds, and writes means
with 95 % confidence intervals and every figure.

```bash
python experiments/run.py --config experiments/configs/quick.json        # ~25 s, lite backend, 6 runs
python experiments/run.py --config experiments/configs/density.json --jobs 4
python experiments/run.py --config experiments/configs/compare_schemes.json --jobs 4
python experiments/run.py --config <cfg> --collect-only                  # rebuild tables and figures only
python experiments/run.py --config <cfg> --dry-run                       # print the commands
```

Results go to `experiments/results/<name>/` (git-ignored): `runs/<run>/` (the scenario's own
output, cached so an interrupted sweep resumes), `runs.csv` (one row per run), `aggregate.csv`
(mean and `_ci95` per setting), `plots/*.png` + `*.csv` (the plotted numbers).

| Config | Sweeps | For |
|---|---|---|
| `quick.json` | vehicles 30, 60 | check that everything works |
| `density.json` | vehicles × attacker ratio | latency, PDR, channel load, detection |
| `sweep_rsu_spacing.json` | RSU spacing 300, 450, 600 m | |
| `sweep_beacon_rate.json` | beacon rate 2, 5, 10 Hz | |
| `compare_schemes.json` | vehicles, 3 schemes | ours vs ECDSA certificates vs central authority |
| `attacks.json` | each attack | time to report, revocation, false revocations |

A config lists any `network/run_scenario.py` option (`_` for `-`). At least 3 seeds are
needed; the runner warns otherwise. Change `backend` to `ns3` for the final numbers and
`ledger` to the gateway URL for real Fabric. `--protocol real` needs the network hooks in Person 3's `protocol/` (see
`detection/README.md`, item 5); the configs use `stub` until then.

## Before the final sweep

1. `python experiments/measure_ecdsa.py --merge <Person 3's compute-times.json> --out experiments/compute_times_all.json`
   (the configs read that file for the processing delays; without `--merge` you get ECDSA only).
2. Fabric commit time and throughput come from Person 2's benchmark; copy the plotted
   numbers into the report. Per-run commit times are also read from `LEDGER_SUBMIT` rows.
3. `python -m detection.train --data ... --test-data ... --metrics detection/results/nextgen_metrics.json`
   then `python experiments/plots.py experiments/results/<name> --detection detection/results/nextgen_metrics.json`.

## Figures (all from the aggregate tables)

authentication and handover latency · packet delivery ratio · channel busy ratio · Fabric commit
time (median and p95) · time from first report to revocation · time to first report · honest
vehicles wrongly reported · attackers caught · bytes added by security per BSM · detection
precision/recall/F1 per attack (from the detector metrics JSON).

## Baselines (`experiments/baselines/`)

`--protocol experiments.baselines.ecdsa_pki` and `--protocol experiments.baselines.central_auth`
run in the same scenario as ours. They reuse the stand-in protocol's message flow and change
what the scheme changes: request size, number of verifications, no shared state (every handover
is a full check again), and for the central scheme a backbone round trip (`ca_rtt_ms`, default 20, and
`ca_proc_ms`, default 1) per request. Not modelled: queueing at the authority, certificate
expiry. Handover requests have the same wire size in all three (the stand-in builds them
internally); the difference is the check cost and the round trip. Say this in the report.

`python experiments/op_counts.py` prints the operation-count and message-size table for the
three schemes and appends the papers listed in `experiments/papers_review.csv`. **That file is
empty: fill one row per paper from the review slides** (the numbers must come from the papers).
Times are only estimated when `--times` has measured `ec_mult` and `hash`; take `ec_mult` from
Person 3's real implementation, not from a different library.

## What the numbers mean (and don't)

* The mock ledger's commit time is a setting (`--mock-commit-ms`, default 500), not a result.
  Real commit times come from Fabric.
* Detection numbers per run need `PID_ASSIGN` (see `detection/README.md`); `pids_unresolved`
  says how many reported pseudonyms could not be matched to a vehicle.
* `pytest experiments/tests` checks the grid, the statistics, the collector, the plots, the
  baselines and the operation-count table on small fake runs. It does not run ns-3.
