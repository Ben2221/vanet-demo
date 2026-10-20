# Results and how to present them

All numbers: real protocol (`--protocol real`), lite 802.11p backend, mock ledger with 500 ms
commit, 120 s of simulated traffic on the 1 km² SUMO grid with 9 RSUs, 3 seeds per setting,
mean ± 95 % CI. Full tables and every figure are in each folder's `REPORT.md`.

| Folder | Config | Question it answers |
|---|---|---|
| [`compare_bsm_ticket/`](compare_bsm_ticket/REPORT.md) | `experiments/configs/compare_bsm_ticket.json` | Latency, delivery and channel load as traffic grows; full ticket vs. digest in BSMs |
| [`presentation_attacks/`](presentation_attacks/REPORT.md) | `presentation_attacks.json` | Is every attack caught, how fast, with how many false alarms? |
| [`presentation_report_k/`](presentation_report_k/REPORT.md) | `presentation_report_k.json` | How many RSUs should have to agree before a revocation? |

Slides built from these numbers: [`../presentation/vanet_results.pptx`](../presentation/vanet_results.pptx).

## Headline numbers (60 vehicles, 10 % attackers)

| | |
|---|---|
| Authentication latency (median / p95) | **1.96 ms / ~4.5 ms** (radio + queueing + ZKP verification) |
| Handover latency (median) | **1.6 ms**; 99 % success; ~30 % accepted via PREAUTH before the ledger commit was visible |
| BSM delivery ratio / channel busy at RSUs | **0.95 / 4.2 %** |
| Security bytes per BSM | **145 B** (was 288 B) |
| Attackers reported | **100 %** for 5 of 6 attack types, 94 % for `const_pos` |
| First lying BSM → report (median) | **0.16–1.1 s** (flood fastest, speed lies ~1 s because the check needs a 0.8 s baseline) |
| Report → revocation visible | **~2.4 s** (needs a second RSU; `const_pos` 10.6 s) |
| First lying BSM → identity revealed, all pseudonyms revoked | **4–5 s** (`const_pos` 15 s) |
| Honest vehicles flagged / reported / revoked | **0 / 0 / 0** |

## Before vs. after the fixes in this branch (same 18 attack runs)

| | Before | After |
|---|---|---|
| Honest vehicles flagged at least once, per run | 12.7 | **0** |
| Time to first report (as reported by the collector) | 14–31 s (measured from attack start) | **0.16–1.1 s** (from the first lying BSM) |
| Mean BSM size | 333 B | **190 B** |
| Channel busy at RSUs | 6.0 % | **4.2 %** |
| BSM delivery ratio | 0.927 | **0.949** |
| Runs failing in a parallel sweep | 1 of 18 | **0** |

Density (`compare_bsm_ticket`, digest vs. full ticket): at 90 vehicles the channel busy ratio
drops from 8.6 % to 6.0 % and PDR rises from 0.892 to 0.928; authentication and detection are
unchanged.

## The K trade-off (`const_pos`, the hardest attack)

| K (RSUs that must report) | 1 | **2 (ours)** | 3 |
|---|---|---|---|
| Attackers revoked within 120 s | 94 % | 67 % | 50 % |
| Report → revocation | 0.5 s | 10.6 s | 25 s |
| Who can revoke an honest car | any single RSU | two colluding RSUs | three |

Say it this way: *K = 2 costs us revocation of attackers that only one RSU ever sees, and buys
"no single RSU can revoke anyone".* The attackers missed at K = 2 were reported (identified as
lying) but drove out of coverage before a second RSU saw them.

## How to show results (what to put on which slide)

1. **One headline slide with 4 big numbers**: auth latency, handover latency, attackers
   reported, honest vehicles revoked. Footnote the setup (lite radio, mock ledger, 3 seeds).
2. **Latency vs. vehicles** (`compare_bsm_ticket/plots/auth_latency.png`) — shows it scales.
3. **BSM size and channel load, full ticket vs. digest** — a design improvement with a number.
4. **Per-attack bars**: time to report and reported/revoked share
   (`presentation_attacks/plots/first_report_delay.png`, `revocation_rate.png`).
5. **The K trade-off** — shows you understand the security/performance tension.
6. **"Which checks fired" table** from `REPORT.md` — answers "how does the detector know?".
7. **Limitations slide** — state them before you are asked (see `docs/HOW_IT_WORKS.md`, §9).

Always show the confidence interval or say "mean of 3 seeds"; never show a single run.

## Reproduce

```bash
pip install -r requirements.txt
python experiments/run.py --config experiments/configs/compare_bsm_ticket.json --jobs 4
python experiments/run.py --config experiments/configs/presentation_attacks.json --jobs 4
python experiments/run.py --config experiments/configs/presentation_report_k.json --jobs 4
python experiments/export_results.py compare_bsm_ticket presentation_attacks presentation_report_k
cd docs/presentation && npm install pptxgenjs && node build_deck.js
```

For the final report, run the same configs with ns-3 (`"backend": "ns3"`, Docker on Windows) and
the real Fabric gateway (`"ledger": "http://localhost:3000"`), and with 300 s runs
(`attacks.json`, `density.json`, `sweep_report_k.json`).
