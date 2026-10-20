# Results: realmap_schemes

Mean ± 95 % confidence interval over the seeds. Latencies are simulated time (radio + queueing + the measured compute times). `–` = not measured in this setting.

| metric | protocol=experiments.baselines.central_auth, vehicles=120 | protocol=experiments.baselines.central_auth, vehicles=60 | protocol=experiments.baselines.ecdsa_pki, vehicles=120 | protocol=experiments.baselines.ecdsa_pki, vehicles=60 | protocol=real, vehicles=120 | protocol=real, vehicles=60 |
|---|---|---|---|---|---|---|
| auth latency, median (ms) | 22.28 ± 0.02 | 22.23 ± 0.03 | 1.40 ± 0.25 | 1.29 ± 0.03 | 2.41 ± 0.46 | 1.96 ± 0.03 |
| auth latency, p95 (ms) | 24.92 ± 0.24 | 23.69 ± 0.91 | 5.44 ± 2.23 | 3.11 ± 0.47 | 9.90 ± 7.28 | 4.30 ± 1.72 |
| handover latency, median (ms) | 22.21 ± 0.02 | 22.17 ± 0.03 | 1.30 ± 0.20 | 1.19 ± 0.06 | 2.16 ± 2.64 | 1.43 |
| auth success | 1.000 | 1.000 | 0.999 ± 0.004 | 1.000 | 0.997 ± 0.009 | 1.000 |
| handover success | 0.990 ± 0.008 | 0.989 ± 0.019 | 0.990 ± 0.008 | 0.989 ± 0.020 | 0.990 ± 0.008 | 0.986 ± 0.021 |
| handovers via PREAUTH | 0.00 | 0.00 | 0.00 | 0.00 | 0.26 ± 0.20 | 0.32 ± 0.06 |
| BSM PDR | 0.939 ± 0.008 | 0.968 ± 0.007 | 0.938 ± 0.009 | 0.968 ± 0.007 | 0.919 ± 0.014 | 0.961 ± 0.005 |
| channel busy (RSU) | 0.031 ± 0.001 | 0.018 ± 0.001 | 0.031 ± 0.001 | 0.018 ± 0.001 | 0.039 ± 0.001 | 0.023 ± 0.000 |
| security bytes / BSM | 72 | 72 | 72 | 72 | 145 ± 1 | 145 ± 0 |
| attackers reported | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| attackers revoked | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| first lie -> report, median (s) | 0.24 ± 0.03 | 0.25 ± 0.07 | 0.26 ± 0.04 | 0.26 ± 0.07 | 0.27 ± 0.03 | 0.27 ± 0.09 |
| report -> revocation (s) | 0.82 ± 1.05 | 1.36 ± 2.42 | 0.82 ± 1.05 | 1.36 ± 2.42 | 0.86 ± 0.86 | 1.34 ± 2.30 |
| first lie -> identity reveal (s) | 2.33 ± 1.05 | 2.80 ± 2.31 | 2.34 ± 1.05 | 2.81 ± 2.31 | 2.39 ± 1.14 | 2.93 ± 2.49 |
| honest flagged | 1.7 ± 1.4 | 0.7 ± 1.4 | 1.7 ± 1.4 | 0.7 ± 1.4 | 1.7 ± 1.4 | 0.7 ± 1.4 |
| honest reported | 0.0 | 0.3 ± 1.4 | 0.0 | 0.3 ± 1.4 | 0.0 | 0.3 ± 1.4 |
| honest revoked | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| pseudonym changes / vehicle | 3.2 ± 0.4 | 3.1 ± 1.0 | 3.2 ± 0.4 | 3.1 ± 1.1 | 2.0 ± 0.1 | 1.9 ± 0.3 |
| seeds | 3 | 3 | 3 | 3 | 3 | 3 |

## Which detector checks fired

Counted once per pseudonym and RSU (the first flag). Honest flags alone revoke nothing: a pseudonym is reported after K flagged BSMs out of W, and revoked when 2 different RSUs report it.

| check | flags on attackers | flags on honest vehicles |
|---|---|---|
| heading | 24 | 60 |
| pos_jump | 358 | 0 |
| pos_speed | 151 | 6 |
| range | 282 | 0 |

## Figures

![attack_to_exclusion](plots/attack_to_exclusion.png)
![auth_latency](plots/auth_latency.png)
![auth_success](plots/auth_success.png)
![channel_busy](plots/channel_busy.png)
![detection_rate](plots/detection_rate.png)
![first_report_delay](plots/first_report_delay.png)
![handover_latency](plots/handover_latency.png)
![handover_success](plots/handover_success.png)
![handover_via_preauth](plots/handover_via_preauth.png)
![honest_flagged](plots/honest_flagged.png)
![honest_wrongly_revoked](plots/honest_wrongly_revoked.png)
![ledger_commit](plots/ledger_commit.png)
![ledger_commit_p95](plots/ledger_commit_p95.png)
![pdr](plots/pdr.png)
![report_to_revocation](plots/report_to_revocation.png)
![revocation_rate](plots/revocation_rate.png)
![security_bytes](plots/security_bytes.png)
