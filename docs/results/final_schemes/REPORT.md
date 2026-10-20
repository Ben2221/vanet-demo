# Results: final_schemes

Mean ± 95 % confidence interval over the seeds. Latencies are simulated time (radio + queueing + the measured compute times). `–` = not measured in this setting.

| metric | protocol=experiments.baselines.central_auth, vehicles=30 | protocol=experiments.baselines.central_auth, vehicles=60 | protocol=experiments.baselines.central_auth, vehicles=90 | protocol=experiments.baselines.ecdsa_pki, vehicles=30 | protocol=experiments.baselines.ecdsa_pki, vehicles=60 | protocol=experiments.baselines.ecdsa_pki, vehicles=90 | protocol=real, vehicles=30 | protocol=real, vehicles=60 | protocol=real, vehicles=90 |
|---|---|---|---|---|---|---|---|---|---|
| auth latency, median (ms) | 21.93 ± 0.00 | 21.93 ± 0.00 | 21.93 ± 0.00 | 1.06 ± 0.02 | 1.08 ± 0.00 | 1.11 ± 0.05 | 1.54 ± 0.02 | 1.60 ± 0.02 | 1.63 ± 0.02 |
| auth latency, p95 (ms) | 22.75 ± 0.44 | 22.79 ± 0.38 | 23.82 ± 0.20 | 2.26 ± 0.07 | 2.50 ± 0.33 | 3.53 ± 0.43 | 2.77 ± 0.83 | 2.76 ± 0.48 | 4.90 ± 1.48 |
| handover latency, median (ms) | 21.81 ± 0.00 | 21.81 ± 0.00 | 21.81 ± 0.00 | 0.92 ± 0.05 | 0.94 ± 0.05 | 0.96 ± 0.02 | 1.05 ± 0.02 | 1.06 ± 0.03 | 1.09 ± 0.04 |
| auth success | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.998 ± 0.007 | 1.000 |
| handover success | 0.989 ± 0.026 | 0.988 ± 0.016 | 0.990 ± 0.014 | 0.989 ± 0.026 | 0.986 ± 0.017 | 0.990 ± 0.015 | 0.983 ± 0.023 | 0.986 ± 0.005 | 0.983 ± 0.015 |
| handovers via PREAUTH | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.00 | 0.41 ± 0.09 | 0.40 ± 0.04 | 0.41 ± 0.11 |
| BSM PDR | 0.996 ± 0.000 | 0.992 ± 0.002 | 0.988 ± 0.003 | 0.996 ± 0.001 | 0.992 ± 0.001 | 0.988 ± 0.003 | 0.996 ± 0.002 | 0.991 ± 0.003 | 0.986 ± 0.003 |
| channel busy (RSU) | 0.039 ± 0.004 | 0.067 ± 0.004 | 0.094 ± 0.005 | 0.039 ± 0.004 | 0.067 ± 0.004 | 0.094 ± 0.005 | 0.048 ± 0.005 | 0.083 ± 0.005 | 0.116 ± 0.006 |
| security bytes / BSM | 72 | 72 | 72 | 72 | 72 | 72 | 144 ± 0 | 144 ± 0 | 144 ± 0 |
| attackers reported | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| attackers revoked | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| first lie -> report, median (s) | 0.24 ± 0.15 | 0.25 ± 0.05 | 0.24 ± 0.06 | 0.25 ± 0.18 | 0.25 ± 0.05 | 0.25 ± 0.07 | 0.29 ± 0.14 | 0.26 ± 0.08 | 0.27 ± 0.03 |
| report -> revocation (s) | 1.11 ± 1.33 | 2.38 ± 2.68 | 3.45 ± 4.11 | 1.13 ± 1.29 | 2.29 ± 2.78 | 3.26 ± 3.62 | 0.95 ± 1.20 | 2.36 ± 2.33 | 3.59 ± 4.85 |
| first lie -> identity reveal (s) | 2.85 ± 1.91 | 4.02 ± 3.13 | 5.25 ± 4.82 | 2.75 ± 1.73 | 4.03 ± 3.13 | 5.26 ± 4.87 | 2.53 ± 1.23 | 3.86 ± 2.44 | 5.12 ± 4.77 |
| honest flagged | 0.0 | 0.0 | 0.3 ± 1.4 | 0.0 | 0.0 | 0.3 ± 1.4 | 0.0 | 0.0 | 0.3 ± 1.4 |
| honest reported | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| honest revoked | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| pseudonym changes / vehicle | 3.1 ± 1.1 | 3.1 ± 1.0 | 3.1 ± 1.0 | 3.1 ± 1.1 | 3.2 ± 0.8 | 3.1 ± 1.0 | 1.6 ± 0.1 | 1.5 ± 0.2 | 1.5 ± 0.2 |
| seeds | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 |

## Which detector checks fired

Counted once per pseudonym and RSU (the first flag). Honest flags alone revoke nothing: a pseudonym is reported after K flagged BSMs out of W, and revoked when 2 different RSUs report it.

| check | flags on attackers | flags on honest vehicles |
|---|---|---|
| heading | 0 | 6 |
| pos_jump | 282 | 0 |
| pos_speed | 111 | 0 |
| range | 196 | 0 |

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
