# Results: compare_bsm_ticket

Mean ± 95 % confidence interval over the seeds. Latencies are simulated time (radio + queueing + the measured compute times). `–` = not measured in this setting.

| metric | vehicles=30 | vehicles=60 | vehicles=90 | vehicles=30 | vehicles=60 | vehicles=90 |
|---|---|---|---|---|---|---|
| auth latency, median (ms) | 1.88 ± 0.02 | 1.94 ± 0.02 | 2.37 ± 0.14 | 1.88 ± 0.02 | 1.97 ± 0.07 | 2.18 ± 0.43 |
| auth latency, p95 (ms) | 3.43 ± 0.38 | 5.06 ± 3.57 | 7.24 ± 3.40 | 3.28 ± 0.19 | 4.38 ± 3.18 | 7.25 ± 4.04 |
| handover latency, median (ms) | 1.43 ± 0.06 | 1.90 ± 0.18 | 2.29 ± 0.18 | 1.42 ± 0.07 | 1.59 ± 0.22 | 1.94 ± 0.07 |
| auth success | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| handover success | 0.987 ± 0.015 | 0.991 ± 0.001 | 0.995 ± 0.005 | 0.987 ± 0.014 | 0.990 ± 0.004 | 0.993 ± 0.006 |
| handovers via PREAUTH | 0.36 ± 0.03 | 0.27 ± 0.03 | 0.23 ± 0.11 | 0.36 ± 0.03 | 0.31 ± 0.04 | 0.29 ± 0.08 |
| BSM PDR | 0.967 ± 0.010 | 0.929 ± 0.009 | 0.892 ± 0.013 | 0.976 ± 0.008 | 0.951 ± 0.006 | 0.928 ± 0.010 |
| channel busy (RSU) | 0.031 ± 0.001 | 0.058 ± 0.004 | 0.086 ± 0.007 | 0.022 ± 0.001 | 0.041 ± 0.003 | 0.060 ± 0.005 |
| security bytes / BSM | 288 ± 0 | 288 ± 0 | 288 ± 0 | 144 ± 0 | 145 ± 0 | 145 ± 0 |
| attackers reported | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| attackers revoked | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| first lie -> report, median (s) | 0.29 ± 0.14 | 0.26 ± 0.06 | 0.28 ± 0.02 | 0.29 ± 0.14 | 0.26 ± 0.06 | 0.28 ± 0.02 |
| report -> revocation (s) | 1.08 ± 1.06 | 2.46 ± 2.28 | 3.50 ± 3.97 | 1.07 ± 1.05 | 2.43 ± 2.32 | 3.46 ± 4.04 |
| first lie -> identity reveal (s) | 2.64 ± 1.40 | 4.08 ± 2.68 | 5.38 ± 4.64 | 2.64 ± 1.40 | 4.03 ± 2.77 | 5.34 ± 4.73 |
| honest flagged | 0.0 | 0.0 | 0.3 ± 1.4 | 0.0 | 0.0 | 0.3 ± 1.4 |
| honest reported | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| honest revoked | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 |
| pseudonym changes / vehicle | 1.6 ± 0.1 | 1.7 ± 0.3 | 1.7 ± 0.3 | 1.6 ± 0.1 | 1.6 ± 0.3 | 1.6 ± 0.2 |
| seeds | 3 | 3 | 3 | 3 | 3 | 3 |

## Which detector checks fired

Counted once per pseudonym and RSU (the first flag). Honest flags alone revoke nothing: a pseudonym is reported after K flagged BSMs out of W, and revoked when 2 different RSUs report it.

| check | flags on attackers | flags on honest vehicles |
|---|---|---|
| heading | 0 | 4 |
| pos_jump | 181 | 0 |
| pos_speed | 74 | 0 |
| range | 136 | 0 |

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
