# Results: presentation_report_k

Mean ± 95 % confidence interval over the seeds. Latencies are simulated time (radio + queueing + the measured compute times). `–` = not measured in this setting.

| metric | report_k=1 | report_k=2 | report_k=3 |
|---|---|---|---|
| auth latency, median (ms) | 1.96 ± 0.06 | 1.97 ± 0.08 | 1.96 ± 0.05 |
| auth latency, p95 (ms) | 4.31 ± 3.32 | 4.72 ± 4.40 | 4.49 ± 3.97 |
| handover latency, median (ms) | 1.59 ± 0.24 | 1.60 ± 0.22 | 1.69 ± 0.33 |
| auth success | 1.000 | 1.000 | 1.000 |
| handover success | 0.990 ± 0.004 | 0.996 ± 0.009 | 0.994 ± 0.006 |
| handovers via PREAUTH | 0.31 ± 0.04 | 0.32 ± 0.06 | 0.30 ± 0.08 |
| BSM PDR | 0.951 ± 0.006 | 0.949 ± 0.007 | 0.948 ± 0.007 |
| channel busy (RSU) | 0.041 ± 0.003 | 0.042 ± 0.002 | 0.043 ± 0.001 |
| security bytes / BSM | 145 ± 0 | 145 ± 0 | 145 ± 0 |
| attackers reported | 0.94 ± 0.24 | 0.94 ± 0.24 | 0.94 ± 0.24 |
| attackers revoked | 0.94 ± 0.24 | 0.67 | 0.50 ± 0.41 |
| first lie -> report, median (s) | 0.97 ± 3.05 | 0.97 ± 3.05 | 0.97 ± 3.05 |
| report -> revocation (s) | 0.46 ± 0.07 | 10.57 ± 11.91 | 25.01 ± 39.39 |
| first lie -> identity reveal (s) | 7.97 ± 12.01 | 15.23 ± 12.19 | 33.59 ± 29.44 |
| honest flagged | 0.0 | 0.0 | 0.0 |
| honest reported | 0.0 | 0.0 | 0.0 |
| honest revoked | 0.0 | 0.0 | 0.0 |
| pseudonym changes / vehicle | 1.5 ± 0.2 | 1.4 ± 0.2 | 1.4 ± 0.2 |
| seeds | 3 | 3 | 3 |

## Which detector checks fired

Counted once per pseudonym and RSU (the first flag). Honest flags alone revoke nothing: a pseudonym is reported after K flagged BSMs out of W, and revoked when 2 different RSUs report it.

| check | flags on attackers | flags on honest vehicles |
|---|---|---|
| pos_jump | 48 | 0 |
| pos_speed | 48 | 0 |
| range | 91 | 0 |

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
