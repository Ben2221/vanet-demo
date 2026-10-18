# Misbehaviour detection (Person 4)

Authentication does not stop a registered car from lying in its safety messages. The
detector at each RSU finds those cars; the RSU reports the pseudonym; the ledger revokes it
after K=2 different RSUs report it.

| File | What |
|---|---|
| `detector.py` | `check(bsm, history) -> (flagged, features)` (interface 5). Rule-based checks; optional Random Forest |
| `reporting.py` | `ReportingRule(k, w)`: report a pseudonym after K flagged messages out of its last W |
| `generator.py` | labelled BSM streams: honest + const_pos, random_pos, const_speed, random_speed, sudden_stop, replay, flood, sybil |
| `loaders.py` | one loader for VeReMi, VeReMi Extension and VeReMi NextGen → the same message dicts |
| `evaluate.py` | per-attack precision / recall / F1 / FPR, vehicle-level detection and false-report rates, K/W tuning |
| `train.py` | trains and evaluates the Random Forest, train/test split **by vehicle** |
| `tests/` | `pytest detection/tests` |

```bash
pip install -r detection/requirements.txt
pytest detection/tests
python -m detection.evaluate --vehicles 80          # rules on generated data, per-attack table
python -m detection.train --metrics detection/results/generated_metrics.json
python -m detection.train --data <NextGen train dir> --test-data <NextGen test dir> \
       --metrics detection/results/nextgen_metrics.json      # the numbers for the report
```

The scenario picks the detector up by itself (`--detector auto` imports
`detection.detector.check`). `VANET_DETECTOR=ml` switches to the Random Forest
(needs `detection/models/rf.joblib`, made by `train.py`, not committed).

## The checks

Hard checks (any one flags the message): `range`, `speed_range`, `pos_jump`, `speed_cons`,
`pos_speed`, `heading`, `msg_rate`, `replay`, `sybil`. Weak checks (two together flag):
`sudden_appear`, `overlap`. `foreign` is information, not a rule (see below).

* `pos_speed` compares the claimed speed, averaged over the last 0.8-3 s, with the speed
  implied by the path through the received positions (path length, so corners do not hurt).
* `replay` fires when time or sequence goes backwards, or when a pseudonym is sent by a
  different network sender than the one that normally uses it.
* `sybil` fires when one sender keeps coming back to the same pseudonyms (A, B, A, B, A):
  ghost vehicles sent by the same radio. A normal pseudonym change never goes back.
* Thresholds have two profiles: `scenario` (our SUMO traces, speed is stepwise so honest
  vehicles show accelerations up to ~20 m/s²) and `veremi` (physical datasets, ≤ 10 m/s²).
  `detector.use_profile("veremi")` or `VANET_PROFILE=veremi`. **Use `veremi` when evaluating on
  VeReMi / NextGen.**

## For Person 3 (protocol / RSU logic)

1. **Do not count `features["foreign"] == 1` messages in the pseudonym's K-of-W window.**
   A foreign message is a copy of someone's message sent by another sender; counting it
   would get the innocent owner revoked. Use `detection.reporting.ReportingRule`, or copy
   its two lines. The copier is caught through its own pseudonym (`sybil`).
2. **Log the pseudonym of each vehicle once:** `node.log("PID_ASSIGN", 0, None, "<pid hex>")`
   from the vehicle node whenever it starts using a pseudonym. Without it the evaluation cannot
   tell which vehicle a reported pseudonym belongs to (it falls back to `PSEUDONYM_CHANGE`
   and `IDENTITY_REVEALED`, and counts what it could not resolve in `pids_unresolved`).
3. K and W: the stand-in uses K=3, W=10. On generated data, K=6, W=10 cut honest false reports
   from 5.6 % to 1.3 % of honest vehicles for 0.3 s more delay (`evaluate.tune_k_w`). The window size hardly
   matters because attack flags come in runs. Re-tune on the NextGen test split before fixing it.

## What is verified, and what is not

* Unit tests (22) pass; detector, reporting rule, generator, loaders.
* On the generator (rules / Random Forest, `detection/results/generated_metrics.json`) the
  overall F1 is 0.94 / 0.97, FPR 0.02 % / 0.05 %. **These are optimistic:** the generator is simpler
  than real traffic. Weak spots: `const_pos` (a constant offset that stays inside radio range
  is invisible to kinematic checks; recall 0.36 / 0.45) and, for the rules, `sudden_stop`
  (0.46) when the vehicle was already slow.
* On Person 1's scenario (`--backend lite`, 30 and 60 vehicles, 3 seeds) every attacker was reported,
  and honest vehicles reported fell from 11 to under 1 per run after the profile and
  averaging changes.
* **Not done:** the real VeReMi NextGen / VeReMi Extension data was not downloaded here (NextGen is
  36 GB). The loader handles the classic VeReMi JSON-lines format from its published layout;
  the Extension CSV and NextGen field names are matched by a list of aliases (`loaders.ALIASES`)
  and **have not been checked against the real files**. Run
  `python -m detection.loaders --inspect <file>` first; if it says a field is missing, add the real
  name to `ALIASES`. The per-attack numbers for the report must come from the real NextGen test split.
* Seen in the stand-in protocol, not in the detector: in the lite scenario one vehicle sent BSMs
  under five different pseudonyms in turn at 10 Hz. `sybil` flags it. Check how
  pseudonyms are chosen in `network/protocols/stub_auth.py` (and make sure the real protocol never
  does this).
