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

## Fits Person 3's `protocol/` (checked against `protocol/rsu.py` and `vehicle.py` on main)

`RSU.verify_bsm` calls `detector.check(payload, history)` with the BSM payload
`{"pid", "fields": {x, y, speed, heading, timestamp, ...}, "ticket"}` and the pseudonym's earlier
payloads. `check` accepts that format as well as the flat one of interface 5 (`detector.normalize`).
Without `seq`, `rsu_x/rsu_y` or `sender` the checks that need them (range, sequence replay,
foreign sender, sybil, sudden appearance) are skipped, and a BSM without x, y, speed and a
time is not flagged and never raises, so `verify_bsm` does not turn it into "malformed_bsm".
`detection/tests/test_protocol_integration.py` runs honest and lying vehicles through the real
`Vehicle` and `RSU` classes: an honest car is never flagged; a car that claims 30 m/s while moving at
10 m/s is reported by both RSUs, revoked on the ledger, and its later BSMs are dropped.

Things for Person 3 / Person 1 to look at (not changed by me):

1. **History length.** `RSU.verify_bsm` keeps only the last `detector_w` payloads (10) as the history.
   The speed checks compare against a message 0.8-3 s old, i.e. 8-30 BSMs at 10 Hz, so keep ~20-30
   payloads of history and use W only for the K-of-W window.
2. **K.** The RSU default is `detector_k=2`. On generated data K=2 reports 8.8 % of honest vehicles,
   K=3 5.6 %, K=6 1.3 % (for 0.3 / 0.4 / 0.7 s delay, `evaluate.tune_k_w`); the ledger needs two RSUs
   to agree, which helps, but re-tune K on the NextGen test split before fixing it.
3. **Repeated reports.** The RSU calls `report_misbehaviour` on every flagged message once the window has
   K flags. `detection.reporting.ReportingRule` reports once per pseudonym; fewer ledger writes.
4. **Time.** The BSM `timestamp` must be simulated time, not `time.time()`; the checks use it to
   compute speeds. (Authentication freshness in `protocol/` uses `time.time()`; that is for Person 1 / 3.)
5. **Network hooks.** `protocol/__init__.py` has no `create_vehicle`, `create_rsu`, `setup` (interface 3),
   so `run_scenario.py --protocol real` cannot load it yet, and `protocol/` writes nothing to the metrics
   CSV. My result collector needs the events `REPORT` (result = pseudonym) and
   `PID_ASSIGN` (node = vehicle, result = pseudonym, once per pseudonym) to score detection per vehicle.
6. When the network layer provides the sender (`node.last_sender`) put it in `fields["sender"]` and the RSU's
   receive position in `fields["rsu_x"], fields["rsu_y"]`: that switches on the replay-by-copy, sybil and range
   checks. Messages with `features["foreign"] == 1` must not count towards the pseudonym's window.

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
  under five different pseudonyms in turn at 10 Hz. `sybil` flags it. Cause: the stand-in
  rotated its pseudonym right after the 3rd session, so a car ping-ponging between two RSUs cycled
  pseudonyms. Fixed: it now rotates at the next full authentication, as the real protocol does.
