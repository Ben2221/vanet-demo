"""Train and evaluate the machine-learning detector (Person 4).

    python -m detection.train                          # generated data, quick check
    python -m detection.train --data path/to/NextGen   # real data (train/test by vehicle)
    python -m detection.train --data train_dir --test-data test_dir

The model is a Random Forest on the rule-check outputs and the numeric features
of detection/detector.py. Train and test sets are split BY VEHICLE. Report
per-attack precision, recall and F1, never just accuracy: the data is
imbalanced (most messages are honest) and class_weight="balanced" is used.

Scores on generated data are optimistic. For the report use the real NextGen
test split via --data / --test-data.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from detection import detector as det
from detection.evaluate import format_table, per_attack_metrics, run_detector, vehicle_metrics
from detection.generator import generate
from detection.loaders import load, split_by_vehicle


def features_of(results: list[dict]):
    import numpy as np
    X = np.array([det.feature_vector(r["features"]) for r in results])
    y = np.array([r["label"] for r in results])
    return X, y


def main(argv=None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=None, help="VeReMi / NextGen file or folder (default: generated data)")
    ap.add_argument("--test-data", default=None, help="separate test file or folder (default: split --data by vehicle)")
    ap.add_argument("--vehicles", type=int, default=120, help="vehicles when generating")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--out", default=str(det.MODEL_PATH))
    ap.add_argument("--metrics", default=None, help="write the per-attack metrics to this JSON file")
    ap.add_argument("--sample", type=float, default=1.0,
                    help="keep this fraction of the sender vehicles of --data (memory; VeReMi Extension has 3.2 M messages)")
    ap.add_argument("--profile", default=None, help="detector profile: 'scenario' (default) or 'veremi' (physical datasets)")
    a = ap.parse_args(argv)
    if a.profile:
        det.use_profile(a.profile)

    from sklearn.ensemble import RandomForestClassifier
    import joblib

    if a.data:
        train_raw = load(a.data, sample=a.sample)
        test_raw = load(a.test_data, sample=a.sample) if a.test_data else None
        if test_raw is None:
            train_raw, test_raw = split_by_vehicle(train_raw, seed=a.seed)
        source = a.data
    else:
        train_raw = generate(n_vehicles=a.vehicles, seed=a.seed)
        test_raw = generate(n_vehicles=a.vehicles, seed=a.seed + 100)      # new vehicles, new seed
        source = "generated"

    # features come from the rules (detector.rule_features), computed in reception order
    train, test = run_detector(train_raw, _rules), run_detector(test_raw, _rules)
    Xtr, ytr = features_of([r for r in train if not r.get("ambiguous")])
    Xte, yte = features_of([r for r in test if not r.get("ambiguous")])

    model = RandomForestClassifier(n_estimators=a.trees, class_weight="balanced", n_jobs=-1,
                                   random_state=a.seed, min_samples_leaf=5)
    model.fit(Xtr, ytr)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, a.out)

    keep = [r for r in test if not r.get("ambiguous")]
    scores = model.predict_proba(Xte)[:, 1]
    ml_results = [{**r, "flagged": bool(s >= 0.5)} for r, s in zip(keep, scores)]
    rule_m, ml_m = per_attack_metrics(test), per_attack_metrics(ml_results)
    print(f"source: {source}   train msgs {len(train)}   test msgs {len(test)}")
    print("\nRULES"); print(format_table(rule_m))
    print("\nRANDOM FOREST"); print(format_table(ml_m))
    imp = sorted(zip(det.FEATURES, model.feature_importances_), key=lambda p: -p[1])[:8]
    print("\ntop features:", ", ".join(f"{n} {v:.2f}" for n, v in imp))
    # vehicle level: the K-of-W reporting rule the RSUs use, on the rules' and the forest's flags
    veh = {"rules": vehicle_metrics(test), "random_forest": vehicle_metrics(ml_results)}
    for name, v in veh.items():
        print(f"\n{name}: {v['detected']}/{v['attackers']} attacker vehicles reported, "
              f"{v['honest_reported']}/{v['honest']} honest vehicles reported, median delay {v['delay_s_median']}")
    out = {"source": source, "sample": a.sample, "profile": a.profile or "scenario",
           "train_messages": len(train), "test_messages": len(test),
           "train_vehicles": len({r["vehicle"] for r in train}), "test_vehicles": len({r["vehicle"] for r in test}),
           "rules": rule_m, "random_forest": ml_m, "vehicles": veh, "features": det.FEATURES}
    if a.metrics:
        Path(a.metrics).parent.mkdir(parents=True, exist_ok=True)
        Path(a.metrics).write_text(json.dumps(out, indent=2))
    return out


def _rules(bsm, history):
    f = det.rule_features(bsm, history)
    return det.rules_flag(f), f


if __name__ == "__main__":
    main()
