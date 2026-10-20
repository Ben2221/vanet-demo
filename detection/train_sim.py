"""Train the simulator's detector model on simulator data (Person 4).

The model trained on VeReMi Extension (detection/benchmark.py) does not transfer to our
SUMO/ns-3 traffic: in a grid run it flagged ~80 honest vehicles. Kinematics differ (VeReMi
is LuST at Veins' sampling, ours SUMO at 0.1 s), so the simulator gets its own model:

    # labelled training data: RSUs log every checked BSM (grid, seeds 11-12, six attacks)
    python network/run_scenario.py ... --detector-log --out experiments/results/detector_train/<run>
    python -m detection.train_sim experiments/results/detector_train/*

  1. read every detector_log.npz (features of every BSM an RSU checked, ground truth);
  2. split BY VEHICLE: 70 % train, 30 % validation;
  3. gradient boosting (HistGradientBoosting, balanced classes) on the train vehicles;
  4. threshold: the lowest probability at which the hybrid detector (rules OR model) reports
     no more honest vehicles under the RSUs' K-of-W rule (K = 3 of W = 10) on the
     validation vehicles than the rules alone do, so the model only adds attackers;
  5. refit on all vehicles and save detection/models/hgb_sim.joblib (a ThresholdModel).

Use it with --detector-mode hybrid --detector-model detection/models/hgb_sim.joblib, and
evaluate it on scenarios it has not seen (LuST, other seeds).
"""
from __future__ import annotations

import argparse
import json
import zlib
from collections import defaultdict, deque
from pathlib import Path

import numpy as np

from detection import detector as det

OUT = Path(__file__).resolve().parent / "models" / "hgb_sim.joblib"
K, W = 3, 10


def load(dirs: list[str]) -> dict:
    parts = [np.load(Path(d) / "detector_log.npz", allow_pickle=False) for d in dirs
             if (Path(d) / "detector_log.npz").exists()]
    if not parts:
        raise SystemExit("no detector_log.npz found (run scenarios with --detector-log)")
    feats = [str(f) for f in parts[0]["features"]]
    if feats != det.FEATURES:
        raise SystemExit("detector features changed since these logs were written; regenerate them")
    run_ids = np.concatenate([np.full(len(p["y"]), i) for i, p in enumerate(parts)])
    veh = np.concatenate([p["vehicle"] for p in parts])
    return {"X": np.vstack([p["X"] for p in parts]), "y": np.concatenate([p["y"] for p in parts]),
            "vehicle": np.array([f"{r}:{v}" for r, v in zip(run_ids, veh)]),   # vehicles differ per run
            "pid": np.array([f"{r}:{p}" for r, p in zip(run_ids, np.concatenate([q["pid"] for q in parts]))]),
            "t": np.concatenate([p["t"] for p in parts]), "runs": len(parts)}


def vehicles_reported(d: dict, mask: np.ndarray, flag: np.ndarray) -> tuple[set, set]:
    """K-of-W per pseudonym in time order; returns (reported vehicles, attacker vehicles)."""
    order = np.argsort(d["t"][mask], kind="stable")
    idx = np.nonzero(mask)[0][order]
    win: dict = defaultdict(lambda: deque(maxlen=W))
    reported, attackers = set(), set()
    for i in idx:
        if d["y"][i]:
            attackers.add(d["vehicle"][i])
        q = win[d["pid"][i]]
        q.append(bool(flag[i]))
        if sum(q) >= K:
            reported.add(d["vehicle"][i])
    return reported, attackers


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args(argv)
    import joblib
    from sklearn.ensemble import HistGradientBoostingClassifier
    d = load(a.runs)
    rules = np.array([any(x[det.FEATURES.index(k)] for k in det.HARD)
                      or sum(x[det.FEATURES.index(k)] for k in det.WEAK) >= 2 for x in d["X"]])
    val = np.array([zlib.crc32(v.encode()) % 100 < 30 for v in d["vehicle"]])
    make = lambda: HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1,  # noqa: E731
                                                   class_weight="balanced", random_state=1)
    m = make().fit(d["X"][~val], d["y"][~val])
    p = np.zeros(len(d["y"]))
    p[val] = m.predict_proba(d["X"][val])[:, 1]
    rep_rules, attackers = vehicles_reported(d, val, rules)
    honest_rules = len(rep_rules - attackers)
    chosen, table = 0.999, []
    for thr in (0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.98, 0.99, 0.995, 0.999):
        rep, _ = vehicles_reported(d, val, rules | (p >= thr))
        honest = len(rep - attackers)
        table.append({"threshold": thr, "attackers_reported": len(rep & attackers), "attackers": len(attackers),
                      "honest_reported": honest, "honest_reported_rules_only": honest_rules,
                      "message_recall": float(((rules | (p >= thr)) & (d["y"] == 1))[val].sum() / max(1, (d["y"][val] == 1).sum())),
                      "message_fpr": float(((rules | (p >= thr)) & (d["y"] == 0))[val].sum() / max(1, (d["y"][val] == 0).sum()))})
    for row in table:                       # lowest threshold that adds no honest report
        if row["honest_reported"] <= honest_rules:
            chosen = row["threshold"]
            break
    final = make().fit(d["X"], d["y"])
    info = {"runs": d["runs"], "messages": int(len(d["y"])), "attack_messages": int(d["y"].sum()),
            "vehicles": int(len(set(d["vehicle"]))), "threshold": chosen, "k": K, "w": W,
            "rules_only_validation": {"attackers_reported": len(rep_rules & attackers), "attackers": len(attackers),
                                      "honest_reported": honest_rules},
            "threshold_table": table}
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(det.ThresholdModel(final, chosen, info), a.out)
    Path(a.out).with_suffix(".json").write_text(json.dumps(info, indent=1))
    for row in table:
        print(row)
    print(f"threshold {chosen} -> {a.out}")


if __name__ == "__main__":
    main()
