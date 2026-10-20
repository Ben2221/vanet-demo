"""Misbehaviour-detection benchmark on VeReMi Extension (Person 4).

    python -m detection.benchmark                       # 30 % of the vehicles, 5 splits
    python -m detection.benchmark --sample 1.0          # all 3.2 M messages (needs ~10 GB RAM)

Steps:
  1. load a deterministic sample of whole sender vehicles (detection/loaders.py);
  2. replay every message in reception order through the rule checks of
     detection/detector.py ("veremi" profile) and keep only compact arrays: the feature
     vector, the rules' verdict and window features (mean / max of the pseudonym's last
     WINDOW feature vectors, so a model sees a little history, like the K-of-W rule);
  3. for SPLITS different train / test splits BY VEHICLE (70 / 30) train and score:
       rules        the rule checks alone (what the RSUs use today)
       rf           Random Forest on the per-message features (detection/train.py)
       hgb          gradient boosting (HistGradientBoosting) on the per-message features
       hgb_window   gradient boosting on per-message + window features
     per attack (precision, recall, F1), overall (+ FPR, PR-AUC, ROC-AUC) and per vehicle
     (the K-of-W reporting rule: attackers reported, honest vehicles reported);
  4. tune K and W on split 0 for the best model; save curves for the figures;
  5. train the per-message model on every sampled vehicle plus generated data in the
     simulator's profile and save it for --detector-mode hybrid (detection/models/).

Output: detection/results/veremi_benchmark.json (+ the model). VeReMi Extension has no
receiver positions or receive times, so the range, sudden-appearance and signal-strength
checks cannot fire on it; the 39 simulations are merged, so cross-pseudonym checks may
compare vehicles of different simulations.
"""
from __future__ import annotations

import argparse
import json
import math
import time
import zlib
from collections import defaultdict, deque
from pathlib import Path

import numpy as np

from detection import detector as det
from detection.loaders import VEREMI_EXT_CLASSES, load_csv
from experiments.stats import mean_ci

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "veremi_ext" / "mixalldata_clean.csv"
OUT = ROOT / "results" / "veremi_benchmark.json"
MODEL_OUT = ROOT / "models" / "hgb_hybrid.joblib"
WINDOW = 10
TARGET_FPR = 0.002      # calibrated models: at most 0.2 % of honest messages flagged (validation)
SPLITS = 5
HIST = 20
WIN_NUMERIC = ["speed_err", "speed_err_cur", "implied_speed", "implied_base", "accel", "heading_delta",
               "rate", "dt"]


def featurize(messages: list[dict]) -> dict:
    """Replay in reception order; return compact arrays."""
    det.reset()
    messages.sort(key=lambda m: m["rx_time"])
    n, F = len(messages), len(det.FEATURES)
    idx = [det.FEATURES.index(k) for k in WIN_NUMERIC]
    hard = [det.FEATURES.index(k) for k in det.HARD]
    X = np.zeros((n, F), np.float32)
    W = np.zeros((n, 2 * len(idx) + 2), np.float32)
    rules = np.zeros(n, bool)
    hist: dict = defaultdict(lambda: deque(maxlen=HIST))
    win: dict = defaultdict(lambda: deque(maxlen=WINDOW))
    keys = ["pid", "seq", "t", "x", "y", "speed", "heading", "rsu_x", "rsu_y", "rx_time", "sender"]
    for i, m in enumerate(messages):
        bsm = {k: m.get(k) for k in keys}
        f = det.rule_features(bsm, list(hist[m["pid"]]))
        hist[m["pid"]].append(bsm)
        v = np.asarray(det.feature_vector(f), np.float32)
        X[i] = v
        rules[i] = det.rules_flag(f)
        w = win[m["pid"]]
        if w:
            a = np.stack(w)
            W[i, :len(idx)] = a[:, idx].mean(0)
            W[i, len(idx):2 * len(idx)] = a[:, idx].max(0)
            W[i, -2] = a[:, hard].sum()                    # hard flags in the window
            W[i, -1] = len(w)
        w.append(v)
    return {"X": X, "W": W, "rules": rules,
            "y": np.array([m["label"] for m in messages], np.int8),
            "attack": np.array([m["attack"] for m in messages]),
            "vehicle": np.array([str(m["vehicle"]) for m in messages]),
            "pid": np.array([str(m["pid"]) for m in messages]),
            "t": np.array([m["rx_time"] for m in messages], np.float64)}


def split_mask(vehicles: np.ndarray, seed: int, test: float = 0.3) -> np.ndarray:
    """True for test messages; whole vehicles go to one side."""
    uniq = np.unique(vehicles)
    is_test = {v: zlib.crc32(f"{seed}:{v}".encode()) % 1000 < test * 1000 for v in uniq}
    return np.array([is_test[v] for v in vehicles])


def scores(y: np.ndarray, flag: np.ndarray, attack: np.ndarray) -> dict:
    honest = y == 0
    fp = int((flag & honest).sum())
    out = {}
    for a in sorted(str(x) for x in set(attack[y == 1])) + ["ALL"]:
        pos = (y == 1) if a == "ALL" else (attack == a)
        tp = int((flag & pos).sum())
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / pos.sum() if pos.sum() else 0.0
        out[a] = {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0,
                  "n": int(pos.sum())}
    out["ALL"]["fpr"] = fp / honest.sum() if honest.sum() else 0.0
    return out


def vehicle_level(d: dict, mask: np.ndarray, flag: np.ndarray, k: int = 3, w: int = 10) -> dict:
    """K-of-W per pseudonym, scored per vehicle (messages already in time order)."""
    win: dict = defaultdict(lambda: deque(maxlen=w))
    reported, attackers, vehicles = set(), set(), set()
    for i in np.nonzero(mask)[0]:
        veh = d["vehicle"][i]
        vehicles.add(veh)
        if d["y"][i]:
            attackers.add(veh)
        q = win[d["pid"][i]]
        q.append(bool(flag[i]))
        if sum(q) >= k:
            reported.add(veh)
    honest = vehicles - attackers
    return {"k": k, "w": w, "attackers": len(attackers), "detected": len(reported & attackers),
            "detection_rate": len(reported & attackers) / len(attackers) if attackers else None,
            "honest": len(honest), "honest_reported": len(reported & honest),
            "false_report_rate": len(reported & honest) / len(honest) if honest else None}


def models():
    from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
    return {
        "rf": (lambda: RandomForestClassifier(n_estimators=100, class_weight="balanced", n_jobs=-1,
                                              min_samples_leaf=5, random_state=1), False),
        "hgb": (lambda: HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, class_weight="balanced",
                                                       random_state=1), False),
        "hgb_window": (lambda: HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1,
                                                              class_weight="balanced", random_state=1), True),
    }


def curves(y: np.ndarray, p: np.ndarray, points: int = 60) -> dict:
    from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve
    pr, rc, _ = precision_recall_curve(y, p)
    fpr, tpr, _ = roc_curve(y, p)
    pick = lambda a, b: [[float(x), float(z)] for x, z in zip(a[::max(1, len(a) // points)], b[::max(1, len(a) // points)])]  # noqa: E731
    return {"pr": pick(rc, pr), "roc": pick(fpr, tpr), "pr_auc": float(average_precision_score(y, p)),
            "roc_auc": float(roc_auc_score(y, p))}


def run(data: Path, sample: float, splits: int) -> dict:
    t0 = time.time()
    det.use_profile("veremi")
    msgs = list(load_csv(data, sample=sample))
    d = featurize(msgs)
    del msgs
    print(f"{len(d['y'])} messages, {len(np.unique(d['vehicle']))} vehicles featurised in {time.time() - t0:.0f} s")
    results: dict = defaultdict(list)          # model -> per-split dicts
    best_probe = None
    for s in range(splits):
        te = split_mask(d["vehicle"], s)
        tr = ~te
        y, att = d["y"][te], d["attack"][te]
        results["rules"].append({"msg": scores(y, d["rules"][te], att),
                                 "veh": vehicle_level(d, te, d["rules"])})
        for name, (make, window) in models().items():
            X = np.hstack([d["X"], d["W"]]) if window else d["X"]
            m = make()
            m.fit(X[tr], d["y"][tr])
            p = m.predict_proba(X[te])[:, 1]
            flag_all = np.zeros(len(d["y"]), bool)
            flag_all[te] = p >= 0.5
            res = {"msg": scores(y, p >= 0.5, att), "veh": vehicle_level(d, te, flag_all), **curves(y, p)}
            results[name].append(res)
            if window:
                # calibrated: fit on 80 % of the training vehicles, pick the threshold that keeps
                # the false-positive rate <= TARGET_FPR on the other 20 %, then score the test split
                val = tr & split_mask(d["vehicle"], 100 + s, test=0.2)
                fit = tr & ~val
                mc = make()
                mc.fit(X[fit], d["y"][fit])
                pv = mc.predict_proba(X[val])[:, 1]
                honest_v = np.sort(pv[d["y"][val] == 0])
                thr = float(honest_v[int(math.ceil((1 - TARGET_FPR) * len(honest_v))) - 1]) if len(honest_v) else 0.5
                thr = max(thr, 0.5)
                pc = mc.predict_proba(X[te])[:, 1]
                flag_c = np.zeros(len(d["y"]), bool)
                flag_c[te] = pc > thr
                results[name + "_calibrated"].append({"msg": scores(y, pc > thr, att),
                                                      "veh": vehicle_level(d, te, flag_c), "threshold": thr,
                                                      **curves(y, pc)})
                if s == 0:
                    best_probe = (te, flag_c)
        print(f"split {s}: " + ", ".join(f"{k} F1 {v[-1]['msg']['ALL']['f1']:.3f}" for k, v in results.items()))
    # K / W tuning for the calibrated window model on split 0
    te, flag_all = best_probe
    tuning = [vehicle_level(d, te, flag_all, k, w) for w in (5, 10, 15, 20) for k in (1, 2, 3, 4, 5) if k <= w]
    summary = {}
    for name, runs in results.items():
        attacks = sorted({str(a) for r in runs for a in r["msg"]}, key=lambda a: (a == "ALL", a))
        row = {"per_attack": {a: {mtr: mean_ci(r["msg"].get(a, {}).get(mtr) for r in runs)[:2]
                                  for mtr in ("precision", "recall", "f1")}
                              | {"n": int(sum(r["msg"].get(a, {}).get("n", 0) for r in runs) / len(runs))}
                              for a in attacks},
               "fpr": mean_ci(r["msg"]["ALL"]["fpr"] for r in runs)[:2],
               "vehicle_detection_rate": mean_ci(r["veh"]["detection_rate"] for r in runs)[:2],
               "honest_reported": mean_ci(r["veh"]["honest_reported"] for r in runs)[:2],
               "honest_vehicles": runs[0]["veh"]["honest"], "attacker_vehicles": runs[0]["veh"]["attackers"]}
        if "threshold" in runs[0]:
            row["threshold"] = mean_ci(r["threshold"] for r in runs)[:2]
        if "pr_auc" in runs[0]:
            row["pr_auc"] = mean_ci(r["pr_auc"] for r in runs)[:2]
            row["roc_auc"] = mean_ci(r["roc_auc"] for r in runs)[:2]
            row["curves_split0"] = {"pr": runs[0]["pr"], "roc": runs[0]["roc"]}
        summary[name] = row
    return {"source": str(data), "sample": sample, "splits": splits, "messages": int(len(d["y"])),
            "vehicles": int(len(np.unique(d["vehicle"]))), "profile": "veremi", "window": WINDOW,
            "classes": VEREMI_EXT_CLASSES, "models": summary, "k_w_tuning_hgb_window_calibrated": tuning,
            "seconds": round(time.time() - t0)}, d


def train_hybrid_model(d: dict, out: Path, generated_vehicles: int = 200) -> dict:
    """Per-message model for the simulator (--detector-mode hybrid): every sampled VeReMi
    vehicle ("veremi" profile) plus generated traffic with attacks in the simulator's
    ("scenario") profile, so the model has seen both kinds of kinematics."""
    import joblib
    from sklearn.ensemble import HistGradientBoostingClassifier
    from detection.evaluate import run_detector
    from detection.generator import generate
    det.use_profile("scenario")
    gen = run_detector(generate(n_vehicles=generated_vehicles, seed=7))
    Xg = np.array([det.feature_vector(r["features"]) for r in gen], np.float32)
    yg = np.array([r["label"] for r in gen], np.int8)
    X, y = np.vstack([d["X"], Xg]), np.concatenate([d["y"], yg])
    m = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, class_weight="balanced", random_state=1)
    m.fit(X, y)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(m, out)
    return {"model": str(out), "veremi_messages": int(len(d["y"])), "generated_messages": int(len(yg)),
            "features": det.FEATURES}


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default=str(DATA))
    ap.add_argument("--sample", type=float, default=0.3, help="fraction of sender vehicles")
    ap.add_argument("--splits", type=int, default=SPLITS)
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--model-out", default=str(MODEL_OUT))
    a = ap.parse_args(argv)
    res, d = run(Path(a.data), a.sample, a.splits)
    res["hybrid_model"] = train_hybrid_model(d, Path(a.model_out))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=1, default=lambda o: o.item() if hasattr(o, "item") else str(o)))
    for name, row in res["models"].items():
        f1 = row["per_attack"]["ALL"]["f1"]
        print(f"{name:11s} F1 {f1[0]:.3f} ± {f1[1]:.3f}  FPR {row['fpr'][0]:.4f}  "
              f"attackers reported {row['vehicle_detection_rate'][0]:.3f}  honest reported {row['honest_reported'][0]:.1f}"
              f"/{row['honest_vehicles']}")
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
