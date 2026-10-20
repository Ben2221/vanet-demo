"""Misbehaviour detector (Person 4).

Interface 5 (docs/interfaces.md):

    check(bsm, history) -> (flagged, features)

``bsm`` is a dict {"pid", "seq", "t", "x", "y", "speed", "heading", "rsu_x",
"rsu_y", "rx_time", "sender"}; ``history`` is the list of earlier dicts of the
same pseudonym at this RSU, newest last. ``features`` is a flat dict of the
check outputs (0/1) and a few numbers; it is also the input of the ML detector.

K-of-W reporting: do not count a message whose ``features["foreign"]`` is 1 in
the pseudonym's window. It is a copy sent by someone else; counting it would
get the innocent owner of the pseudonym reported. The copier is caught through
its own pseudonym (``sybil`` fires when one sender alternates pseudonyms).

Two detectors share the same features:

* rules (default): any "hard" check fires, or two "weak" checks fire together
* ml: a Random Forest trained by detection/train.py on the same features.
  Select with the environment variable VANET_DETECTOR=ml (needs
  detection/models/rf.joblib); otherwise the rules are used.

The checks follow the VeReMi plausibility checks: range, speed, position
consistency, speed consistency, position vs speed, heading, message rate,
overlapping vehicles, replay and sudden appearance. One extra check, ``sybil``,
uses the network sender address, which the RSU knows: two pseudonyms that
alternate from the same sender are ghost vehicles.

Cross-pseudonym checks (overlap, sybil) keep a little state per receiving RSU,
keyed by the RSU position. Call ``reset()`` between independent runs.
"""

from __future__ import annotations

import math
import os
from collections import defaultdict, deque
from pathlib import Path

# ----------------------------------------------------------------- thresholds
# Two profiles. "scenario" is for our SUMO traces: vehicle speed there is stepwise (1 s samples),
# so honest vehicles show accelerations up to ~20 m/s^2 over 0.8 s. "veremi" is for datasets with
# physical kinematics (VeReMi, VeReMi Extension, NextGen): braking is at most ~10 m/s^2.
# Pick with use_profile(name) or the environment variable VANET_PROFILE.
PROFILES = {
    "scenario": {"MAX_ACCEL": 25.0, "POS_SPEED_TOL": 8.0},
    "veremi": {"MAX_ACCEL": 10.0, "POS_SPEED_TOL": 8.0},
}
MAX_SPEED = 60.0          # m/s, faster than this is not a road vehicle
MAX_ACCEL = 25.0          # m/s^2 over >= BASELINE_DT (set by the profile)
MAX_RANGE = 450.0         # m, a sender cannot be heard from farther away
MAX_BEACON_RATE = 13      # messages per second from one pseudonym (nominal 10 Hz)
BASELINE_DT = 0.8         # s, minimum baseline for speed / position-speed checks
MAX_GAP = 2.0             # s, older history is stale (lost messages, left the range)
BASELINE_MAX = 3.0        # s, longest baseline for the speed / position-speed checks
POS_SPEED_TOL = 8.0       # m/s, |implied speed - mean claimed speed| (set by the profile)
HEADING_FLIP = 150.0      # deg between consecutive messages while moving
APPEAR_RADIUS = 150.0     # a new pseudonym first heard this close to the RSU is odd
OVERLAP_DIST = 1.0        # m, two different pseudonyms at the same place
OVERLAP_DT = 0.5          # s


def use_profile(name: str) -> None:
    """Switch the kinematic thresholds: "scenario" (our SUMO traces) or "veremi" (physical datasets)."""
    global MAX_ACCEL, POS_SPEED_TOL
    MAX_ACCEL = PROFILES[name]["MAX_ACCEL"]
    POS_SPEED_TOL = PROFILES[name]["POS_SPEED_TOL"]


HARD = ["range", "speed_range", "pos_jump", "speed_cons", "pos_speed", "heading",
        "msg_rate", "replay", "sybil"]
WEAK = ["sudden_appear", "overlap"]
INFO = ["foreign"]        # 1: sent by someone other than the pseudonym's owner (a copy); not a rule
NUMERIC = ["d_rsu", "speed", "dt", "implied_speed", "implied_base", "speed_err", "speed_err_cur",
           "accel", "heading_delta", "rate"]
FEATURES = HARD + WEAK + INFO + NUMERIC

use_profile(os.environ.get("VANET_PROFILE", "scenario"))

MODEL_PATH = Path(__file__).resolve().parent / "models" / "rf.joblib"


# ------------------------------------------------------- cross-pseudonym state
class _Context:
    """What one RSU remembers across pseudonyms."""

    CELL = 5.0

    def __init__(self) -> None:
        self.grid: dict[tuple[int, int], dict[str, tuple[float, float, float, object]]] = defaultdict(dict)
        self.cell_of: dict[str, tuple[int, int]] = {}
        self.sender_recent: dict[object, deque] = defaultdict(lambda: deque(maxlen=14))

    def overlap(self, pid: str, t: float, x: float, y: float, sender=None) -> bool:
        """Two pseudonyms at the same place at the same time. A pseudonym from the same
        sender is that vehicle's own pseudonym change, not a second vehicle (a sender that
        goes back and forth between pseudonyms is caught by ``sybil``)."""
        cx, cy = int(x // self.CELL), int(y // self.CELL)
        hit = False
        for dx in (-1, 0, 1):
            for dy in (-1, 0, 1):
                for other, (ot, ox, oy, osender) in self.grid.get((cx + dx, cy + dy), {}).items():
                    if sender is not None and osender == sender:
                        continue
                    if other != pid and abs(t - ot) < OVERLAP_DT and math.hypot(x - ox, y - oy) < OVERLAP_DIST:
                        hit = True
        old = self.cell_of.get(pid)
        if old is not None and old != (cx, cy):
            self.grid[old].pop(pid, None)
        self.grid[(cx, cy)][pid] = (t, x, y, sender)
        self.cell_of[pid] = (cx, cy)
        return hit

    def sybil(self, sender, pid: str) -> bool:
        """True when one sender keeps coming back to the same pseudonyms: A, B, A, B, A...

        Ghost vehicles are sent in turn by the same radio, so a pseudonym shows up in
        three separate runs within a few messages. A vehicle that changes its pseudonym
        once never goes back to the old one."""
        if sender is None:
            return False
        recent = self.sender_recent[sender]
        recent.append(pid)
        runs: dict[str, int] = {}
        prev = None
        for p in recent:
            if p != prev:
                runs[p] = runs.get(p, 0) + 1
            prev = p
        return any(n >= 3 for n in runs.values())


_contexts: dict[tuple[int, int], _Context] = {}


def reset() -> None:
    """Forget all cross-pseudonym state (call between independent runs)."""
    _contexts.clear()


TIME_FIELDS = ("t", "timestamp", "sendTime", "time")


def normalize(b: dict) -> dict:
    """Accept both BSM formats and return the flat one of interface 5.

    flat      {"pid", "seq", "t", "x", "y", "speed", "heading", "rsu_x", "rsu_y", "rx_time", "sender"}
    protocol  {"pid", "fields": {"x", "y", "speed", "heading", "timestamp", ...}, "ticket": ...}
              (what protocol/vehicle.py make_bsm builds and protocol/rsu.py passes to the detector)

    Optional inputs may be missing (seq, rsu_x/rsu_y, rx_time, sender): the checks that need
    them are skipped. x, y, speed and a time field are required (KeyError otherwise)."""
    if "fields" not in b:
        return b
    fl = b["fields"]
    t = next(float(fl[k]) for k in TIME_FIELDS if k in fl)
    return {"pid": str(b.get("pid", "")), "seq": fl.get("seq"), "t": t, "x": float(fl["x"]),
            "y": float(fl["y"]), "speed": float(fl["speed"]), "heading": float(fl.get("heading", 0.0)),
            "rsu_x": fl.get("rsu_x"), "rsu_y": fl.get("rsu_y"), "rx_time": float(fl.get("rx_time", t)),
            "sender": fl.get("sender")}


def _context(bsm: dict) -> _Context:
    key = (round(bsm.get("rsu_x") or 0.0), round(bsm.get("rsu_y") or 0.0))
    ctx = _contexts.get(key)
    if ctx is None:
        ctx = _contexts[key] = _Context()
    return ctx


# ---------------------------------------------------------------------- rules
def _angle_diff(a: float, b: float) -> float:
    d = abs(a - b) % 360.0
    return 360.0 - d if d > 180.0 else d


def rule_features(bsm: dict, history: list[dict]) -> dict:
    """All checks for one message. Returns the flat feature dict."""
    bsm = normalize(bsm)
    history = [normalize(h) for h in history]
    f: dict = {k: 0 for k in HARD + WEAK + INFO}
    f.update({k: 0.0 for k in NUMERIC})
    t, x, y, v = bsm["t"], bsm["x"], bsm["y"], bsm["speed"]
    ctx = _context(bsm)

    has_rsu = bsm.get("rsu_x") is not None and bsm.get("rsu_y") is not None
    d_rsu = math.hypot(x - bsm["rsu_x"], y - bsm["rsu_y"]) if has_rsu else 0.0
    f["d_rsu"] = d_rsu
    f["speed"] = v
    if has_rsu and d_rsu > MAX_RANGE:
        f["range"] = 1
    if v > MAX_SPEED or v < 0:
        f["speed_range"] = 1

    rx = bsm.get("rx_time", t)
    f["rate"] = 1 + sum(1 for h in history if rx - h.get("rx_time", h["t"]) <= 1.0)
    if f["rate"] > MAX_BEACON_RATE:
        f["msg_rate"] = 1

    if history:
        sender = bsm.get("sender")
        # the owner of a pseudonym is the sender that uses it most; a message
        # from anyone else is a copy (replay) and must not disturb the owner's history
        counts: dict = {}
        for h in history:
            counts[h.get("sender")] = counts.get(h.get("sender"), 0) + 1
        owner = max(counts, key=counts.get)
        if sender is not None and owner is not None and sender != owner:
            f["replay"] = 1
            f["foreign"] = 1
        own = [h for h in history if h.get("sender") == sender] if sender is not None else history
        prev = own[-1] if own else None
        if prev is not None:
            dt = t - prev["t"]
            f["dt"] = dt
            # replay by the same sender: time or sequence goes backwards
            seq_back = bsm.get("seq") is not None and prev.get("seq") is not None and bsm["seq"] <= prev["seq"]
            if dt <= 0 or seq_back:
                f["replay"] = 1
            elif dt <= MAX_GAP:
                implied = math.hypot(x - prev["x"], y - prev["y"]) / dt
                f["implied_speed"] = implied
                if implied > MAX_SPEED:
                    f["pos_jump"] = 1
                if v > 2.0 and prev["speed"] > 2.0:
                    f["heading_delta"] = _angle_diff(bsm["heading"], prev["heading"])
                    if f["heading_delta"] > HEADING_FLIP and dt < 1.0:
                        f["heading"] = 1
            # checks over a baseline of BASELINE_DT .. BASELINE_MAX seconds
            base_i = None
            for i in range(len(own) - 1, -1, -1):
                age = t - own[i]["t"]
                if age > BASELINE_MAX:
                    break
                if age >= BASELINE_DT:
                    base_i = i
                    break
            if base_i is not None:
                base = own[base_i]
                dtb = t - base["t"]
                span = own[base_i:] + [bsm]
                # distance along the path through the recent messages (a straight
                # chord under-measures the speed of a vehicle that turned a corner)
                pts = [(m["x"], m["y"]) for m in span]
                path = sum(math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(pts, pts[1:]))
                implied_b = path / dtb
                f["implied_base"] = implied_b
                # claimed speed averaged over the same window: robust to stepwise speeds in traces
                claimed = sum(m["speed"] for m in span) / len(span)
                f["speed_err"] = abs(implied_b - claimed)
                f["speed_err_cur"] = abs(implied_b - v)
                # acceleration from smoothed speeds (mean of up to 3 newest vs 3 oldest messages)
                newest = [m["speed"] for m in span[-3:]]
                oldest = [m["speed"] for m in own[max(0, base_i - 2):base_i + 1]]
                f["accel"] = abs(sum(newest) / len(newest) - sum(oldest) / len(oldest)) / dtb
                if f["speed_err"] > POS_SPEED_TOL:
                    f["pos_speed"] = 1
                if f["accel"] > MAX_ACCEL:
                    f["speed_cons"] = 1
    elif has_rsu and d_rsu < APPEAR_RADIUS:
        f["sudden_appear"] = 1

    if ctx.overlap(bsm["pid"], t, x, y, bsm.get("sender")):
        f["overlap"] = 1
    if ctx.sybil(bsm.get("sender"), bsm["pid"]):
        f["sybil"] = 1
    return f


def rules_flag(f: dict) -> bool:
    return any(f[k] for k in HARD) or sum(f[k] for k in WEAK) >= 2


# ------------------------------------------------------------------------- ML
_model = None
_model_tried = False


def _load_model():
    global _model, _model_tried
    if not _model_tried:
        _model_tried = True
        if MODEL_PATH.exists():
            import joblib
            _model = joblib.load(MODEL_PATH)
    return _model


def feature_vector(f: dict) -> list[float]:
    return [float(f[k]) for k in FEATURES]


def check(bsm: dict, history: list[dict]) -> tuple[bool, dict]:
    """Interface 5. Returns (flagged, features). A BSM without x, y, speed and a time is not flagged
    (features has "error"): authentication, not the detector, decides whether it is malformed."""
    try:
        f = rule_features(bsm, history)
    except (KeyError, TypeError, ValueError, StopIteration) as exc:
        return False, {"error": f"unreadable_bsm: {exc!r}"}
    if os.environ.get("VANET_DETECTOR", "rules") == "ml":
        model = _load_model()
        if model is not None:
            p = float(model.predict_proba([feature_vector(f)])[0][1])
            f["ml_score"] = p
            return p >= 0.5, f
    return rules_flag(f), f
