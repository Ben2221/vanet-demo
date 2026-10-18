"""Tests for Person 4's detector, reporting rule, generator and loaders. Run: pytest detection/tests"""

import json

import pytest

from detection import detector as det
from detection.evaluate import per_attack_metrics, run_detector, vehicle_metrics
from detection.generator import ATTACKS, generate
from detection.loaders import from_record, load, normalise_attack, split_by_vehicle
from detection.reporting import ReportingRule


def msg(pid="a", seq=0, t=0.0, x=100.0, y=0.0, speed=10.0, heading=90.0, sender=1, rx=None):
    return {"pid": pid, "seq": seq, "t": t, "x": x, "y": y, "speed": speed, "heading": heading,
            "rsu_x": 0.0, "rsu_y": 0.0, "rx_time": t if rx is None else rx, "sender": sender}


def honest_history(n=12, speed=10.0):
    """n messages at 10 Hz of a vehicle driving along x at constant speed."""
    return [msg(seq=i, t=i * 0.1, x=100 + speed * i * 0.1, speed=speed) for i in range(n)]


@pytest.fixture(autouse=True)
def fresh():
    det.reset()
    yield
    det.reset()


def feed(history, new):
    """Run the checks the way an RSU does and return the features of the last message."""
    det.reset()
    h = []
    f = {}
    for m in history + [new]:
        flagged, f = det.check(m, list(h))
        h.append(m)
    return flagged, f


def test_honest_vehicle_is_not_flagged():
    h = honest_history()
    flagged, f = feed(h, msg(seq=12, t=1.2, x=100 + 10 * 1.2))
    assert not flagged and not any(f[k] for k in det.HARD)


def test_out_of_range_position():
    flagged, f = feed(honest_history(), msg(seq=12, t=1.2, x=700))
    assert flagged and f["range"] == 1


def test_position_jump():
    flagged, f = feed(honest_history(), msg(seq=12, t=1.2, x=300))
    assert flagged and f["pos_jump"] == 1


def test_speed_does_not_match_movement():
    # moves at 10 m/s but keeps claiming 30 m/s (one outlier is averaged away; a lie that lasts is caught)
    lie = [msg(seq=12 + i, t=1.2 + i * 0.1, x=100 + 10 * (1.2 + i * 0.1), speed=30.0) for i in range(10)]
    flagged, f = feed(honest_history(speed=10.0) + lie[:-1], lie[-1])
    assert flagged and f["pos_speed"] == 1


def test_sudden_stop_claim():
    stop = [msg(seq=12 + i, t=1.2 + i * 0.1, x=100 + 15 * (1.2 + i * 0.1), speed=0.0) for i in range(10)]
    flagged, f = feed(honest_history(speed=15.0) + stop[:-1], stop[-1])      # says 0, keeps moving at 15
    assert flagged and f["pos_speed"]


def test_impossible_speed():
    flagged, f = feed(honest_history(), msg(seq=12, t=1.2, x=112, speed=90.0))
    assert flagged and f["speed_range"] == 1


def test_replay_same_sender_time_goes_back():
    flagged, f = feed(honest_history(), msg(seq=3, t=0.3, x=103, rx=1.2))
    assert flagged and f["replay"] == 1


def test_replay_copy_sent_by_other_sender():
    flagged, f = feed(honest_history(), msg(seq=12, t=1.2, x=112, sender=99))
    assert flagged and f["replay"] == 1


def test_replay_does_not_make_the_owner_look_bad():
    """A copied message in between must not flag the owner's next genuine message."""
    det.reset()
    h = []
    for m in honest_history() + [msg(seq=5, t=0.5, x=105, sender=99, rx=1.25)]:
        det.check(m, list(h))
        h.append(m)
    flagged, f = det.check(msg(seq=12, t=1.2, x=112, sender=1, rx=1.3), list(h))
    assert not flagged and f["replay"] == 0


def test_foreign_copy_is_marked_and_not_counted_for_the_owner():
    det.reset()
    h = []
    for m in honest_history():
        det.check(m, list(h))
        h.append(m)
    flagged, f = det.check(msg(seq=5, t=0.5, x=105, sender=99, rx=1.25), list(h))
    assert flagged and f["foreign"] == 1
    r = ReportingRule(k=1, w=3)
    assert r.update("a", True, foreign=bool(f["foreign"])) is False        # the owner is not reported
    assert r.update("a", True) is True


def test_flooding():
    h = [msg(seq=i, t=i * 0.01, x=100 + 0.1 * i, rx=i * 0.01) for i in range(20)]
    flagged, f = feed(h, msg(seq=20, t=0.2, x=102, rx=0.2))
    assert flagged and f["msg_rate"] == 1


def test_sybil_ghosts_alternate_from_one_sender():
    det.reset()
    flags = []
    for i in range(6):
        for pid in ("own", "ghost1"):
            m = msg(pid=pid, seq=i, t=i * 0.1, x=100 + i, sender=5)
            flags.append(det.check(m, [])[1]["sybil"])
    assert any(flags)


def test_pseudonym_change_is_not_sybil():
    det.reset()
    seen = []
    for i in range(10):
        pid = "old" if i < 5 else "new"
        seen.append(det.check(msg(pid=pid, seq=i, t=i * 0.1, x=100 + i, sender=5), [])[1]["sybil"])
    assert not any(seen)


def test_gap_in_reception_is_not_a_jump():
    """The vehicle left the range for 10 s and came back somewhere else."""
    h = honest_history()
    flagged, f = feed(h, msg(seq=200, t=11.2, x=-250.0))
    assert not f["pos_jump"] and not f["pos_speed"]


def test_every_attack_is_found_by_the_rules():
    res = run_detector(generate(n_vehicles=60, attacker_ratio=0.3, seed=7))
    m = per_attack_metrics(res)
    assert set(ATTACKS) <= set(m)
    for a in ATTACKS:
        if a != "const_pos":            # a constant offset inside the radio range is not visible to these rules
            assert m[a]["recall"] > 0.6, (a, m[a])
    assert m["ALL"]["fpr"] < 0.01


def test_reporting_rule_k_of_w():
    r = ReportingRule(k=3, w=5)
    assert [r.update("p", f) for f in (1, 0, 1, 0, 1, 1)] == [False, False, False, False, True, False]
    assert not any(r.update("q", f) for f in (1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1))   # spread out: never 3 in 5
    with pytest.raises(ValueError):
        ReportingRule(k=6, w=5)


def test_vehicle_metrics_catches_attackers_and_spares_honest():
    res = run_detector(generate(n_vehicles=50, attacker_ratio=0.2, seed=3))
    vm = vehicle_metrics(res, k=3, w=10)
    assert vm["detection_rate"] >= 0.8
    assert vm["false_report_rate"] <= 0.1


def test_normalise_attack_names():
    assert normalise_attack("ConstantPositionOffset") == "const_pos"
    assert normalise_attack("dosAttack") == "flood"
    assert normalise_attack(0) == "honest" and normalise_attack(None) == "honest"


def test_loader_veremi_jsonl(tmp_path):
    p = tmp_path / "JSONlog-0-7-A0.json"
    lines = [
        {"type": 2, "rcvTime": 1.0, "pos": [10.0, 20.0, 0], "spd": [1, 0, 0]},
        {"type": 3, "rcvTime": 1.1, "sendTime": 1.05, "sender": 12, "senderPseudo": 1012,
         "messageID": 4, "pos": [30.0, 20.0, 0], "spd": [3.0, 4.0, 0], "hed": [0, 1, 0],
         "attackerType": 4},
        {"type": 3, "rcvTime": 1.2, "sendTime": 1.15, "sender": 13, "senderPseudo": 1013,
         "messageID": 5, "pos": [40.0, 20.0, 0], "spd": [5.0, 0.0, 0], "hed": [1, 0, 0],
         "attackerType": 0},
    ]
    p.write_text("\n".join(json.dumps(x) for x in lines))
    msgs = load(p)
    assert len(msgs) == 2
    assert msgs[0]["speed"] == pytest.approx(5.0) and msgs[0]["rsu_x"] == 10.0
    assert msgs[0]["attack"] == "random_pos" and msgs[0]["label"] == 1
    assert msgs[1]["label"] == 0 and msgs[1]["heading"] == pytest.approx(90.0)


def test_loader_csv_with_aliases(tmp_path):
    p = tmp_path / "ext.csv"
    p.write_text("sendTime,rcvTime,senderID,senderPseudo,messageID,posx,posy,spdx,spdy,attackerType\n"
                 "1.0,1.1,7,700,1,5,6,3,4,SuddenStop\n")
    (m,) = load(p)
    assert m["x"] == 5.0 and m["speed"] == pytest.approx(5.0) and m["attack"] == "sudden_stop"


def test_loader_unknown_columns_error_names_the_columns():
    with pytest.raises(KeyError) as e:
        from_record({"foo": 1, "bar": 2})
    assert "foo" in str(e.value) and "ALIASES" in str(e.value)


def test_split_by_vehicle_never_shares_a_vehicle():
    msgs = generate(n_vehicles=40, seed=2)
    train, test = split_by_vehicle(msgs, 0.3, seed=1)
    assert {m["vehicle"] for m in train}.isdisjoint({m["vehicle"] for m in test})
    assert train and test
