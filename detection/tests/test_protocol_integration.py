"""My detector inside Person 3's real RSU (protocol/rsu.py), fed with real signed BSMs.

protocol/rsu.py calls detector.check(payload, history) where payload is
{"pid", "fields": {...safety fields...}, "ticket": ...} and history is the list of the
pseudonym's earlier payloads. detection.detector.normalize() accepts that format.
"""

import time
import types

import pytest

pytest.importorskip("protocol")

from detection import detector as det  # noqa: E402
from protocol.crypto import keygen  # noqa: E402
from protocol.ledger import MockLedger  # noqa: E402
from protocol.registration import create_pseudonyms, register_pseudonyms  # noqa: E402
from protocol.rsu import RSU  # noqa: E402
from protocol.vehicle import Vehicle  # noqa: E402


@pytest.fixture(autouse=True)
def fresh():
    det.reset()
    yield
    det.reset()


def world(k=3, w=20):
    ledger = MockLedger()
    ledger.set_policy("road_access", {"car"})
    pseudonyms = create_pseudonyms(2, 1, "car")
    register_pseudonyms(pseudonyms, ledger, time.time() + 600)
    (sk1, pk1), (sk2, pk2) = keygen(), keygen()
    trusted = {"RSU-1": pk1, "RSU-2": pk2}
    detector = types.SimpleNamespace(check=det.check)
    rsus = [RSU("RSU-1", ledger, sk1, pk1, trusted_rsu_keys=trusted, detector=detector, detector_k=k, detector_w=w),
            RSU("RSU-2", ledger, sk2, pk2, trusted_rsu_keys=trusted, detector=detector, detector_k=k, detector_w=w)]
    vehicle = Vehicle(pseudonyms, "car", trusted_rsu_keys=trusted)
    res = rsus[0].authenticate(vehicle.make_auth_request(rsus[0].beacon(), "road_access"))
    assert res["ok"], res
    assert vehicle.accept_ticket(res["ticket"], pk1)
    return ledger, rsus, vehicle


def drive(vehicle, rsus, n, claimed_speed=10.0):
    """n BSMs at 10 Hz of a vehicle moving at 10 m/s along x; both RSUs hear each one."""
    out = []
    for i in range(n):
        t = i * 0.1
        bsm = vehicle.make_bsm(x=100.0 + 10.0 * t, y=0.0, speed=claimed_speed, heading=90.0, timestamp=t)
        out.append([r.verify_bsm(bsm) for r in rsus])
    return out


def test_honest_vehicle_is_never_flagged_or_revoked():
    ledger, rsus, vehicle = world()
    results = drive(vehicle, rsus, 60)
    assert all(r["ok"] and not r["flagged"] for row in results for r in row)
    assert not ledger.is_revoked(vehicle.current.pid) and not ledger.misbehaviour_reports


def test_lying_about_speed_gets_reported_by_two_rsus_and_revoked():
    ledger, rsus, vehicle = world()
    pid = vehicle.current.pid
    results = drive(vehicle, rsus, 60, claimed_speed=30.0)       # moves at 10 m/s, claims 30
    flat = [r for row in results for r in row]
    assert all(r["ok"] for r in flat[:10])                        # signatures and tickets are fine at first
    assert any(r.get("flagged") for r in flat)
    assert ledger.misbehaviour_reports[pid]["reporters"] == {"RSU-1", "RSU-2"}
    assert ledger.is_revoked(pid)
    # once revoked, every RSU drops its safety messages
    after = [r for r in flat if not r["ok"]]
    assert after and all(r["reason"] == "expired_or_revoked" for r in after)


def test_bsm_without_position_is_accepted_not_flagged_by_the_detector():
    ledger, rsus, vehicle = world()
    res = rsus[0].verify_bsm(vehicle.make_bsm(note="no kinematics"))
    assert res["ok"] and not res["flagged"] and "error" in res["features"]


def test_flat_and_protocol_formats_give_the_same_features():
    flat = {"pid": "a", "seq": None, "t": 1.0, "x": 5.0, "y": 6.0, "speed": 7.0, "heading": 8.0,
            "rsu_x": None, "rsu_y": None, "rx_time": 1.0, "sender": None}
    proto = {"pid": "a", "fields": {"timestamp": 1.0, "x": 5.0, "y": 6.0, "speed": 7.0, "heading": 8.0}, "ticket": {}}
    assert det.normalize(proto) == flat
    det.reset()
    f1 = det.check(flat, [])[1]
    det.reset()
    f2 = det.check(proto, [])[1]
    assert f1 == f2
