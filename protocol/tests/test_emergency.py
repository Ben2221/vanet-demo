"""Emergency vehicles: the class is bound at registration, the emergency service is allowed to
that class only, the "ev" (siren on) flag counts only under an emergency ticket, a signed fake
is reported at once, and the RSU priority lane (protocol/sim_app.py --emergency-*)."""
from types import SimpleNamespace

import pytest

from protocol.crypto import keygen
from protocol.ledger import MockLedger
from protocol.messages import INTERNED, Message
from protocol.registration import create_pseudonyms, register_pseudonyms
from protocol.rsu import RSU
from protocol.v2v import V2VVerifier
from protocol.vehicle import Vehicle

EV_SERVICE = "emergency-priority"
KIN = dict(seq=1, t=0.0, x=100.0, y=200.0, speed=13.9, heading=90.0)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def world(rsu_opts=None, **vehicle_opts):
    """One RSU, an ambulance (class emergency) and a car, both registered by the TA."""
    clock = Clock()
    ledger = MockLedger()
    ledger.set_policy("road_access", {"car", "emergency"})
    ledger.set_policy(EV_SERVICE, {"emergency"})
    sk, pk = keygen()
    trusted = {"RSU-1": pk}
    amb, car = create_pseudonyms(1, 1, "emergency"), create_pseudonyms(1, 1, "car")
    register_pseudonyms(amb + car, ledger, clock() + 600)
    rsu = RSU("RSU-1", ledger.view("RSU-1"), sk, pk, trusted_rsu_keys=trusted, clock=clock,
              ticket_digest_cache=100, **(rsu_opts or {}))
    mk = lambda ps, cls: Vehicle(ps, cls, trusted_rsu_keys=trusted, clock=clock, **vehicle_opts)  # noqa: E731
    return ledger, rsu, mk(amb, "emergency"), mk(car, "car"), trusted, clock


def login(rsu, v, trusted, service):
    res = rsu.authenticate(v.make_auth_request(rsu.beacon(), service))
    if res["ok"]:
        assert v.accept_ticket(res["ticket"], trusted[rsu.rsu_id], res.get("r"))
    return res


def test_wire_names_appended():
    assert INTERNED[-3:] == ["ev", EV_SERVICE, "fake_emergency"]


def test_only_emergency_class_gets_the_emergency_service():
    _, rsu, amb, car, trusted, _ = world()
    assert login(rsu, amb, trusted, EV_SERVICE)["ok"]
    assert amb.ticket["payload"]["class"] == "emergency"
    assert login(rsu, car, trusted, EV_SERVICE)["reason"] == "policy_denied"
    # claiming the class in the request breaks the Merkle leaf (class is bound at registration)
    req = Message.from_bytes(car.make_auth_request(rsu.beacon(), EV_SERVICE))
    req.fields["vehicle_class"] = "emergency"
    assert rsu.authenticate(req.to_bytes())["reason"] == "not_registered"


def test_alert_accepted_only_under_an_emergency_ticket():
    _, rsu, amb, car, trusted, clock = world()
    login(rsu, amb, trusted, EV_SERVICE)
    login(rsu, car, trusted, "road_access")
    peer = V2VVerifier(trusted, clock)
    ok = peer.receive(amb.make_bsm(ev=True, **KIN), clock())[0]
    assert ok["ok"] and ok["payload"]["ev"] == 1
    fake = peer.receive(car.make_bsm(ev=True, **KIN), clock())[0]
    assert not fake["ok"] and fake["reason"] == "fake_emergency"
    assert peer.receive(car.make_bsm(**KIN), clock())[0]["ok"]          # the same car without the flag


def test_flag_is_signed():
    _, rsu, amb, car, trusted, clock = world()
    login(rsu, car, trusted, "road_access")
    msg = Message.from_bytes(car.make_bsm(**KIN))
    msg.fields["payload"]["ev"] = 1                                     # added after signing
    res = V2VVerifier(trusted, clock).receive(msg.to_bytes(), clock())[0]
    assert res["reason"] == "invalid_signature"


def test_rsu_reports_a_signed_fake_at_once():
    ledger, rsu, amb, car, trusted, clock = world()
    login(rsu, amb, trusted, EV_SERVICE)
    login(rsu, car, trusted, "road_access")
    assert rsu.receive_bsm(amb.make_bsm(ev=True, **KIN), rx_time=clock())[0]["ok"]
    res = rsu.receive_bsm(car.make_bsm(ev=True, **KIN), rx_time=clock())[0]
    assert res["reason"] == "fake_emergency" and res["reported"] and res["evidence"]
    pid = car.current.pid
    assert pid in rsu.reported
    assert ledger.misbehaviour_reports[pid]["evidence"][0]["evidence_hash"] == res["evidence"]
    again = rsu.receive_bsm(car.make_bsm(ev=True, **KIN), rx_time=clock())[0]
    assert again["reason"] == "fake_emergency" and not again.get("reported")     # reported once


def test_rsu_does_not_report_a_maced_fake():
    _, rsu, _, car, trusted, clock = world(bsm_auth="mac")
    login(rsu, car, trusted, "road_access")
    rsu.receive_bsm(car.make_bsm(**KIN), rx_time=clock())               # anchor: the RSU learns the ticket
    res = rsu.receive_bsm(car.make_bsm(mac_rsus=["RSU-1"], ev=True, **KIN), rx_time=clock())[0]
    assert res["reason"] == "fake_emergency" and not res.get("reported")   # a MAC is no third-party evidence


def test_priority_lane_waits_only_for_the_job_in_progress():
    from protocol.sim_app import CpuQueue
    clock = {"t": 0.0}
    q = CpuQueue(SimpleNamespace(now=lambda: clock["t"], schedule=lambda d, f: None))
    for _ in range(10):
        q.run(0.010)                                                    # 100 ms of queued logins
    clock["t"] = 0.015                                                  # second job in progress
    assert q.run_priority(0.002) == pytest.approx(0.022)                # after it, not after the backlog
    assert q.run_priority(0.002) == pytest.approx(0.024)                # behind the earlier priority job
    assert q.run(0.010) == pytest.approx(0.114)                         # later arrivals wait for both
