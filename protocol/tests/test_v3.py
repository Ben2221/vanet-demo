"""v3 mechanisms: ECQV tickets, TESLA BSMs, batch verification, revocation filter, BBS
credentials, RSU clusters, vehicle-side verification, trust-weighted revocation."""
import time

import pytest

from network.ledger_client import InMemoryLedger
from network.protocols.stub_auth import builtin_check
from protocol import bbs, bloom, ecqv, tesla
from protocol.batch import batch_cost, batch_verify, find_invalid
from protocol.crypto import keygen, schnorr_sign, bip340_sign
from protocol.ledger import MockLedger
from protocol.messages import INTERNED, TYPE_CODES, Message
from protocol.registration import create_pseudonyms, register_pseudonyms
from protocol.rsu import RSU
from protocol.v2v import V2VVerifier
from protocol.vehicle import Vehicle, bbs_pseudonyms, canonical_json, ticket_digest

KIN = dict(seq=1, t=0.0, x=100.0, y=200.0, speed=13.9, heading=90.0)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def world(n=1, rsus=2, clock=None, rsu_opts=None, credential=None, **vehicle_opts):
    clock = clock or Clock()
    ledger = MockLedger()
    ledger.set_policy("road_access", {"car"})
    keys = {f"RSU-{i}": keygen() for i in range(1, rsus + 1)}
    trusted = {name: pk for name, (_, pk) in keys.items()}
    vehicles = []
    if credential:
        issuer = bbs.IssuerKey.generate()
        ledger.register_root(1, issuer.pk_hex, clock() + 600)
        for _ in range(n):
            cred = bbs.enroll(issuer, "car", 1)
            ps, index = bbs_pseudonyms(cred, 8)
            vehicles.append(Vehicle(ps, trusted_rsu_keys=trusted, clock=clock, credential=cred,
                                    bbs_index=index, **vehicle_opts))
    else:
        ps = create_pseudonyms(n, 1, "car")
        register_pseudonyms(ps, ledger, clock() + 600)
        vehicles = [Vehicle([p], trusted_rsu_keys=trusted, clock=clock, **vehicle_opts) for p in ps]
    opts = {"ticket_digest_cache": 100, **(rsu_opts or {})}
    nodes = [RSU(name, ledger.view(name), sk, pk, trusted_rsu_keys=trusted, clock=clock, **opts)
             for name, (sk, pk) in keys.items()]
    return ledger, nodes, vehicles, trusted, clock


def authenticate(rsu, vehicle, trusted):
    res = rsu.authenticate(vehicle.make_auth_request(rsu.beacon(), "road_access"))
    assert res["ok"], res
    assert vehicle.accept_ticket(res["ticket"], trusted[rsu.rsu_id], res.get("r"))
    return res


def test_wire_codes_append_only():
    assert TYPE_CODES["TESLA_KEY"] == 8
    assert INTERNED[61] == "quarantined" and INTERNED[62:65] == ["ti", "tm", "kd"]
    assert len(INTERNED) < 256


# ------------------------------------------------------------------- ECQV
def test_ecqv_issue_receive_reconstruct():
    ca_sk, ca_pk = keygen()
    k, R = ecqv.request()
    cert, r = ecqv.issue(ca_sk, R, {"pid": "aa" * 8, "expiry": 5.0})
    d = ecqv.receive(k, r, cert, ca_pk)
    assert d is not None
    other_sk, other_pk = keygen()
    assert ecqv.receive(k, r, cert, other_pk) is None                      # wrong CA
    assert ecqv.receive(k, r, {**cert, "expiry": 6.0}, ca_pk) is None      # altered certificate
    assert ecqv.receive(k + 1, r, cert, ca_pk) is None                     # not the requester


def test_implicit_cert_flow_and_size():
    _, (rsu, rsu2), (v,), trusted, clock = world(rsu_opts={"implicit_cert": True}, implicit_cert=True,
                                                  bsm_ticket="digest")
    res = authenticate(rsu, v, trusted)
    ticket = res["ticket"]
    assert "signature" not in ticket and "pu" in ticket["payload"] and "pk" not in ticket["payload"]
    explicit = {"payload": {**{k: v for k, v in ticket["payload"].items() if k != "pu"}, "pk": "02" + "11" * 32},
                "signature": {"R": "02" + "22" * 32, "s": "33" * 32}}
    assert len(Message("BSM", {"t": ticket}).to_bytes()) < len(Message("BSM", {"t": explicit}).to_bytes()) - 60
    bsm = v.make_bsm(**KIN)                                    # first BSM carries the full ticket
    out = rsu2.verify_bsm(bsm)
    assert out["ok"], out
    assert rsu2.verify_bsm(v.make_bsm(**{**KIN, "seq": 2}))["ok"]      # digest now known at rsu2


def test_implicit_cert_forged_ticket_rejected():
    _, (rsu, rsu2), (v,), trusted, clock = world(rsu_opts={"implicit_cert": True}, implicit_cert=True)
    authenticate(rsu, v, trusted)
    v.ticket = {"payload": {**v.ticket["payload"], "expiry": v.ticket["payload"]["expiry"] + 100}}
    assert rsu2.verify_bsm(v.make_bsm(**KIN))["reason"] == "invalid_bsm_signature"


def test_implicit_cert_request_cannot_be_swapped():
    _, (rsu, _), (v,), trusted, clock = world(rsu_opts={"implicit_cert": True}, implicit_cert=True)
    req = Message.from_bytes(v.make_auth_request(rsu.beacon(), "road_access"))
    _, R_attacker = ecqv.request()
    req.fields["cert_req"] = R_attacker.hex()
    assert rsu.authenticate(req.to_bytes())["reason"] == "invalid_proof"


# ------------------------------------------------------------------ TESLA
def test_tesla_chain_buffer_release_and_late():
    s = tesla.Sender(t0=0.0, length=50, interval=0.05, delay=2)
    r = tesla.Receiver(0.05, 2, skew=0.001)
    assert r.anchor("p", "d", 0.0, s.commitment(0.0)) == []
    i, tag = s.mac(0.06, b"m1")                                # interval 2
    status, out = r.receive("p", "d", 0.0, i, tag, b"m1", None, 0.061, item="m1")
    assert status == "buffered" and out == []
    j = s.disclosable(0.16)                                    # interval 4 discloses K_2
    assert j == 2
    out = r.disclose("p", "d", 0.0, j, s.key(j).hex(), 0.16)
    assert out == [("m1", True, 0.061)]
    i, tag = s.mac(0.07, b"m2")
    assert r.receive("p", "d", 0.0, i, tag, b"m2", None, 0.15, "m2")[0] == "tesla_late"


def test_tesla_forged_mac_and_off_chain_key():
    s = tesla.Sender(0.0, 50, 0.05, 2)
    r = tesla.Receiver(0.05, 2, 0.001)
    r.anchor("p", "d", 0.0, s.commitment(0.0))
    i, tag = s.mac(0.06, b"m")
    r.receive("p", "d", 0.0, i, "00" * 8, b"m", None, 0.061, "forged")
    assert r.disclose("p", "d", 0.0, 2, "11" * 16, 0.16) == []           # not on the chain
    assert r.disclose("p", "d", 0.0, 2, s.key(2).hex(), 0.16) == [("forged", False, 0.061)]


def test_tesla_verified_anchor_waits_behind_pending():
    s = tesla.Sender(0.0, 50, 0.05, 2)
    r = tesla.Receiver(0.05, 2, 0.001)
    r.anchor("p", "d", 0.0, s.commitment(0.0))
    i, tag = s.mac(0.06, b"m")
    r.receive("p", "d", 0.0, i, tag, b"m", None, 0.061, "mac")
    assert r.receive_verified("p", "d", 0.0, 4, 0.16, "anchor") == []
    out = r.disclose("p", "d", 0.0, 2, s.key(2).hex(), 0.17)
    assert [x[0] for x in out] == ["mac", "anchor"]


def test_tesla_bsm_end_to_end_rsu_and_vehicle():
    clock = Clock(1000.0)
    _, (rsu, rsu2), (v, w), trusted, clock = world(n=2, clock=clock, rsu_opts={
        "tesla": tesla.Receiver(), "detector": builtin_check}, bsm_auth="tesla")
    authenticate(rsu, v, trusted)
    peer = V2VVerifier(trusted, clock, tesla.Receiver())
    results, rsu_results = [], []
    for k in range(12):
        clock.t += 0.1
        data = v.make_bsm(**{**KIN, "seq": k, "t": clock.t, "x": 100 + 1.39 * k})
        rsu_results += rsu.receive_bsm(data, rx_time=clock.t + 0.001, rsu_pos=(100.0, 200.0))
        results += peer.receive(data, clock.t + 0.001)
    assert any(Message.from_bytes(v.make_bsm(**KIN)).fields.get("tm") for _ in range(1))
    oks = [x for x in rsu_results if x["ok"]]
    assert len(oks) >= 9 and all(x["ok"] for x in rsu_results)
    assert sum(x["ok"] for x in results) >= 9
    assert v.make_bsm(urgent=True, **KIN) and v.last_bsm_anchor          # urgent: signed at once


# ------------------------------------------------------------------- batch
def test_batch_verify_and_bisection():
    items = []
    for i in range(10):
        sk, pk = keygen()
        m = b"m%d" % i
        items.append((pk, m, schnorr_sign(sk, m) if i % 2 else bip340_sign(sk, m)))
    assert batch_verify(items)
    bad = list(items)
    bad[3] = (bad[3][0], b"x", bad[3][2])
    assert not batch_verify(bad)
    assert find_invalid(bad)[0] == [3]
    sp = {2: 1.2, 8: 1.7, 32: 2.0}
    assert batch_cost(32, 1.0, sp) == pytest.approx(16.0)
    assert batch_cost(1, 1.0, sp) == 1.0
    assert batch_cost(32, 1.0, sp, invalid=1) > batch_cost(32, 1.0, sp)


# ------------------------------------------------------------ revocation filter
def test_bloom_filter():
    pids = [f"{i:016x}" for i in range(40)]
    f = bloom.build(pids)
    assert all(bloom.contains(f, p) for p in pids)
    fp = sum(bloom.contains(f, f"{i:016x}") for i in range(1000, 6000)) / 5000
    assert fp < 0.03
    assert not bloom.contains(bloom.build([]), "00" * 8)


def test_revocation_filter_in_beacon_drops_bsm():
    _, (rsu, _), (v,), trusted, clock = world()
    authenticate(rsu, v, trusted)
    peer = V2VVerifier(trusted, clock)
    data = v.make_bsm(**KIN)
    assert peer.receive(data, clock())[0]["ok"]
    beacon = rsu.beacon({"rf": bloom.build([v.current.pid])})
    assert Vehicle([create_pseudonyms(1)[0]], trusted_rsu_keys=trusted, clock=clock).verify_beacon(beacon)
    peer.set_filter(beacon["payload"]["rf"], beacon["payload"]["timestamp"])
    assert peer.receive(data, clock())[0]["reason"] == "revoked_filter"


# --------------------------------------------------------------------- BBS
def test_bbs_authentication_through_rsu():
    _, (rsu, _), (v, w), trusted, clock = world(n=2, credential=True, rsu_opts={"bbs_j_max": 8})
    authenticate(rsu, v, trusted)
    authenticate(rsu, w, trusted)
    assert v.current.pid != w.current.pid
    req = Message.from_bytes(v.make_auth_request(rsu.beacon(), "road_access"))
    req.fields["vehicle_class"] = "emergency"                   # class is bound into the proof
    assert rsu.authenticate(req.to_bytes())["reason"] == "invalid_proof"
    req = Message.from_bytes(w.make_auth_request(rsu.beacon(), "road_access"))
    req.fields["j"] = 9
    assert rsu.authenticate(req.to_bytes())["reason"] == "j_out_of_range"


def test_bbs_pseudonyms_unlinkable_and_traceable():
    issuer = bbs.IssuerKey.generate()
    cred = bbs.enroll(issuer, "car", 1)
    ps, index = bbs_pseudonyms(cred, 4)
    assert len({p.pid for p in ps}) == 4
    assert {p.pid for p in ps} == set(bbs.nyms_of(cred.sk_v, 1, 4))    # what the TA revokes after a trace


# ----------------------------------------------------------------- clusters
def test_cluster_ticket_reissued_on_handover():
    _, (a, b), (v,), trusted, clock = world(rsu_opts={})
    a.cluster, b.cluster = 1, 2
    authenticate(a, v, trusted)
    assert v.ticket["payload"]["cl"] == 1
    b.preauth_cache[v.current.pid] = v.ticket["payload"]
    beacon = b.beacon()
    res = b.handover(v.make_before_break_handover("RSU-2", beacon))
    assert res["ok"] and res["reason"] == "cluster_ticket"
    assert v.accept_ticket(res["ticket"], trusted["RSU-2"], res.get("r"), count_session=False)
    assert v.ticket_cluster == 2


# ---------------------------------------------------------------------- V2V
def test_v2v_signed_ok_mac_unverifiable():
    _, (rsu, _), (v,), trusted, clock = world(bsm_auth="mac")
    authenticate(rsu, v, trusted)
    peer = V2VVerifier(trusted, clock)
    assert peer.receive(v.make_bsm(**KIN), clock())[0]["ok"]          # anchor with full ticket
    assert peer.receive(v.make_bsm(**KIN), clock())[0]["reason"] == "unverifiable"


def test_ticket_period_forces_full_ticket():
    _, (rsu, _), (v,), trusted, clock = world(bsm_ticket="digest", ticket_period=2.0)
    authenticate(rsu, v, trusted)
    full = lambda d: "ticket" in Message.from_bytes(d).fields["payload"]  # noqa: E731
    assert full(v.make_bsm(**KIN))
    clock.t += 1.0
    assert not full(v.make_bsm(**KIN))
    clock.t += 1.1
    assert full(v.make_bsm(**KIN))


# -------------------------------------------------------------------- trust
def test_trust_weighted_revocation():
    led = InMemoryLedger(report_k=2, trust_weighted=True)
    led.call("rsu1", "report_misbehaviour", pid="p1", evidence_hash="00")
    assert led.call("rsu2", "report_misbehaviour", pid="p1", evidence_hash="00")["revoked"]
    led.call("TA", "set_weight", rsu="rsu3", weight=0.5)
    led.call("TA", "set_weight", rsu="rsu4", weight=0.5)
    led.call("rsu3", "report_misbehaviour", pid="p2", evidence_hash="00")
    assert not led.call("rsu4", "report_misbehaviour", pid="p2", evidence_hash="00")["revoked"]
    assert led.call("rsu1", "report_misbehaviour", pid="p2", evidence_hash="00")["revoked"]
    assert set(led.call("TA", "get_reports", pid="p2")["reports"]) == {"rsu1", "rsu3", "rsu4"}
    with pytest.raises(Exception):
        led.call("rsu1", "set_weight", rsu="rsu1", weight=1.0)      # TA only


def test_weighted_quarantine():
    class View:
        def __init__(self, w):
            self.w = w

        def weight(self, rsu):
            return self.w.get(rsu, 1.0)

        def is_revoked(self, pid):
            return False

    sk, pk = keygen()
    rsu = RSU("RSU-1", View({"RSU-7": 0.5, "RSU-8": 0.5}), sk, pk, quarantine_k=2)
    assert not rsu._add_reporter("p", "RSU-7")
    assert not rsu._add_reporter("p", "RSU-8")                  # 0.5 + 0.5 < 2
    assert rsu._add_reporter("p", "RSU-1")                      # + 1.0 = 2


# ------------------------------------------------- vehicle rules (sim_app)
def _app(**config):
    from types import SimpleNamespace
    from protocol.sim_app import VehicleApp
    env = SimpleNamespace(config={"rsu_range": 300.0, **config}, shared={})
    node = SimpleNamespace(env=env, now=lambda: 0.0, name="veh0", is_attacker=False)
    return VehicleApp(node, env), node, env


def test_dead_reckoning_triggers():
    a, _, _ = _app(dr_bsm=True)
    s = dict(x=0.0, y=0.0, vx=10.0, vy=0.0, speed=10.0, heading=90.0)
    assert a._dr_due(s, 0.0, None)                                    # first BSM
    a.last_sent = (0.0, 0.0, 0.0, 10.0, 0.0, 10.0, 90.0)
    on_track = dict(s, x=5.0)
    assert not a._dr_due(on_track, 0.5, a._prediction_error(on_track, 0.5))
    off = dict(s, x=3.0)                                              # 2 m behind the prediction
    assert a._dr_due(off, 0.5, a._prediction_error(off, 0.5))
    assert not a._dr_due(dict(s, x=9.0), 0.9, 0.0)
    assert a._dr_due(dict(s, x=9.6), 0.96, 0.0)                        # max gap 1 s (next tick is later)
    assert a._dr_due(dict(on_track, heading=100.0), 0.5, 0.0)          # heading > 4 deg
    assert a._urgent(dict(s, speed=10.0), 0.0) is False
    assert a._urgent(dict(s, speed=9.0), 0.1)                          # -10 m/s^2


def test_mix_zone_needs_junction_and_neighbours():
    from types import SimpleNamespace
    a, node, env = _app(mix_zones=True)
    a.vehicle.ticket = {"payload": {"expiry": 1e9}}
    env.shared["junctions"] = [(0.0, 0.0)]
    others = [SimpleNamespace(active=True, app=None, position=lambda d=d: (d, 0.0)) for d in (10.0, 20.0)]
    env.vehicles = [node] + others
    node.position = lambda: (5.0, 0.0)
    node.log = lambda *x, **k: None
    node.now = lambda: 30.0
    first = a.vehicle.current.pid
    a._mix_check(node, 30.0)
    assert a.vehicle.current.pid == first                              # only 2 neighbours
    import random
    env.rng = random.Random(1)
    b, bnode, _ = _app(mix_zones=True)
    b.vehicle.ticket = {"payload": {"expiry": 1e9}}
    bnode.env, bnode.log = env, node.log
    others.append(SimpleNamespace(active=True, app=b, position=lambda: (0.0, 30.0), env=env, log=node.log,
                                  now=lambda: 30.0))
    env.vehicles = [node] + others
    b_first = b.vehicle.current.pid
    a._mix_check(node, 30.0)
    assert a.vehicle.current.pid != first and 30.5 <= a.silent_until <= 31.5
    assert a._silent(node, 31.6)                                       # still inside the zone
    assert b.vehicle.current.pid != b_first                            # the neighbour changed with it


@pytest.fixture(scope="module")
def v3_run(tmp_path_factory):
    """The whole v3 profile in the scenario (lite backend, short)."""
    import json
    from network.run_scenario import main
    out = tmp_path_factory.mktemp("v3")
    main(["--backend", "lite", "--vehicles", "30", "--duration", "40", "--seed", "3", "--protocol", "real",
          "--profile", "v3", "--attacker-ratio", "0.1", "--attack", "random_pos", "--attack-start", "5",
          "--rsu-cpu", "--v2v-verify", "--privacy-log", "--faulty-rsus", "0.25",
          "--out", str(out), "--quiet"])
    return out, json.loads((out / "protocol_stats.json").read_text())


def test_v3_profile_end_to_end(v3_run):
    out, st = v3_run
    assert st["rsu_bsm"]["accepted"] > 0 and st["v2v"]["accepted"] > 0
    assert st["bsm_suppressed_dr"] > 0 and st["cluster_switches"] > 0
    assert st["filter_bytes"]["n"] > 0 and st["faulty_reports"] > 0
    assert (out / "observed_bsms.csv").stat().st_size > 1000
    events = (out / "metrics.csv").read_text()
    for ev in ("AUTH_OK", "CLUSTER_SWITCH", "REPORT", "FAULTY_REPORT"):
        assert ev in events, ev


# ------------------------------------------------------------ latency work
def test_ticket_renewal_issues_fresh_ticket_without_zkp():
    _, (rsu, _), (v,), trusted, clock = world(rsu_opts={"implicit_cert": True}, implicit_cert=True)
    authenticate(rsu, v, trusted)
    old = v.ticket
    rsu.preauth_cache[v.current.pid] = rsu._ticket_ok(old)
    clock.t += 29.0
    res = rsu.handover(v.make_renew_request(rsu.rsu_id, rsu.beacon()))
    assert res["ok"] and res["reason"] == "renewed", res
    assert "merkle_check" not in rsu.ops and "verify" not in rsu.ops       # no ZKP for a renewal
    assert v.accept_ticket(res["ticket"], trusted[rsu.rsu_id], res.get("r"))
    assert v.ticket["payload"]["expiry"] > old["payload"]["expiry"]
    assert rsu.verify_bsm(v.make_bsm(**KIN))["ok"]
    # a renewal request cannot be replayed (nonce used) or made without the ticket key
    req = v.make_renew_request(rsu.rsu_id, rsu.beacon())
    assert rsu.handover(req)["ok"]
    assert not rsu.handover(req)["ok"]


def test_precomputed_bbs_proof_verifies_and_is_single_use():
    issuer = bbs.IssuerKey.generate()
    cred = bbs.enroll(issuer, "car", 1)
    pre = cred.precompute(5)
    nym, proof = cred.finish(pre, b"ctx")
    assert bbs.verify_proof(bytes.fromhex(issuer.pk_hex), nym, proof, "car", 1, 5, b"ctx")
    ps, index = bbs_pseudonyms(cred, 4)
    v = Vehicle(ps, credential=cred, bbs_index=index, trusted_rsu_keys={})
    assert len(v._bbs_pre) == 2                         # current and next pseudonym ready


def test_load_triggered_batching():
    from types import SimpleNamespace
    from protocol.sim_app import CpuQueue
    clock = {"t": 0.0}
    scheduled = []
    node = SimpleNamespace(now=lambda: clock["t"], schedule=lambda d, f: scheduled.append((clock["t"] + d, f)))
    q = CpuQueue(node, batch=True, speedup={2: 1.2, 8: 1.75, 32: 2.0})
    done = []
    q.add_signature(1e-3, False, lambda t: done.append(t))
    assert done == [pytest.approx(1e-3)] and q.batches == [1]          # idle: verified at once, no waiting
    for _ in range(8):                                                 # these arrive while it is busy
        q.add_signature(1e-3, False, lambda t: done.append(t))
    assert len(done) == 1 and len(scheduled) == 1
    clock["t"], fn = scheduled[0]
    fn()
    assert q.batches == [1, 8] and len(done) == 9
    assert done[-1] == pytest.approx(1e-3 + 8e-3 / 1.75)               # one batch, cheaper than 8 singles


def test_adaptive_auth_mode_switches_with_channel_load():
    a, node, env = _app(bsm_auth="tesla", adaptive_auth=True)
    logs = []
    node.log = lambda *x, **k: logs.append(x)
    env.shared = {}
    cbr = {"v": 0.1}
    node.channel_busy_ratio = lambda: cbr["v"]
    a._update_mode(node, 10.0)
    assert a.sign_mode
    cbr["v"] = 0.35
    a._update_mode(node, 11.0)
    assert not a.sign_mode                                             # busy channel: TESLA
    cbr["v"] = 0.15
    a._update_mode(node, 11.5)
    assert not a.sign_mode                                             # held ADAPT_HOLD after a change
    cbr["v"] = 0.25
    a._update_mode(node, 13.0)
    assert not a.sign_mode                                             # hysteresis band
    cbr["v"] = 0.15
    a._update_mode(node, 13.5)
    assert a.sign_mode
