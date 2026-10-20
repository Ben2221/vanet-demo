"""--bsm-auth mac: ECDH session-MAC BSMs with signed anchors, anchor-only evidence, adaptive period."""
import hashlib
import time

import pytest

from protocol.crypto import bsm_mac_key, bsm_tag, bsm_tag_ok, keygen
from protocol.ledger import MockLedger
from network.protocols.stub_auth import builtin_check
from protocol.messages import INTERNED, Message, make_message
from protocol.registration import create_pseudonyms, register_pseudonyms
from protocol.rsu import RSU
from protocol.vehicle import MAX_MAC_TAGS, Vehicle, adaptive_anchor_period, canonical_json, ticket_digest

KIN = dict(seq=7, t=12.345, x=1234.567, y=-89.012, speed=13.9, heading=271.3)


def world(count=2, rsus=2, cache=100, **vehicle_opts):
    ledger = MockLedger()
    ledger.set_policy("road_access", {"car"})
    ps = create_pseudonyms(count, 1, "car")
    register_pseudonyms(ps, ledger, time.time() + 600)
    keys = {f"RSU-{i}": keygen() for i in range(1, rsus + 1)}
    trusted = {name: pk for name, (_, pk) in keys.items()}
    nodes = [RSU(name, ledger.view(name), sk, pk, trusted_rsu_keys=trusted, ticket_digest_cache=cache)
             for name, (sk, pk) in keys.items()]
    vehicles = [Vehicle([p], trusted_rsu_keys=trusted, bsm_auth="mac", **vehicle_opts) for p in ps]
    return ledger, nodes, vehicles, trusted


def authenticate(rsu, vehicle, trusted):
    res = rsu.authenticate(vehicle.make_auth_request(rsu.beacon(), "road_access"))
    assert res["ok"], res
    assert vehicle.accept_ticket(res["ticket"], trusted[rsu.rsu_id])
    return res["ticket"]


def mac_bsm(vehicle, **opts) -> bytes:
    """Next MAC (non-anchor) BSM of the vehicle."""
    for _ in range(vehicle.anchor_every + 1):
        raw = vehicle.make_bsm(**opts, **KIN)
        if not vehicle.last_bsm_anchor:
            return raw
    raise AssertionError("no MAC BSM produced")


def edit(raw: bytes, change) -> bytes:
    msg = Message.from_bytes(raw)
    change(msg.fields)
    return msg.to_bytes()


def test_interned_strings_are_append_only():
    assert INTERNED[51:54] == ["ticket_digest", "k", "unknown_ticket_digest"]
    assert INTERNED[54:59] == ["tags", "invalid_bsm_mac", "bsm_mac_not_for_rsu", "anchor_overdue", "anchor_required"]


def test_mac_key_agreement_without_handshake():
    v_sk, v_pk = keygen()
    r_sk, r_pk = keygen()
    digest = "ab" * 8
    k = bsm_mac_key(v_sk, r_pk, digest)
    assert k == bsm_mac_key(r_sk, v_pk, digest) and len(k) == 32
    assert k != bsm_mac_key(v_sk, r_pk, "cd" * 8) and k != bsm_mac_key(v_sk, keygen()[1], digest)
    tag = bsm_tag(k, b"payload")
    assert len(bytes.fromhex(tag)) == 8 and bsm_tag_ok(k, b"payload", tag)
    assert not bsm_tag_ok(k, b"payload!", tag) and not bsm_tag_ok(k, b"payload", None)


def test_vehicle_options_validated():
    ps = create_pseudonyms(1, 1, "car")
    with pytest.raises(ValueError):
        Vehicle(ps, bsm_auth="none")
    with pytest.raises(ValueError):
        Vehicle(ps, bsm_auth="mac", anchor_every=0)
    assert Vehicle(ps, bsm_auth="mac").bsm_ticket == "digest"
    assert Vehicle(ps).bsm_auth == "sig"


def test_anchor_schedule_and_round_trip():
    _, (r1, _), (v, _), trusted = world(anchor_every=4, ticket_every=100)
    authenticate(r1, v, trusted)
    kinds = []
    for _ in range(9):
        raw = v.make_bsm(**KIN)
        f = Message.from_bytes(raw).fields
        res = r1.verify_bsm(raw)
        assert res["ok"], res
        assert res["anchor"] == v.last_bsm_anchor == ("signature" in f) == ("tags" not in f)
        kinds.append("A" if v.last_bsm_anchor else "m")
        if not v.last_bsm_anchor:
            assert f["payload"]["ticket_digest"] == ticket_digest(v.ticket) and list(f["tags"]) == ["RSU-1"]
    assert "".join(kinds) == "AmmmAmmmA"                    # the first one carries the full ticket
    v.send_full_ticket()
    raw = v.make_bsm(**KIN)
    assert v.last_bsm_anchor and "ticket" in Message.from_bytes(raw).fields["payload"]


def test_no_trusted_target_means_anchor():
    _, (r1, _), (v, _), trusted = world()
    authenticate(r1, v, trusted)
    v.make_bsm(**KIN)
    v.current_rsu_id = None
    v.make_bsm(mac_rsus=["RSU-99"], **KIN)                  # untrusted RSU: nobody to MAC for
    assert v.last_bsm_anchor


def test_tag_vector_current_first_trusted_only_capped():
    _, nodes, (v, _), trusted = world(rsus=5)
    r1 = nodes[0]
    authenticate(r1, v, trusted)
    raw = mac_bsm(v, mac_rsus=["RSU-3", "evil", "RSU-1", "RSU-2", "RSU-4", "RSU-5"])
    tags = Message.from_bytes(raw).fields["tags"]
    assert list(tags) == ["RSU-1", "RSU-3", "RSU-2"] and len(tags) == MAX_MAC_TAGS


def test_neighbour_rsu_verifies_its_own_tag_after_preauth():
    _, (r1, r2), (v, _), trusted = world()
    ticket = authenticate(r1, v, trusted)
    raw = mac_bsm(v, mac_rsus=["RSU-2"])
    assert r2.verify_bsm(raw)["reason"] == "unknown_ticket_digest"
    assert r2.receive_preauth(r1.preauthorize_neighbour("RSU-2", ticket))["ok"]
    assert r2.verify_bsm(raw)["ok"] and r1.verify_bsm(raw)["ok"]
    # each RSU has its own key: RSU-1's tag under RSU-2's id does not verify
    swapped = edit(raw, lambda f: f["tags"].update({"RSU-2": f["tags"]["RSU-1"]}))
    assert r2.verify_bsm(swapped)["reason"] == "invalid_bsm_mac"
    only_r1 = mac_bsm(v)
    assert r2.verify_bsm(only_r1)["reason"] == "bsm_mac_not_for_rsu"
    assert len(r2._mac_keys) == 1 and len(r1._mac_keys) == 1


def test_mac_bsm_tampered_forged_unknown_rejected():
    _, (r1, _), (victim, attacker), trusted = world()
    authenticate(r1, victim, trusted)
    authenticate(r1, attacker, trusted)
    good = mac_bsm(victim)
    assert r1.verify_bsm(good)["ok"]
    victim_digest = Message.from_bytes(good).fields["payload"]["ticket_digest"]
    tampered = edit(good, lambda f: f["payload"]["fields"].update(x=0.0))
    assert r1.verify_bsm(tampered)["reason"] == "invalid_bsm_mac"
    bad_tag = edit(good, lambda f: f["tags"].update({"RSU-1": "00" * 8}))
    assert r1.verify_bsm(bad_tag)["reason"] == "invalid_bsm_mac"
    assert r1.verify_bsm(edit(good, lambda f: f["tags"].update({"RSU-1": 5})))["reason"] == "invalid_bsm_mac"
    # the attacker MACs the victim's pid and digest with its own pseudonym key
    own = mac_bsm(attacker)
    def forge(f):
        f["payload"].update(pid=victim.current.pid, ticket_digest=victim_digest)
        key = bsm_mac_key(attacker.current.secret, trusted["RSU-1"], victim_digest)
        f["tags"] = {"RSU-1": bsm_tag(key, canonical_json(f["payload"]))}
    assert r1.verify_bsm(edit(own, forge))["reason"] == "invalid_bsm_mac"
    swapped = edit(own, lambda f: f["payload"].update(ticket_digest=victim_digest))
    assert r1.verify_bsm(swapped)["reason"] == "ticket_pseudonym_mismatch"
    unknown = edit(own, lambda f: f["payload"].update(ticket_digest="00" * 8))
    assert r1.verify_bsm(unknown)["reason"] == "unknown_ticket_digest"
    no_digest = edit(own, lambda f: (f["payload"].pop("ticket_digest"), f["payload"].update(ticket=victim.ticket)))
    assert r1.verify_bsm(no_digest)["reason"] == "malformed_bsm"
    assert r1.verify_bsm(edit(own, lambda f: f.update(tags=["RSU-1"])))["reason"] == "bsm_mac_not_for_rsu"


def test_mac_bsm_checks_revocation():
    ledger, (r1, _), (v, _), trusted = world()
    authenticate(r1, v, trusted)
    raw = mac_bsm(v)
    ledger.revoke(v.current.pid)
    assert r1.verify_bsm(raw)["reason"] == "expired_or_revoked"


def test_mac_bsm_size_reduction():
    _, nodes, (v, _), trusted = world(rsus=3)
    authenticate(nodes[0], v, trusted)
    ps = create_pseudonyms(1, 1, "car")
    sig_v = Vehicle(ps, trusted_rsu_keys=trusted, bsm_ticket="digest")
    sig_v.ticket = v.ticket
    sig_v.make_bsm(**KIN)
    signed_digest = len(sig_v.make_bsm(**KIN))
    one, three = len(mac_bsm(v)), len(mac_bsm(v, mac_rsus=["RSU-2", "RSU-3"]))
    assert signed_digest - one >= 55 and three - one == 2 * (2 + len("RSU-2") + 2 + 8), (signed_digest, one, three)
    _, (r1, _), (cv, _), trusted = world(compact_wire=True)
    authenticate(r1, cv, trusted)
    compact = mac_bsm(cv)
    assert r1.verify_bsm(compact)["ok"] and len(compact) <= 80, len(compact)


class _FlagAll:
    def check(self, bsm, history):
        return True, {}


class _FlagFar:
    """Self-contained check: flags x beyond 1000 (like builtin_check's range test)."""
    def check(self, bsm, history):
        return bsm["x"] > 1000, {}


def kin(i: int, x: float) -> dict:
    return dict(seq=i, t=i * 0.1, x=x, y=0.0, speed=10.0, heading=0.0)


def send(rsu, vehicle, i, x):
    raw = vehicle.make_bsm(**kin(i, x))
    return raw, rsu.verify_bsm(raw, rx_time=i * 0.1, rsu_pos=(0.0, 0.0))


def test_report_waits_for_a_flagged_anchor():
    ledger, (r1, _), (v, _), trusted = world(anchor_every=5, ticket_every=100)
    r1.detector, r1.detector_k = _FlagFar(), 3
    authenticate(r1, v, trusted)
    pid = v.current.pid
    kinds, i = [], 0
    while True:
        raw, res = send(r1, v, i, 5000.0 if i else 0.0)       # honest first anchor, then lies
        kinds.append(("A" if v.last_bsm_anchor else "m", res.get("reason")))
        i += 1
        if res.get("reported"):
            break
        assert pid not in ledger.misbehaviour_reports
    # 3 flagged MACs reach K, the 4th MAC is refused until the next (lying, signed) anchor
    assert kinds == [("A", "valid_bsm")] + [("m", "valid_bsm")] * 3 + [("m", "anchor_required"), ("A", "valid_bsm")]
    evidence = ledger.misbehaviour_reports[pid]["evidence"]
    assert [e["evidence_hash"] for e in evidence] == [hashlib.sha256(raw).hexdigest()]


def test_vehicle_that_skips_anchors_is_cut_off():
    ledger, (r1, _), (v, _), trusted = world(anchor_every=10**9, ticket_every=10**9)
    r1.mac_run_limit = 40
    authenticate(r1, v, trusted)
    reasons = [send(r1, v, i, float(i))[1]["reason"] for i in range(60)]
    assert reasons[:41] == ["valid_bsm"] * 41 and set(reasons[41:]) == {"anchor_overdue"}
    v.anchor_every = 1                                       # one anchor resets the run
    assert send(r1, v, 60, 60.0)[1]["ok"]
    v.anchor_every = 10**9
    assert send(r1, v, 61, 61.0)[1]["ok"]
    # the reviewer's evasion: lies only in MAC BSMs, never another anchor
    ledger, (r1, _), (v, _), trusted = world(anchor_every=10**9, ticket_every=10**9)
    r1.detector = builtin_check
    authenticate(r1, v, trusted)
    res = [send(r1, v, i, float(i) if i < 15 else 5000.0)[1] for i in range(200)]
    accepted_lies = sum(r["ok"] for r in res[15:])
    assert accepted_lies == r1.detector_k and {r.get("reason") for r in res[17:]} == {"anchor_required"}


def test_stale_flags_do_not_report_a_later_lone_flag():
    ledger, (r1, _), (v, _), trusted = world(anchor_every=10, ticket_every=10**9)
    r1.detector, r1.detector_k, r1.detector_w = _FlagFar(), 3, 10
    authenticate(r1, v, trusted)
    reported, refused = [], []
    for i in range(160):
        glitch = i in (3, 4, 5) or i == 150                  # 3..5 are MACs, 150 is an anchor
        raw, res = send(r1, v, i, 5000.0 if glitch else float(i))
        assert not res["ok"] or res["anchor"] == (i % 10 == 0)
        reported += [i] if res.get("reported") else []
        refused += [] if res["ok"] else [i]
    assert reported == [] and v.current.pid not in ledger.misbehaviour_reports
    # until the 3 flags leave the window (W anchors later), only anchors are taken
    assert refused and all(i % 10 for i in refused) and max(refused) < 110 and min(refused) == 6
    assert sum(r1.bsm_flags[v.current.pid]) == 1


def test_forged_mac_history_does_not_incriminate_an_honest_anchor():
    ledger, (r1, _), (v, _), trusted = world(anchor_every=10, ticket_every=10**9)
    r1.detector = builtin_check
    ticket = authenticate(r1, v, trusted)
    digest, pk = ticket_digest(ticket), bytes.fromhex(ticket["payload"]["pk"])
    key = bsm_mac_key(r1.private_key, pk, digest)            # what an addressed RSU can compute
    flagged_anchors = 0
    for i in range(60):
        raw = v.make_bsm(**kin(i, float(i)))
        if not v.last_bsm_anchor and i > 20:
            payload = {"pid": v.current.pid, "fields": kin(i, 2000.0), "ticket_digest": digest}
            raw = make_message("BSM", payload=payload, tags={r1.rsu_id: bsm_tag(key, canonical_json(payload))}).to_bytes()
        res = r1.verify_bsm(raw, rx_time=i * 0.1, rsu_pos=(0.0, 0.0))
        flagged_anchors += bool(res.get("anchor") and res.get("flagged"))
        assert not res.get("reported"), i
    # the honest anchors look bad against the forged MAC history, but not against earlier anchors
    assert flagged_anchors >= 1 and v.current.pid not in ledger.misbehaviour_reports


def test_sig_mode_reports_on_plain_k_of_w():
    ledger, (r1, _), _, trusted = world()
    v = Vehicle(create_pseudonyms(1, 1, "car"), trusted_rsu_keys=trusted)
    register_pseudonyms(v.pseudonyms, ledger, time.time() + 600)
    r1.detector, r1.detector_k = builtin_check, 2
    authenticate(r1, v, trusted)
    res = [send(r1, v, i, float(i) if i < 5 else 5000.0) for i in range(8)]
    assert [r["reported"] for _, r in res] == [False] * 6 + [True, False]
    evidence = ledger.misbehaviour_reports[v.current.pid]["evidence"]
    assert evidence[0]["evidence_hash"] == hashlib.sha256(res[6][0]).hexdigest()


def test_pid_state_is_bounded_lru():
    ledger, (r1, _), vehicles, trusted = world(count=4, anchor_every=3)
    r1.detector, r1.pid_state_cache = builtin_check, 2
    for i, v in enumerate(vehicles):
        authenticate(r1, v, trusted)
        for j in range(4):
            assert send(r1, v, j, float(j))[1]["ok"]
    kept = [v.current.pid for v in vehicles[2:]]
    assert list(r1._pid_state) == kept and sorted(r1.bsm_history) == sorted(kept) == sorted(r1.bsm_flags)


def test_report_evidence_is_the_last_flagged_anchor():
    ledger, (r1, _), (v, _), trusted = world(anchor_every=20, ticket_every=100)
    r1.detector, r1.detector_k = _FlagAll(), 3
    authenticate(r1, v, trusted)
    anchor = v.make_bsm(**KIN)
    r1.verify_bsm(anchor)
    res = [r1.verify_bsm(mac_bsm(v)) for _ in range(2)]
    assert res[-1]["reported"] and not res[0]["reported"]
    evidence = ledger.misbehaviour_reports[v.current.pid]["evidence"]
    assert evidence[0]["evidence_hash"] == hashlib.sha256(anchor).hexdigest()


def test_adaptive_anchor_period_hysteresis():
    assert adaptive_anchor_period(0.21, 10, current=5) == 5 and adaptive_anchor_period(0.23, 10, current=5) == 10
    assert adaptive_anchor_period(0.19, 10, current=10) == 10 and adaptive_anchor_period(0.17, 10, current=10) == 5
    assert adaptive_anchor_period(0.39, 10, current=20) == 20 and adaptive_anchor_period(0.37, 10, current=20) == 10
    assert adaptive_anchor_period(0.41, 10, current=5) == 20            # far from the current period: no hold
    cbr = [0.2 + 0.015 * (-1) ** i for i in range(50)]                 # jitter around a threshold
    n, changes = 10, 0
    for c in cbr:
        new = adaptive_anchor_period(c, 10, current=n)
        changes, n = changes + (new != n), new
    assert changes <= 1


def test_adaptive_anchor_period_is_monotone():
    assert [adaptive_anchor_period(c, 10) for c in (0.0, 0.19, 0.2, 0.4, 0.41, 0.9)] == [5, 5, 10, 10, 20, 20]
    assert adaptive_anchor_period(0.1, 3) == 2 and adaptive_anchor_period(0.1, 1) == 1
    for base in (1, 2, 3, 10, 25):
        periods = [adaptive_anchor_period(i / 100, base) for i in range(101)]
        assert periods == sorted(periods) and min(periods) >= 1
