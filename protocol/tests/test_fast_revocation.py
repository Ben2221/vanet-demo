"""--fast-revocation: signed QUARANTINE notes and the local K-of-RSUs block."""
import time

from protocol.crypto import keygen
from protocol.ledger import MockLedger
from protocol.messages import INTERNED, TYPE_CODES, Message, message_type
from protocol.registration import create_pseudonyms, register_pseudonyms
from protocol.rsu import RSU
from protocol.vehicle import Vehicle

KIN = dict(seq=1, t=0.1, x=10.0, y=0.0, speed=10.0, heading=0.0)


def flag_all(bsm, history):
    return True, {}


def world(k=2, rsus=3, ttl=30.0):
    """RSUs that report on the first BSM; the ledger never auto-revokes, so only quarantine blocks."""
    clock = [time.time()]
    now = lambda: clock[0]  # noqa: E731
    ledger = MockLedger(auto_revoke_k=99)
    ledger.set_policy("road_access", {"car"})
    ps = create_pseudonyms(1, 1, "car")
    register_pseudonyms(ps, ledger, time.time() + 600)
    keys = {f"RSU-{i}": keygen() for i in range(1, rsus + 1)}
    trusted = {name: pk for name, (_, pk) in keys.items()}
    nodes = [RSU(name, ledger.view(name), sk, pk, trusted_rsu_keys=trusted, detector=flag_all, detector_k=1,
                 quarantine_k=k, quarantine_ttl=ttl, clock=now) for name, (sk, pk) in keys.items()]
    v = Vehicle(ps, trusted_rsu_keys=trusted, clock=now)
    return clock, ledger, nodes, v, trusted


def authenticate(rsu, v, trusted):
    res = rsu.authenticate(v.make_auth_request(rsu.beacon(), "road_access"))
    assert res["ok"], res
    assert v.accept_ticket(res["ticket"], trusted[rsu.rsu_id])
    return res["ticket"]


def report(rsu, bsm):
    res = rsu.verify_bsm(bsm, rx_time=0.1, rsu_pos=(0.0, 0.0))
    assert res["ok"] and res["reported"] and res["evidence"], res
    return res


def edit(raw, change):
    msg = Message.from_bytes(raw)
    change(msg.fields)
    return msg.to_bytes()


def test_wire_codes_are_append_only():
    assert TYPE_CODES["QUARANTINE"] == 7
    assert [TYPE_CODES[t] for t in ("BEACON", "AUTH_REQ", "AUTH_RESP", "HANDOVER_REQ", "PREAUTH", "BSM")] == list(range(1, 7))
    assert INTERNED[54:62] == ["tags", "invalid_bsm_mac", "bsm_mac_not_for_rsu", "anchor_overdue", "anchor_required",
                               "evidence", "reporter", "quarantined"]


def test_note_round_trip_and_size():
    _, _, (r1, r2, _), v, trusted = world()
    authenticate(r1, v, trusted)
    res = report(r1, v.make_bsm(**KIN))
    note = r1.make_quarantine(res["pid"], res["evidence"])
    assert message_type(note) == "QUARANTINE"
    f = Message.from_bytes(note).fields
    assert (f["pid"], f["evidence"], f["reporter"]) == (res["pid"], res["evidence"], "RSU-1")
    assert len(note) < 200 < len(r1.preauthorize_neighbour("RSU-2", v.ticket))
    got = r2.receive_quarantine(note)
    assert got == {"ok": True, "reason": "quarantine_accepted", "pid": res["pid"], "blocked": False}


def test_k_distinct_reporters_block_auth_handover_and_bsm():
    _, ledger, (r1, r2, r3), v, trusted = world()
    ticket = authenticate(r1, v, trusted)
    assert r3.receive_preauth(r1.preauthorize_neighbour("RSU-3", ticket))["ok"]
    bsm = v.make_bsm(**KIN)
    res1, res2 = report(r1, bsm), report(r2, bsm)
    assert not res1["blocked"] and not res2["blocked"]           # own report alone is 1 of K = 2
    pid = res1["pid"]
    n1, n2 = r1.make_quarantine(pid, res1["evidence"]), r2.make_quarantine(pid, res2["evidence"])
    assert not r3.receive_quarantine(n1)["blocked"]
    assert not r3.receive_quarantine(n1)["blocked"]               # a replayed note is the same reporter
    assert not r3.quarantined(pid)
    assert r3.receive_quarantine(n2)["blocked"] and r3.quarantined(pid)
    assert r1.receive_quarantine(n2)["blocked"]                   # own report + one note
    assert not ledger.is_revoked(pid)
    assert r3.verify_bsm(v.make_bsm(**KIN))["reason"] == "quarantined"
    assert r3.handover(v.make_before_break_handover("RSU-3", r3.beacon()))["reason"] == "quarantined"
    assert r3.authenticate(v.make_auth_request(r3.beacon(), "road_access"))["reason"] == "quarantined"
    assert r2.verify_bsm(v.make_bsm(**KIN))["ok"]                 # r2 has only its own report


def test_block_ends_after_ttl_or_turns_into_revocation():
    clock, ledger, (r1, r2, r3), v, trusted = world(ttl=30.0)
    authenticate(r1, v, trusted)
    bsm = v.make_bsm(**KIN)
    for r in (r1, r2):
        res = report(r, bsm)
        r3.receive_quarantine(r.make_quarantine(res["pid"], res["evidence"]))
    pid = res["pid"]
    assert r3.quarantined(pid)
    clock[0] += 31.0
    assert not r3.quarantined(pid)
    r3.quarantine_until[pid] = clock[0] + 30.0
    ledger.revoke([pid])
    assert not r3.quarantined(pid)                                # the ledger's revocation takes over
    assert r3.authenticate(v.make_auth_request(r3.beacon(), "road_access"))["reason"] == "revoked"


def test_forged_tampered_stale_and_untrusted_notes_rejected():
    clock, _, (r1, r2, r3), v, trusted = world()
    authenticate(r1, v, trusted)
    res = report(r1, v.make_bsm(**KIN))
    note = r1.make_quarantine(res["pid"], res["evidence"])
    other = "ab" * 16

    def reason(raw):
        return r3.receive_quarantine(raw)["reason"]

    assert reason(edit(note, lambda f: f.update(pid=other))) == "invalid_quarantine_signature"
    assert reason(edit(note, lambda f: f.update(evidence="cd" * 32))) == "invalid_quarantine_signature"
    assert reason(edit(note, lambda f: f.update(reporter="RSU-2"))) == "invalid_quarantine_signature"
    assert reason(edit(note, lambda f: f.update(reporter="RSU-9"))) == "untrusted_reporter"
    rogue_sk, rogue_pk = keygen()
    rogue = RSU("RSU-9", None, rogue_sk, rogue_pk, clock=lambda: clock[0])
    assert reason(rogue.make_quarantine(res["pid"], res["evidence"])) == "untrusted_reporter"
    assert reason(edit(note, lambda f: f.pop("pid"))) == "malformed_quarantine"
    assert reason(b"\x07\x01\x00") == "malformed_quarantine"
    assert reason(r1.preauthorize_neighbour("RSU-3", v.ticket)) == "wrong_message_type"
    clock[0] += 10.0
    assert reason(note) == "stale_quarantine"
    assert not r3.reporters


def test_disabled_by_default():
    _, _, (r1, r2, r3), v, trusted = world(k=0)
    authenticate(r1, v, trusted)
    bsm = v.make_bsm(**KIN)
    for r in (r1, r2):
        res = report(r, bsm)
        assert not res["blocked"]
        assert r3.receive_quarantine(r.make_quarantine(res["pid"], res["evidence"]))["blocked"] is False
    assert not r3.quarantined(res["pid"]) and r3.verify_bsm(v.make_bsm(**KIN))["ok"]
