"""--bsm-ticket digest and --compact-wire: ticket digests in BSMs, fixed-point kinematics,
BIP340 BSM signatures and beacons without the RSU key."""
import time

import pytest

from protocol.crypto import bip340_sign, bip340_verify, keygen, schnorr_sign
from protocol.ledger import MockLedger
from protocol.messages import INTERNED, KINEMATICS_BYTES, Message, make_message, pack_kinematics, unpack_kinematics
from protocol.registration import create_pseudonyms, register_pseudonyms
from protocol.rsu import RSU
from protocol.vehicle import Vehicle, canonical_json, ticket_digest

KIN = dict(seq=7, t=12.345, x=1234.567, y=-89.012, speed=13.9, heading=271.3)


def world(count=2, cache=100, beacon_public_key=True, **vehicle_opts):
    ledger = MockLedger()
    ledger.set_policy("road_access", {"car"})
    ps = create_pseudonyms(count, 1, "car")
    register_pseudonyms(ps, ledger, time.time() + 600)
    (sk1, pk1), (sk2, pk2) = keygen(), keygen()
    trusted = {"RSU-1": pk1, "RSU-2": pk2}
    rsus = [RSU(name, ledger.view(name), sk, pk, trusted_rsu_keys=trusted, ticket_digest_cache=cache,
                beacon_public_key=beacon_public_key)
            for name, sk, pk in (("RSU-1", sk1, pk1), ("RSU-2", sk2, pk2))]
    vehicles = [Vehicle([p], trusted_rsu_keys=trusted, **vehicle_opts) for p in ps]
    return ledger, rsus, vehicles, trusted


def authenticate(rsu, vehicle, trusted):
    res = rsu.authenticate(vehicle.make_auth_request(rsu.beacon(), "road_access"))
    assert res["ok"], res
    assert vehicle.accept_ticket(res["ticket"], trusted[rsu.rsu_id])
    return res["ticket"]


def payload(bsm: bytes) -> dict:
    return Message.from_bytes(bsm).fields["payload"]


def resign(bsm: bytes, change, secret: int, compact: bool = False) -> bytes:
    msg = Message.from_bytes(bsm)
    change(msg.fields["payload"])
    sign = bip340_sign if compact else schnorr_sign
    msg.fields["signature"] = sign(secret, canonical_json(msg.fields["payload"]))
    return msg.to_bytes()


def test_interned_strings_are_append_only():
    assert INTERNED[50] == "missing_shared_authorization"
    assert INTERNED[51:54] == ["ticket_digest", "k", "unknown_ticket_digest"]


def test_default_bsm_is_unchanged():
    _, (r1, _), (v, _), trusted = world()
    authenticate(r1, v, trusted)
    raw = v.make_bsm(**KIN)
    msg = Message.from_bytes(raw)
    assert list(msg.fields["payload"]) == ["pid", "fields", "ticket"]
    assert set(msg.fields["signature"]) == {"R", "s"}
    assert all(set(payload(v.make_bsm(**KIN))) == {"pid", "fields", "ticket"} for _ in range(20))


def test_digest_schedule_and_round_trip():
    _, (r1, _), (v, _), trusted = world(bsm_ticket="digest", ticket_every=3)
    ticket = authenticate(r1, v, trusted)
    kinds = []
    for _ in range(7):
        raw = v.make_bsm(**KIN)
        assert r1.verify_bsm(raw)["ok"]
        kinds.append("full" if "ticket" in payload(raw) else "digest")
    assert kinds == ["full", "digest", "digest", "full", "digest", "digest", "full"]
    assert payload(v.make_bsm(**KIN))["ticket_digest"] == ticket_digest(ticket) == ticket_digest(v.ticket)
    assert len(ticket_digest(ticket)) == 16
    v.send_full_ticket()
    assert "ticket" in payload(v.make_bsm(**KIN))
    v.handover_accepted("RSU-2")
    assert "ticket" in payload(v.make_bsm(**KIN))


def test_digest_unknown_at_other_rsu_until_learned():
    _, (r1, r2), (v, _), trusted = world(bsm_ticket="digest")
    ticket = authenticate(r1, v, trusted)
    full, digest = v.make_bsm(**KIN), v.make_bsm(**KIN)
    assert "ticket_digest" in payload(digest)
    assert r1.verify_bsm(digest)["ok"]                    # issuer cached it at authentication
    res = r2.verify_bsm(digest)
    assert not res["ok"] and res["reason"] == "unknown_ticket_digest" and res["pid"] == v.current.pid
    assert r2.receive_preauth(r1.preauthorize_neighbour("RSU-2", ticket))["ok"]
    assert r2.verify_bsm(digest)["ok"]
    _, (_, r3), _, _ = world()
    r3.trusted_rsu_keys.update(trusted)
    assert r3.verify_bsm(full)["ok"] and r3.verify_bsm(digest)["ok"]   # learned from the full-ticket BSM


def test_digest_learned_from_handover_request():
    _, (r1, r2), (v, _), trusted = world(bsm_ticket="digest")
    authenticate(r1, v, trusted)
    r2.handover(v.make_handover_request("RSU-2"))       # answer does not matter: the ticket is RSU-signed
    v.make_bsm(**KIN)
    assert r2.verify_bsm(v.make_bsm(**KIN))["ok"]


def test_rsu_without_cache_rejects_digests():
    _, (r1, _), (v, _), trusted = world(cache=0, bsm_ticket="digest")
    authenticate(r1, v, trusted)
    assert r1.verify_bsm(v.make_bsm(**KIN))["ok"]
    assert r1.verify_bsm(v.make_bsm(**KIN))["reason"] == "unknown_ticket_digest"


def test_digest_tampered_forged_and_unknown_rejected():
    _, (r1, _), (victim, attacker), trusted = world(bsm_ticket="digest")
    authenticate(r1, victim, trusted)
    authenticate(r1, attacker, trusted)
    victim.make_bsm(**KIN)
    good = victim.make_bsm(**KIN)
    assert r1.verify_bsm(good)["ok"]
    victim_digest = payload(good)["ticket_digest"]
    # tampered kinematics or digest: the pseudonym signature fails
    tampered = Message.from_bytes(good)
    tampered.fields["payload"]["fields"]["x"] = 0.0
    assert r1.verify_bsm(tampered.to_bytes())["reason"] == "invalid_bsm_signature"
    attacker.make_bsm(**KIN)
    own = attacker.make_bsm(**KIN)
    swapped = Message.from_bytes(own)
    swapped.fields["payload"]["ticket_digest"] = victim_digest
    assert r1.verify_bsm(swapped.to_bytes())["reason"] == "ticket_pseudonym_mismatch"
    # forged: victim's pid and digest, signed with the attacker's key
    forged = resign(own, lambda p: p.update(pid=victim.current.pid, ticket_digest=victim_digest),
                    attacker.current.secret)
    assert r1.verify_bsm(forged)["reason"] == "invalid_bsm_signature"
    unknown = resign(own, lambda p: p.update(ticket_digest="00" * 8), attacker.current.secret)
    assert r1.verify_bsm(unknown)["reason"] == "unknown_ticket_digest"


def test_digest_still_checks_expiry_and_revocation():
    ledger, (r1, _), (v, _), trusted = world(bsm_ticket="digest")
    authenticate(r1, v, trusted)
    v.make_bsm(**KIN)
    digest = v.make_bsm(**KIN)
    ledger.revoke(v.current.pid)
    assert r1.verify_bsm(digest)["reason"] == "expired_or_revoked"
    clock = [time.time()]
    _, (r1, _), (v, _), trusted = world(bsm_ticket="digest")
    r1.clock = v.clock = lambda: clock[0]
    authenticate(r1, v, trusted)
    v.make_bsm(**KIN)
    digest = v.make_bsm(**KIN)
    clock[0] += r1.ticket_seconds + 1
    assert r1.verify_bsm(digest)["reason"] == "expired_or_revoked"


def test_digest_cache_is_bounded_lru():
    _, (r1, _), vehicles, trusted = world(count=3, cache=2, bsm_ticket="digest")
    for v in vehicles:
        authenticate(r1, v, trusted)
        v.make_bsm(**KIN)
    assert len(r1._digest_tickets) == 2
    assert r1.verify_bsm(vehicles[0].make_bsm(**KIN))["reason"] == "unknown_ticket_digest"
    assert r1.verify_bsm(vehicles[2].make_bsm(**KIN))["ok"]


def test_digest_reduces_bsm_size():
    _, (r1, _), (v, _), trusted = world(bsm_ticket="digest")
    authenticate(r1, v, trusted)
    full, digest = len(v.make_bsm(**KIN)), len(v.make_bsm(**KIN))
    assert full - digest >= 150 and digest <= 180, (full, digest)


def test_kinematics_pack_round_trip_and_limits():
    blob = pack_kinematics(KIN)
    assert len(bytes.fromhex(blob)) == KINEMATICS_BYTES == 18
    out = unpack_kinematics(blob, ref_time=12.3)
    assert out["seq"] == 7 and out["t"] == 12.345
    assert abs(out["x"] - KIN["x"]) <= 0.005 and abs(out["y"] - KIN["y"]) <= 0.005
    assert abs(out["speed"] - KIN["speed"]) <= 0.01 and abs(out["heading"] - KIN["heading"]) <= 0.00625
    now = time.time()                                   # wall clock: 32-bit ms stamp unwrapped near ref
    assert abs(unpack_kinematics(pack_kinematics({**KIN, "t": now}), ref_time=now + 0.2)["t"] - now) < 0.001
    edge = unpack_kinematics(pack_kinematics(dict(seq=70000, t=1.0, x=0, y=0, speed=5000.0, heading=-0.5)))
    assert edge["seq"] == 70000 % 65536 and edge["speed"] == pytest.approx(1310.7)
    assert edge["heading"] == pytest.approx(359.5)
    assert unpack_kinematics(pack_kinematics(dict(speed=-3.0)))["speed"] == 0.0
    with pytest.raises(ValueError):
        unpack_kinematics("00" * 17)
    with pytest.raises(ValueError):
        pack_kinematics(dict(x=float("nan")))


def test_bip340_signatures():
    for _ in range(8):                                  # covers keys with odd and even y
        sk, pk = keygen()
        sig = bip340_sign(sk, b"bsm")
        assert len(bytes.fromhex(sig)) == 64 and bip340_verify(pk, b"bsm", sig)
        assert not bip340_verify(pk, b"other", sig)
        assert not bip340_verify(keygen()[1], b"bsm", sig)
        assert not bip340_verify(pk, b"bsm", sig[:-2] + format(int(sig[-2:], 16) ^ 1, "02x"))
        assert not bip340_verify(pk, b"bsm", "zz")


def test_compact_bsm_round_trip_and_detector_fields():
    seen = []
    _, (r1, _), (v, _), trusted = world(compact_wire=True)
    r1.detector = lambda bsm, history: (seen.append(bsm) or False, {})
    authenticate(r1, v, trusted)
    now = time.time()
    raw = v.make_bsm(**{**KIN, "t": now})
    msg = Message.from_bytes(raw)
    assert set(msg.fields["payload"]) == {"pid", "k", "ticket"} and isinstance(msg.fields["signature"], str)
    res = r1.verify_bsm(raw, rx_time=now + 0.001)
    assert res["ok"], res
    assert abs(res["payload"]["fields"]["t"] - now) < 0.001
    assert seen[0]["seq"] == 7 and abs(seen[0]["x"] - KIN["x"]) <= 0.005 and seen[0]["heading"] == 271.3


def test_compact_bsm_tampered_and_forged_rejected():
    _, (r1, _), (v, attacker), trusted = world(compact_wire=True)
    authenticate(r1, v, trusted)
    authenticate(r1, attacker, trusted)
    raw = v.make_bsm(**KIN)
    tampered = Message.from_bytes(raw)
    tampered.fields["payload"]["k"] = pack_kinematics({**KIN, "x": 0.0})
    assert r1.verify_bsm(tampered.to_bytes())["reason"] == "invalid_bsm_signature"
    forged = resign(raw, lambda p: None, attacker.current.secret, compact=True)
    assert r1.verify_bsm(forged)["reason"] == "invalid_bsm_signature"
    legacy = resign(raw, lambda p: None, v.current.secret)   # the owner's {R, s} signature is also valid
    assert r1.verify_bsm(legacy)["ok"]
    bad_blob = resign(raw, lambda p: p.update(k="00" * 5), v.current.secret, compact=True)
    assert r1.verify_bsm(bad_blob)["reason"] == "malformed_bsm"


def test_compact_and_digest_sizes():
    sizes = {}
    for mode, opts in {"default": {}, "compact": dict(compact_wire=True),
                       "both": dict(compact_wire=True, bsm_ticket="digest")}.items():
        _, (r1, _), (v, _), trusted = world(**opts)
        authenticate(r1, v, trusted)
        first = v.make_bsm(**KIN)
        second = v.make_bsm(**KIN)
        assert r1.verify_bsm(first)["ok"] and r1.verify_bsm(second)["ok"]
        sizes[mode] = len(second)
    assert sizes["default"] - sizes["compact"] >= 50, sizes
    assert sizes["both"] <= 130, sizes


def test_beacon_without_public_key():
    _, (r1, r2), (v, _), _ = world(beacon_public_key=False)
    beacon = r1.beacon()
    assert "public_key" not in beacon
    full = make_message("BEACON", **world()[1][0].beacon()).to_bytes()
    assert len(full) - len(make_message("BEACON", **beacon).to_bytes()) >= 30
    assert v.verify_beacon(beacon)
    assert v.make_auth_request(beacon, "road_access")
    forged = {**beacon, "payload": {**beacon["payload"], "rsu_id": "RSU-2"}}
    assert not v.verify_beacon(forged)
    wrong_key = {**r2.beacon(), "public_key": r1.public_key.hex()}
    assert not v.verify_beacon(wrong_key)


def test_padded_tickets_cannot_flush_the_digest_cache():
    _, (r1, _), (victim, attacker), trusted = world(cache=5, bsm_ticket="digest")
    authenticate(r1, victim, trusted)
    authenticate(r1, attacker, trusted)
    assert r1.verify_bsm(victim.make_bsm(**KIN))["ok"]
    own = attacker.make_bsm(**KIN)
    for i in range(20):
        def pad(p, i=i):
            p["ticket"] = {**p["ticket"], f"x{i}": 1,
                           "signature": {**p["ticket"]["signature"], "junk": f"{i:02x}"}}
        assert r1.verify_bsm(resign(own, pad, attacker.current.secret))["ok"]
    assert len(r1._digest_tickets) == 2
    assert ticket_digest({**victim.ticket, "x": 1}) == ticket_digest(victim.ticket)
    assert r1.verify_bsm(victim.make_bsm(**KIN))["ok"]


def test_compact_bsm_requires_all_kinematic_fields():
    _, (r1, _), (v, _), trusted = world(compact_wire=True)
    authenticate(r1, v, trusted)
    with pytest.raises(ValueError):
        v.make_bsm(seq=1, t=1.0)
    with pytest.raises(ValueError):
        v.make_bsm(**KIN, extra=1)
    alias = {**KIN, "timestamp": KIN["t"]}
    del alias["t"]
    assert r1.verify_bsm(v.make_bsm(**alias))["ok"]


def test_ticket_every_only_checked_in_digest_mode():
    Vehicle(create_pseudonyms(1, 1, "car"), ticket_every=0)
    with pytest.raises(ValueError):
        Vehicle(create_pseudonyms(1, 1, "car"), bsm_ticket="digest", ticket_every=0)


def test_compact_seq_unwraps_across_u16():
    seen = []
    _, (r1, _), (v, _), trusted = world(compact_wire=True)
    r1.detector = lambda bsm, history: (seen.append(bsm["seq"]) or False, {})
    authenticate(r1, v, trusted)
    for seq in (65534, 65535, 65536, 65537, 65535):
        assert r1.verify_bsm(v.make_bsm(**{**KIN, "seq": seq}))["ok"]
    assert seen == [65534, 65535, 65536, 65537, 65535]
