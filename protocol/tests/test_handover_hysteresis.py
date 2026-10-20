"""--handover-hysteresis and --auth-timeout: handover decision, hold-down, pseudonym sessions."""
from collections import deque
from types import SimpleNamespace

from protocol.registration import create_pseudonyms
from protocol.sim_app import AUTH_TIMEOUT, HYST_HOLD, VehicleApp
from protocol.vehicle import Vehicle


def app(**config):
    env = SimpleNamespace(config={"rsu_range": 300.0, **config}, shared={})
    dist = {"A": 280.0, "B": 100.0}                     # past the 80 % edge of A, closer to B
    node = SimpleNamespace(env=env, now=lambda: 0.0,
                           nearby_rsus=lambda radius=None: [(SimpleNamespace(name=n), d) for n, d in dist.items()])
    a = VehicleApp(node, env)
    a.vehicle.current_rsu_id = "A"
    return a, node, dist


def hear(a, rsu, *times):
    for t in times:
        a.heard[rsu] = t
        if a.hysteresis:
            a.beacon_times.setdefault(rsu, deque(maxlen=3)).append(t)


def test_auth_timeout_option():
    assert app()[0].auth_timeout == AUTH_TIMEOUT == 1.0
    assert app(auth_timeout=0.2)[0].auth_timeout == 0.2


def test_default_handover_rule_unchanged():
    a, node, dist = app()
    hear(a, "A", 9.8)
    hear(a, "B", 10.0)
    assert a._should_handover(node, "B", 10.0)                  # one beacon from B is enough
    dist["A"] = 100.0
    assert not a._should_handover(node, "B", 10.0)              # inside A's range, A heard 0.2 s ago
    assert a._should_handover(node, "B", 10.4)                  # A lost after 0.35 s


def test_hysteresis_needs_three_recent_target_beacons():
    a, node, _ = app(handover_hysteresis=True)
    hear(a, "A", 9.9)
    hear(a, "B", 9.8, 10.0)
    assert not a._should_handover(node, "B", 10.0)
    hear(a, "B", 10.1)
    assert a._should_handover(node, "B", 10.1)
    hear(a, "B", 11.0)
    assert not a._should_handover(node, "B", 11.0)              # 3rd-last beacon of B 1 s ago


def test_hysteresis_lost_after_one_second():
    a, node, dist = app(handover_hysteresis=True)
    dist["A"] = 100.0                                           # well inside A's range
    hear(a, "A", 11.0)
    hear(a, "B", 11.8, 11.85, 11.9)
    assert not a._should_handover(node, "B", 11.9)              # A silent 0.9 s: not lost yet
    hear(a, "B", 12.0, 12.05, 12.1)
    assert a._should_handover(node, "B", 12.1)                  # A silent 1.1 s: lost


def test_hold_down_after_handover_unless_lost():
    a, node, _ = app(handover_hysteresis=True)
    a.hold_until = 10.0 + HYST_HOLD
    hear(a, "A", 10.5)
    hear(a, "B", 10.6, 10.7, 10.8)
    assert not a._should_handover(node, "B", 10.8)
    hear(a, "B", 11.1, 11.2, 11.3)
    assert a._should_handover(node, "B", 11.3)                  # hold-down over
    a.hold_until = 13.0
    hear(a, "B", 11.9, 12.0, 12.1)
    assert a._should_handover(node, "B", 12.1)                  # A silent for 1.6 s: lost beats the hold


def test_handovers_do_not_burn_pseudonyms_with_hysteresis():
    ps = create_pseudonyms(2, 1, "car")
    v = Vehicle(ps, handover_sessions=False)
    for i in range(10):
        v.handover_accepted(f"RSU-{i}")
    assert v.sessions_on_current == 0 and v.current_rsu_id == "RSU-9"
    old = Vehicle(create_pseudonyms(1, 1, "car"))
    old.handover_accepted("RSU-1")
    assert old.sessions_on_current == 1
    assert app(handover_hysteresis=True)[0].vehicle.handover_sessions is False
    assert app()[0].vehicle.handover_sessions is True


def test_profiles_set_defaults_and_explicit_options_win():
    from network.run_scenario import parse_args
    keys = ("bsm_ticket", "compact_wire", "auth_timeout", "handover_hysteresis", "fast_revocation",
            "bsm_auth", "adaptive_anchor")
    pick = lambda argv: tuple(vars(parse_args(argv))[k] for k in keys)  # noqa: E731
    assert pick([]) == pick(["--profile", "baseline"]) == ("full", False, 1.0, False, False, "sig", False)
    assert pick(["--profile", "v2"]) == ("digest", True, 0.2, True, True, "sig", False)
    assert pick(["--profile", "v2-mac"]) == ("digest", True, 0.2, True, True, "mac", True)
    assert pick(["--profile", "v2", "--bsm-ticket", "full", "--auth-timeout", "0.5"])[:3] == ("full", True, 0.5)
