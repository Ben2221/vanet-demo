"""Unit and integration tests for Person 1's part. Run: pytest network/tests"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from network import ns2_mobility  # noqa: E402
from network.ledger_bridge import LedgerBridge  # noqa: E402
from network.ledger_client import AccessDenied, InMemoryLedger  # noqa: E402
from network.radio import RadioConfig  # noqa: E402
from network.range_test import range_test  # noqa: E402


# ------------------------------------------------------------------ radio
def test_path_loss_puts_threshold_at_400m():
    r = RadioConfig()
    assert r.rx_power_dbm(400) == pytest.approx(r.rx_sensitivity_dbm, abs=1e-6)
    assert r.rx_power_dbm(300) > r.rx_sensitivity_dbm > r.rx_power_dbm(450)


def test_airtime_200_byte_bsm():
    # 200 B + 66 B headers = 2150 bits incl. service+tail, 48 bits/symbol -> 45 symbols
    assert RadioConfig().airtime(200) == pytest.approx(40e-6 + 45 * 8e-6)


def test_range_lite_backend():
    rows = {r["distance_m"]: r["pdr"] for r in range_test([100, 300, 450], backend="lite", packets=20)}
    assert rows[100] == 1.0 and rows[300] == 1.0 and rows[450] == 0.0


# --------------------------------------------------------------- mobility
def test_ns2_parser(tmp_path):
    f = tmp_path / "t.ns2"
    f.write_text(
        "$node_(0) set X_ -1000.0\n$node_(0) set Y_ -1000.0\n$node_(0) set Z_ 0.0\n"
        '$ns_ at 1.00 "$node_(0) set X_ 0.00"\n'
        '$ns_ at 1.00 "$node_(0) set Y_ 0.00"\n'
        '$ns_ at 1.00 "$node_(0) setdest 10.00 0.00 10.000"\n'
        '$ns_ at 2.00 "$node_(0) setdest 10.00 20.00 10.000"\n'
        '$ns_ at 5.00 "$node_(0) set X_ -1000.00"\n'
    )
    tr = ns2_mobility.load(f)[0]
    assert tr.position(0.5) == (-1000.0, -1000.0)
    assert tr.position(1.5) == pytest.approx((5.0, 0.0))
    assert tr.position(3.0) == pytest.approx((10.0, 10.0))
    assert tr.position(4.5) == pytest.approx((10.0, 20.0))     # arrived at 4.0 and stopped
    assert tr.velocity(3.0) == pytest.approx((0.0, 10.0))
    assert tr.position(6.0)[0] == -1000.0


def test_vehicle_keeps_driving_after_its_last_fcd_sample(tmp_path):
    # last sample at t = 2 at 20 m/s heading east (SUMO angle 90): until it leaves at t = 3 it must
    # keep moving, not stand still (a stop from 20 m/s in no time looks like a lie to the detector)
    from mobility import fcd_to_ns2
    fcd = tmp_path / "fcd.xml"
    fcd.write_text('<fcd-export>' + "".join(
        f'<timestep time="{t}.00"><vehicle id="v" x="{100 + 20 * t}" y="50" speed="20" angle="90"/></timestep>'
        for t in range(3)) + '</fcd-export>')
    fcd_to_ns2.convert(fcd, tmp_path, step=1.0)
    tr = ns2_mobility.load(tmp_path / "trace.ns2")[0]
    assert tr.position(2.5) == pytest.approx((150.0, 50.0), abs=0.01)
    assert tr.velocity(2.5) == pytest.approx((20.0, 0.0), abs=0.01)


def test_position_table_does_not_slide_into_the_parking_spot(tmp_path):
    # the vehicle leaves at t = 5 (jump to -1000); just before, the radio must still see it on the road
    f = tmp_path / "t.ns2"
    f.write_text('$node_(0) set X_ 10.0\n$node_(0) set Y_ 0.0\n'
                 '$ns_ at 5.00 "$node_(0) set X_ -1000.00"\n')
    table = ns2_mobility.PositionTable(ns2_mobility.load(f), 1, end=6.0)
    assert table.at(4.95)[0] == pytest.approx((10.0, 0.0))
    assert table.at(5.5)[0][0] == -1000.0


# ----------------------------------------------------------------- ledger
def test_caller_rules():
    led = InMemoryLedger()
    with pytest.raises(AccessDenied):
        led.call("rsu0", "register_root", epoch=1, merkle_root="ab", valid_until=1)
    with pytest.raises(AccessDenied):
        led.call("TA", "record_auth", pid_hash="p", service="s", cls="c", expiry=1)
    assert "txId" in led.call("TA", "register_root", epoch=1, merkle_root="ab", valid_until=1)


def test_two_reports_revoke_and_trace_threshold():
    led = InMemoryLedger(report_k=2, trace_threshold=3)
    led.call("rsu0", "report_misbehaviour", pid="p1", evidence_hash="e")
    assert not led.call("rsu0", "is_revoked", pid="p1")["revoked"]
    led.call("rsu0", "report_misbehaviour", pid="p1", evidence_hash="e")   # same RSU twice
    assert not led.call("rsu0", "is_revoked", pid="p1")["revoked"]
    led.call("rsu1", "report_misbehaviour", pid="p1", evidence_hash="e")
    assert led.call("rsu0", "is_revoked", pid="p1")["revoked"]
    led.call("rsu0", "request_trace", req_id="t", pid="p1", reason="r")
    for i, rsu in enumerate(["rsu0", "rsu1", "rsu2"]):
        res = led.call(rsu, "approve_trace", req_id="t")
        assert res["approved"] == (i == 2)


class FakeClock:
    def __init__(self):
        self.t = 0.0
        self.q = []

    def now(self):
        return self.t

    def schedule(self, delay, fn):
        self.q.append((self.t + delay, len(self.q), fn))
        self.q.sort(key=lambda e: (e[0], e[1]))

    def run(self, until):
        while self.q and self.q[0][0] <= until:
            self.t, _, fn = self.q.pop(0)
            fn()
        self.t = until


def test_bridge_visibility_after_commit_time():
    clock = FakeClock()
    led = InMemoryLedger(commit_ms=800, commit_jitter=0)
    bridge = LedgerBridge(led, clock.now, clock.schedule)
    a, b = bridge.view("rsu0"), bridge.view("rsu1")
    a.record_auth("pid1", "safety", "car", 100)
    assert a.get_auth("pid1") is not None          # the writer knows at once
    assert b.get_auth("pid1") is None              # others wait for the commit
    clock.run(0.79)
    assert b.get_auth("pid1") is None
    clock.run(0.81)
    assert b.get_auth("pid1")["class"] == "car"
    a.report_misbehaviour("bad", "e")
    b.report_misbehaviour("bad", "e")
    clock.run(1.0)
    assert not a.is_revoked("bad")
    clock.run(1.7)
    assert a.is_revoked("bad") and b.is_revoked("bad")


# ------------------------------------------------------------ end to end
@pytest.fixture(scope="module")
def small_run(tmp_path_factory):
    from network.run_scenario import main
    out = tmp_path_factory.mktemp("run")
    summary = main(["--backend", "lite", "--vehicles", "30", "--duration", "40", "--seed", "3",
                    "--protocol", "stub", "--attacker-ratio", "0.1", "--attack", "random_pos",
                    "--attack-start", "5", "--mock-commit-ms", "300", "--out", str(out), "--quiet"])
    return out, summary


def test_outputs_written(small_run):
    out, summary = small_run
    for f in ("metrics.csv", "summary.json", "config.json", "attackers.csv"):
        assert (out / f).exists()
    with (out / "metrics.csv").open() as f:
        header = next(csv.reader(f))
    assert header == ["sim_time", "node", "event", "bytes", "latency_ms", "result"]
    assert json.loads((out / "summary.json").read_text())["vehicles"] == 30


def test_network_and_protocol_work(small_run):
    out, summary = small_run
    assert summary["broadcast_pdr"] > 0.8
    with (out / "metrics.csv").open() as f:
        events = [r["event"] for r in csv.DictReader(f)]
    assert "AUTH_OK" in events
    assert "LEDGER_VISIBLE" in events
    assert "REPORT" in events


def test_traci_matches_fcd():
    from mobility.build_scenario import ensure_scenario
    from mobility.fcd_to_ns2 import read_fcd
    from network.traci_mobility import TraciMobility

    sc = ensure_scenario(30, 40, 3, quiet=True)
    with sc["node_map"].open() as f:
        node_of = {r["sumo_id"]: int(r["node_id"]) for r in csv.DictReader(f)}
    fcd = read_fcd(sc["fcd"])
    mob = TraciMobility(sc["dir"] / "scenario.sumocfg", node_of, len(node_of), [], seed=3)
    try:
        mob.advance(20.0)
        checked = 0
        for sid, tr in fcd.items():
            for t, x, y, _, _ in tr.samples:
                if t == 20.0:
                    px, py = mob.position(node_of[sid], 20.0)
                    assert abs(px - x) < 0.05 and abs(py - y) < 0.05
                    checked += 1
        assert checked > 0
    finally:
        mob.close()


def test_ledger_view_lists_traces():
    clock = FakeClock()
    bridge = LedgerBridge(InMemoryLedger(commit_ms=100, commit_jitter=0, trace_threshold=2),
                          clock.now, clock.schedule, sync_identity="rsu0")
    a = bridge.view("rsu0")
    a.request_trace("t1", "pid1", "test")
    assert a.traces() == {}
    clock.run(0.2)
    assert list(a.traces()) == ["t1"] and not a.traces()["t1"]["approved"]
    assert bridge.sync_identity == "rsu0"


@pytest.fixture(scope="module")
def real_run(tmp_path_factory):
    """Person 3's protocol (ZKP authentication, signed tickets, ledger) in the scenario."""
    pytest.importorskip("coincurve")
    from network.run_scenario import main
    out = tmp_path_factory.mktemp("real")
    summary = main(["--backend", "lite", "--vehicles", "30", "--duration", "40", "--seed", "3",
                    "--protocol", "real", "--attacker-ratio", "0.1", "--attack", "random_pos",
                    "--attack-start", "5", "--mock-commit-ms", "300", "--out", str(out), "--quiet"])
    with (out / "metrics.csv").open() as f:
        rows = list(csv.DictReader(f))
    return out, summary, rows


def test_real_protocol_runs_end_to_end(real_run):
    out, summary, rows = real_run
    events = {r["event"] for r in rows}
    for ev in ("PID_ASSIGN", "AUTH_VERIFY", "AUTH_OK", "HANDOVER_OK", "TX_PREAUTH", "PREAUTH_OK",
               "LEDGER_SUBMIT", "LEDGER_VISIBLE", "REPORT", "REVOKED_VISIBLE"):
        assert ev in events, ev
    assert summary["broadcast_pdr"] > 0.8
    # PREAUTH goes over the backbone, not the radio
    assert all(r["result"].startswith("backbone:") for r in rows if r["event"] in ("TX_PREAUTH", "RX_PREAUTH"))
    # 10 Hz traffic is not logged per packet without --log-bsm
    assert not events & {"TX_BEACON", "RX_BEACON", "TX_BSM", "RX_BSM"}


def test_real_protocol_latency_includes_crypto(real_run):
    out, summary, rows = real_run
    cfg = json.loads((out / "config.json").read_text())
    ct = cfg["compute_times_used"]
    if not ct:
        pytest.skip("no compute-times file (python -m protocol.measure)")
    # the RSU reports its verification time (Merkle check + ZKP verify) in AUTH_VERIFY
    verify_ms = [float(r["latency_ms"]) for r in rows if r["event"] == "AUTH_VERIFY"]
    assert verify_ms and min(verify_ms) == pytest.approx((ct["merkle_check"] + ct["verify"]) * 1000, abs=1e-3)   # CSV keeps 3 decimals
    auth_ms = [float(r["latency_ms"]) for r in rows if r["event"] == "AUTH_OK"]
    floor = (ct["verify_sig"] + ct["prove"] + ct["merkle_check"] + ct["verify"] + ct["sign"]) * 1000
    assert min(auth_ms) > floor


def test_ledger_contract_reference(capsys):
    """The built-in ledger passes the conformance check Person 2's gateway must pass."""
    from network.ledger_check import main
    assert main(["builtin"]) == 0
