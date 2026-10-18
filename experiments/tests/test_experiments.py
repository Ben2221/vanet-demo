"""Tests for Person 4's experiment tooling. Run: pytest experiments/tests"""

import csv
import json
from pathlib import Path

import pytest

from experiments import op_counts, plots, run
from experiments.collect import collect_run
from experiments.stats import mean_ci


def test_mean_ci_three_seeds():
    m, ci, n = mean_ci([10.0, 12.0, 14.0])
    assert m == 12.0 and n == 3
    assert ci == pytest.approx(4.303 * 2.0 / 3 ** 0.5, rel=1e-3)      # t(0.975, df=2) * sd / sqrt(n)


def test_mean_ci_skips_missing_and_handles_one_value():
    assert mean_ci([None, 5.0, float("nan")]) == (5.0, 0.0, 1)
    assert mean_ci([]) == (None, None, 0)


def test_grid_expansion_is_the_full_product():
    cfg = {"seeds": [1, 2, 3], "fixed": {"duration": 60}, "grid": {"vehicles": [50, 100], "attacker_ratio": [0, 0.1]},
           "variants": [{"protocol": "a"}, {"protocol": "b"}]}
    runs = run.expand(cfg)
    assert len(runs) == 2 * 2 * 2 * 3
    assert all(r["duration"] == 60 and r["seed"] in (1, 2, 3) for r in runs)
    assert len({run.run_id(r) for r in runs}) == len(runs)


def test_to_args():
    args = run.to_args({"vehicles": 100, "rsu_spacing": 450, "congestion_control": True, "netanim": False, "x": None})
    assert args == ["--vehicles", "100", "--rsu-spacing", "450", "--congestion-control"]


def _fake_run(d: Path, auth=(1.0, 3.0), reported=("aa", "bb")):
    d.mkdir(parents=True)
    rows = [["sim_time", "node", "event", "bytes", "latency_ms", "result"]]
    rows += [[1.0, "veh1", "AUTH_OK", 100, auth[0], "rsu0"], [2.0, "veh2", "AUTH_OK", 100, auth[1], "rsu0"],
             [3.0, "veh1", "HANDOVER_OK", 50, 0.5, "rsu1"], [1.5, "rsu0", "LEDGER_SUBMIT", 0, 500, "tx"],
             [20.0, "veh3", "PID_ASSIGN", 0, "", "aa"], [20.0, "veh4", "PID_ASSIGN", 0, "", "bb"],
             [40.0, "rsu0", "REPORT", 0, "", reported[0]], [41.0, "rsu1", "REPORT", 0, "", reported[1]],
             [41.5, "rsu1", "REVOKED_VISIBLE", 0, "", "aa"]]
    with (d / "metrics.csv").open("w", newline="") as f:
        csv.writer(f).writerows(rows)
    (d / "summary.json").write_text(json.dumps({
        "broadcast_pdr": 0.95, "cbr_rsu_mean": 0.1, "delay_ms": {"BSM": {"mean": 0.4, "p95": 0.6}},
        "sent_by_type": {"BSM": 10}, "bytes_by_type": {"BSM": 1410}, "wall_time_s": 1.0}))
    (d / "attackers.csv").write_text("node_id,name,attack,start\n3,veh3,random_pos,30.0\n")


def test_collect_run(tmp_path):
    _fake_run(tmp_path / "r")
    r = collect_run(tmp_path / "r")
    assert r["auth_ms_mean"] == 2.0 and r["auth_n"] == 2
    assert r["handover_ms_mean"] == 0.5 and r["ledger_commit_ms_median"] == 500
    assert r["pdr"] == 0.95 and r["security_bytes_per_bsm"] == pytest.approx(141 - 45)
    assert r["attackers"] == 1 and r["attackers_reported"] == 1 and r["detection_rate"] == 1.0
    assert r["honest_reported"] == 1                       # veh4 is not an attacker but pseudonym bb was reported
    assert r["first_report_delay_s_mean"] == pytest.approx(10.0)
    assert r["report_to_revocation_s_mean"] == pytest.approx(1.5)
    assert r["pids_unresolved"] == 0


def test_collect_says_when_pseudonyms_cannot_be_resolved(tmp_path):
    _fake_run(tmp_path / "r", reported=("zz", "yy"))
    r = collect_run(tmp_path / "r")
    assert r["pids_unresolved"] == 2 and r["attackers_reported"] == 0


def test_tables_and_plots(tmp_path, monkeypatch):
    monkeypatch.setattr(run, "RESULTS", tmp_path)
    cfg = {"name": "t", "seeds": [1, 2, 3], "grid": {"vehicles": [30, 60]}, "fixed": {"duration": 60}}
    rows = []
    for v in (30, 60):
        for s in (1, 2, 3):
            d = tmp_path / "t" / "runs" / f"v{v}s{s}"
            _fake_run(d, auth=(v / 10 + s * 0.1, v / 10 + s * 0.2))
            rows.append({"vehicles": v, "seed": s, "duration": 60, **collect_run(d), "run": d.name})
    runs_csv, agg_csv = run.write_tables(rows, cfg)
    agg = list(csv.DictReader(agg_csv.open()))
    assert len(agg) == 2 and agg[0]["n_seeds"] == "3"
    assert float(agg[0]["auth_ms_mean_ci95"]) > 0
    made = plots.make_all(tmp_path / "t", cfg)
    assert (tmp_path / "t" / "plots" / "auth_latency.png").exists() and made


def test_baselines_expose_the_protocol_hooks():
    from experiments.baselines import central_auth, ecdsa_pki
    for mod in (ecdsa_pki, central_auth):
        for hook in ("setup", "message_type", "create_vehicle", "create_rsu"):
            assert callable(getattr(mod, hook))


def test_op_counts_table():
    rows = op_counts.schemes()
    ours, ecdsa, central = rows
    assert ours["handover_bytes"] < ecdsa["handover_bytes"]        # shared ledger state: smaller handover
    assert central["backbone_round_trips"] == 1 and ours["backbone_round_trips"] == 0
    assert "| scheme |" in op_counts.to_markdown(rows)
