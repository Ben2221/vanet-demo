"""Checks for the separate three-vehicle, two-RSU visibility demo."""

from __future__ import annotations

import csv
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mobility.fcd_to_ns2 import read_fcd  # noqa: E402
from mobility.place_rsus import read_csv  # noqa: E402
from mobility.sumo_env import binary  # noqa: E402
from network.visibility_demo import DURATION, RSU_POSITIONS, main  # noqa: E402


@pytest.fixture(scope="module")
def demo_run(tmp_path_factory):
    try:
        binary("sumo")
        binary("netconvert")
    except RuntimeError as exc:
        pytest.skip(str(exc))
    out = tmp_path_factory.mktemp("visibility_3v2r")
    summary = main(["--backend", "lite", "--out", str(out)])
    return out, summary


def test_exact_topology_and_vehicle_visibility(demo_run):
    out, summary = demo_run
    assert summary["vehicles"] == 3
    assert summary["rsus"] == 2
    tracks = read_fcd(out / "mobility/fcd.xml")
    assert set(tracks) == {"veh0", "veh1", "veh2"}
    for track in tracks.values():
        assert track.samples[0][0] == 0
        assert track.samples[-1][0] == DURATION - 1
        assert track.samples[-1][1] > track.samples[0][1]
    rsus = read_csv(out / "mobility/rsus.csv")
    assert [r["node_id"] for r in rsus] == [3, 4]
    assert [(r["x"], r["y"]) for r in rsus] == RSU_POSITIONS


def test_authentication_handover_and_outputs(demo_run):
    out, summary = demo_run
    assert summary["broadcast_pdr"] > 0.9
    with (out / "metrics.csv").open() as f:
        rows = list(csv.DictReader(f))
    for event in ("AUTH_OK", "HANDOVER_OK"):
        assert {r["node"] for r in rows if r["event"] == event} == {"veh0", "veh1", "veh2"}
    config = json.loads((out / "config.json").read_text())
    assert config["trace_threshold"] == 2
    assert config["backend"] == "lite"
    assert (out / "summary.json").is_file()
    assert (out / "attackers.csv").is_file()


def test_sumo_view_has_two_labelled_rsus_and_ranges(demo_run):
    out, _ = demo_run
    additional = ET.parse(out / "mobility/rsus.add.xml").getroot()
    assert [p.get("id") for p in additional.findall("poi")] == ["rsu0", "rsu1"]
    assert len(additional.findall("poly")) == 2
    view = ET.parse(out / "mobility/gui-settings.xml").getroot()
    assert view.find("scheme/vehicles").get("vehicleName_show") == "true"
    assert view.find("scheme/pois").get("poiName_show") == "true"
