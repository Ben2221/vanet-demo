"""Scenarios cut from a real city (mobility/real_scenario.py) and the FCD conversion they use."""
from pathlib import Path

import pytest

from mobility import fcd_to_ns2
from mobility.real_scenario import PRESETS, _rsu_bounds


def test_presets_and_rsu_box():
    lust = PRESETS["lust"]
    assert set(lust["windows"]) == {"low", "mid", "peak"} and lust["windows"]["peak"] == 8 * 3600
    x0, y0, x1, y1 = _rsu_bounds(lust, 450.0)
    assert (x1 - x0, y1 - y0) == (900.0, 900.0)                 # 3 x 3 RSUs at 450 m inside 1.35 km


def test_fcd_window_offset_and_parking(tmp_path: Path):
    fcd = tmp_path / "fcd.xml"
    steps = []
    for k in range(6):                                          # car A inside at 1000.0-1000.2 and 1000.5
        t = 1000 + k / 10
        veh = f'<vehicle id="A" x="{10 + k}" y="5" speed="10" angle="90"/>' if k in (0, 1, 2, 5) else ""
        steps.append(f'<timestep time="{t:.1f}">{veh}</timestep>')
    fcd.write_text("<fcd-export>" + "".join(steps) + "</fcd-export>")
    n = fcd_to_ns2.convert(fcd, tmp_path, step=0.1, time_offset=1000.0)
    assert n == 1
    trace = (tmp_path / "trace.ns2").read_text()
    assert '$ns_ at 0.00 "$node_(0) set X_ 10.00"' in trace     # times start at 0
    px, _ = fcd_to_ns2.park_position(0)
    assert f'$ns_ at 0.30 "$node_(0) set X_ {px:.2f}"' in trace  # parked while out of the box
    assert '$ns_ at 0.50 "$node_(0) set X_ 15.00"' in trace     # back at 0.5
