"""Two-node 802.11p range test (plan step 2).

One car broadcasts 100 BSM-sized packets to one RSU at each distance. Messages
should arrive at 100 m and 300 m and fail at 450 m (range about 400 m).

  python network/range_test.py                  # 50 m .. 500 m
  python network/range_test.py --backend ns3 --distances 100 300 450
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from network.radio import RadioConfig  # noqa: E402
from network.static_harness import GROUP_SPACING, Broadcaster, make_backend, run  # noqa: E402


def range_test(distances: list[float], backend: str = "auto", packets: int = 100, size: int = 200,
               radio: RadioConfig | None = None, seed: int = 1) -> list[dict]:
    radio = radio or RadioConfig()
    positions: list[tuple[float, float]] = []
    for k, d in enumerate(distances):
        x0 = k * GROUP_SPACING
        positions += [(x0, 0.0), (x0 + d, 0.0)]          # car = 2k, RSU = 2k+1
    duration = packets * 0.1 + 2
    be = make_backend(backend, positions, radio, duration, seed)
    bcs = [Broadcaster(2 * k, 10.0, size, 0.5 + 0.01 * k, packets) for k in range(len(distances))]
    res = run(be, bcs, duration, seed)
    be.finish(".") if be.name == "ns3" else None
    rows = []
    for k, d in enumerate(distances):
        uids = [u for u, s in res.sent.items() if s == 2 * k]
        got = sum(1 for u in uids if (2 * k + 1) in res.received.get(u, ()))
        rows.append({"distance_m": d, "sent": len(uids), "received": got,
                     "pdr": got / len(uids) if uids else 0.0,
                     "rx_power_dbm": round(radio.rx_power_dbm(d), 2), "backend": be.name})
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--distances", type=float, nargs="+",
                    default=[50, 100, 150, 200, 250, 300, 350, 375, 400, 425, 450, 500])
    ap.add_argument("--backend", choices=["auto", "ns3", "lite"], default="auto")
    ap.add_argument("--packets", type=int, default=100)
    ap.add_argument("--tx-power", type=float, default=20.0)
    ap.add_argument("--range", type=float, default=400.0)
    ap.add_argument("--fading", choices=["none", "nakagami"], default="none")
    ap.add_argument("--out", type=Path, default=ROOT / "experiments" / "results" / "range_test.csv")
    a = ap.parse_args()
    radio = RadioConfig(tx_power_dbm=a.tx_power, target_range_m=a.range, fading=a.fading)
    rows = range_test(a.distances, a.backend, a.packets, radio=radio)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    with a.out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"{'distance':>9} {'rx dBm':>8} {'PDR':>6}")
    for r in rows:
        print(f"{r['distance_m']:>8.0f}m {r['rx_power_dbm']:>8.1f} {r['pdr']:>6.2f}")
    ok = next((r for r in rows if r["distance_m"] == 300), None)
    bad = next((r for r in rows if r["distance_m"] == 450), None)
    if ok and bad:
        print("PASS" if ok["pdr"] > 0.9 and bad["pdr"] < 0.1 else "FAIL",
              "(arrive at 300 m, fail at 450 m)")
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
