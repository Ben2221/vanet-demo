"""BSM delivery ratio against the number of vehicles in range (plan step 4).

For each density N, N vehicles stand at random points within --radius of an
RSU and all beacon at 10 Hz. Every case is an isolated group in one run.
Reports, per N: broadcast PDR among vehicle pairs within --pdr-range, PDR at
the RSU, mean/95th-percentile delay and the RSU's channel busy ratio.

  python network/density_test.py --counts 10 20 40 80 120 160
"""

from __future__ import annotations

import argparse
import csv
import math
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from network.radio import RadioConfig  # noqa: E402
from network.static_harness import GROUP_SPACING, Broadcaster, make_backend, run  # noqa: E402


def density_test(counts: list[int], backend: str = "auto", radius: float = 150.0, pdr_range: float = 300.0,
                 seconds: float = 10.0, rate: float = 10.0, size: int = 200, seed: int = 1,
                 radio: RadioConfig | None = None) -> list[dict]:
    radio = radio or RadioConfig()
    rng = random.Random(seed)
    positions: list[tuple[float, float]] = []
    groups = []                                # (rsu node, [vehicle nodes])
    for k, n in enumerate(counts):
        cx = k * GROUP_SPACING
        rsu = len(positions)
        positions.append((cx, 0.0))
        vs = []
        for _ in range(n):
            r = radius * math.sqrt(rng.random())
            a = rng.uniform(0, 2 * math.pi)
            vs.append(len(positions))
            positions.append((cx + r * math.cos(a), r * math.sin(a)))
        groups.append((rsu, vs))
    duration = seconds + 2
    be = make_backend(backend, positions, radio, duration, seed)
    bcs = [Broadcaster(v, rate, size, rng.uniform(0.5, 0.6), int(seconds * rate))
           for _, vs in groups for v in vs]
    res = run(be, bcs, duration, seed)
    busy = {rsu: be.busy_time(rsu) for rsu, _ in groups}
    name = be.name
    if name == "ns3":
        be.finish(".")
    rows = []
    for (rsu, vs), n in zip(groups, counts):
        vset = set(vs)
        exp = got = rsu_exp = rsu_got = 0
        delays = []
        for uid, src in res.sent.items():
            if src not in vset:
                continue
            sx, sy = positions[src]
            rec = res.received.get(uid, set())
            for v in vs:
                if v == src or math.hypot(positions[v][0] - sx, positions[v][1] - sy) > pdr_range:
                    continue
                exp += 1
                if v in rec:
                    got += 1
                    delays.append(res.rx_delay[(uid, v)])
            rsu_exp += 1
            rsu_got += rsu in rec
        delays.sort()
        rows.append({
            "vehicles": n, "pdr": got / exp if exp else None, "pdr_at_rsu": rsu_got / rsu_exp if rsu_exp else None,
            "delay_mean_ms": sum(delays) / len(delays) if delays else None,
            "delay_p95_ms": delays[int(0.95 * (len(delays) - 1))] if delays else None,
            "cbr_rsu": busy[rsu] / duration, "backend": name,
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--counts", type=int, nargs="+", default=[10, 20, 40, 60, 80, 100, 120, 160])
    ap.add_argument("--backend", choices=["auto", "ns3", "lite"], default="auto")
    ap.add_argument("--radius", type=float, default=150.0)
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--rate", type=float, default=10.0)
    ap.add_argument("--size", type=int, default=200, help="BSM bytes (with security ~ 200-300)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", type=Path, default=ROOT / "experiments" / "results" / "density_test.csv")
    ap.add_argument("--plot", action="store_true", help="also save a PNG (needs matplotlib)")
    a = ap.parse_args()
    rows = density_test(a.counts, a.backend, a.radius, seconds=a.seconds, rate=a.rate, size=a.size, seed=a.seed)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    with a.out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"{'vehicles':>8} {'PDR':>6} {'PDR@RSU':>8} {'delay ms':>9} {'p95 ms':>7} {'CBR':>5}")
    for r in rows:
        print(f"{r['vehicles']:>8} {r['pdr']:>6.3f} {r['pdr_at_rsu']:>8.3f} {r['delay_mean_ms']:>9.3f} "
              f"{r['delay_p95_ms']:>7.3f} {r['cbr_rsu']:>5.2f}")
    if a.plot:
        from network.plots import plot_density
        png = plot_density(a.out)
        print(f"plot: {png}")
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
