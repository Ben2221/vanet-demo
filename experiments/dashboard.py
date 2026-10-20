"""The v3 evaluation as one self-contained HTML page (Person 4).

    python experiments/dashboard.py          # -> experiments/results/v3_dashboard.html

Reads whatever exists of: experiments/results/{compare_v3, compare_lust, ablation_v3, trust_v3,
sensitivity_obu, sensitivity_attack, sensitivity_attackers, mixzone_tradeoff}/aggregate.csv
(+ runs.csv and per-run protocol_stats.json for latency distributions),
detection/results/veremi_benchmark.json, experiments/results/ledger_consensus/summary.json and
one LuST scenario for the map. Every chart is inline SVG drawn from those numbers.
"""
from __future__ import annotations

import csv
import html
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "experiments" / "results"
OUT = RES / "v3_dashboard.html"

SCHEMES = ["ECDSA-PKI", "Central-TA", "Phase-I", "v2", "v2-mac", "v3-fast", "v3-private"]
CVAR = {"ECDSA-PKI": "--c1", "Central-TA": "--c2", "Phase-I": "--c3", "v2": "--c4", "v2-mac": "--c5",
        "v3-fast": "--c6", "v3-private": "--c7"}
FOCUS = {"v3-fast", "v3-private"}

# (title, column, unit, better, note)
METRICS = [
    ("Getting a ticket", "ticket_ms_mean", "ms", "low", "full login or renewal, mean"),
    ("Neighbour acceptance latency", "v2v_accept_ms_mean", "ms", "low", "BSM sent → accepted by a vehicle"),
    ("RSU acceptance latency", "rsu_accept_ms_mean", "ms", "low", "BSM sent → accepted by an RSU, incl. CPU queue"),
    ("Safety traffic", "safety_bytes_per_vehicle_s", "B/s", "low", "BSM + key bytes per vehicle-second"),
    ("Channel busy ratio", "cbr_rsu_mean", "ratio", "low", "measured by ns-3 at the RSUs"),
    ("Delivery ratio", "pdr", "ratio", "high", "broadcasts received within 300 m"),
    ("Neighbour BSMs verifiable", "v2v_verified_ratio", "share", "high", "within 100 m, revoked senders excluded"),
    ("Revoked senders accepted", "v2v_revoked_accepted_ratio", "share", "low", "by vehicles, after revocation"),
    ("Handovers on the radio", "handover_n", "per run", "low", "HANDOVER_REQ exchanges"),
    ("Vehicle CPU load", "obu_cpu_util_mean", "share", "low", "OBU assumed 5× slower than this PC"),
    ("Pseudonym changes tracked", "tracking_success", "share", "low", "global eavesdropper, dead-reckoning linker"),
    ("Attack → first report", "first_report_delay_s_mean", "s", "low", "attackers reported by K RSUs"),
    ("Attackers caught", "detection_rate", "share", "high", ""),
    ("Honest vehicles revoked", "honest_revoked", "vehicles", "low", ""),
]


# ------------------------------------------------------------------ data
def _f(x):
    try:
        v = float(x)
        return v if math.isfinite(v) else None
    except (TypeError, ValueError):
        return None


def _read(name: str, file: str = "aggregate.csv") -> list[dict]:
    f = RES / name / file
    if not f.exists():
        return []
    with f.open(newline="") as fh:
        rows = list(csv.DictReader(fh))
    cfg = ROOT / "experiments" / "configs" / f"{name}.json"
    if cfg.exists():
        order = [v.get("label") for v in json.loads(cfg.read_text()).get("variants", [])]
        rows.sort(key=lambda r: (order.index(r.get("label")) if r.get("label") in order else 99,
                                 str(r.get("real", "")), _f(r.get("vehicles")) or 0))
    return rows


def _fmt(v, digits=None):
    if v is None:
        return "–"
    a = abs(v)
    if digits is not None:
        return f"{v:.{digits}f}"
    return (f"{v:,.0f}" if a >= 100 else f"{v:.1f}" if a >= 10 else f"{v:.2f}" if a >= 0.1
            else f"{v:.3f}" if a >= 0.001 else ("0" if v == 0 else f"{v:.1e}"))


def esc(s) -> str:
    return html.escape(str(s))


# ---------------------------------------------------------------- charts
def _axis_ticks(lo, hi, n=4):
    if hi <= lo:
        hi = lo + 1
    raw = (hi - lo) / n
    mag = 10 ** math.floor(math.log10(raw))
    step = min((m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw), default=raw)
    start = math.floor(lo / step) * step
    ticks, t = [], start
    while t <= hi + step * 0.5:
        ticks.append(round(t, 10))
        t += step
    return ticks


def line_chart(rows, col, xkey, xlabels=None, log=False) -> str:
    """One line per scheme over xkey; whiskers = 95 % CI."""
    pts: dict = {}
    for r in rows:
        v = _f(r.get(col))
        if v is None:
            continue
        pts.setdefault(r.get("label"), []).append((r.get(xkey), v, _f(r.get(col + "_ci95")) or 0.0))
    if not pts:
        return '<p class="nodata">No data for this metric.</p>'
    xs = xlabels or sorted({x for s in pts.values() for x, _, _ in s}, key=lambda x: _f(x) or 0)
    vals = [v for s in pts.values() for _, v, _ in s]
    if log and any(v > 0 for v in vals):
        lo_v = max(min(v for v in vals if v > 0), 1e-4)
        lo, hi = math.log10(lo_v) - 0.15, math.log10(max(vals) * 1.6)
        tr = lambda v: math.log10(max(v, lo_v))  # noqa: E731
        ticks = [10 ** k for k in range(math.floor(lo), math.ceil(hi) + 1)]
        tick_pos = lambda t: math.log10(t)  # noqa: E731
    else:
        log = False
        hi = max(v + c for s in pts.values() for _, v, c in s) * 1.08 or 1
        lo = min(0.0, min(v - c for s in pts.values() for _, v, c in s))
        tr = lambda v: v  # noqa: E731
        ticks = _axis_ticks(lo, hi)
        hi = max(hi, ticks[-1])
        tick_pos = lambda t: t  # noqa: E731
    W, H, L, R, T, B = 330, 196, 46, 10, 10, 28
    sx = lambda x: L + (W - L - R) * ((xs.index(x) + 0.5) / len(xs))  # noqa: E731
    sy = lambda v: T + (H - T - B) * (1 - (tr(v) - lo) / ((hi - lo) or 1))  # noqa: E731
    o = [f'<svg viewBox="0 0 {W} {H}" class="chart" role="img">']
    for t in ticks:
        if not (lo - 1e-9 <= tick_pos(t) <= hi + 1e-9):
            continue
        y = sy(t)
        o.append(f'<line x1="{L}" x2="{W - R}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                 f'<text x="{L - 6}" y="{y + 3.5:.1f}" class="tick" text-anchor="end">{_fmt(t)}</text>')
    for x in xs:
        o.append(f'<text x="{sx(x):.1f}" y="{H - 9}" class="tick" text-anchor="middle">'
                 f'{esc(str(x).replace("lust:", ""))}</text>')
    for name in SCHEMES + sorted(set(pts) - set(SCHEMES)):
        s = sorted(pts.get(name, []), key=lambda p: xs.index(p[0]) if p[0] in xs else 0)
        if not s:
            continue
        c = f"var({CVAR.get(name, '--c3')})"
        w = 2.6 if name in FOCUS else 1.5
        d = " ".join(f"{'M' if i == 0 else 'L'}{sx(x):.1f},{sy(v):.1f}" for i, (x, v, _) in enumerate(s))
        o.append(f'<path d="{d}" fill="none" stroke="{c}" stroke-width="{w}"/>')
        for x, v, ci in s:
            if ci and not log:
                o.append(f'<line x1="{sx(x):.1f}" x2="{sx(x):.1f}" y1="{sy(v - ci):.1f}" y2="{sy(v + ci):.1f}" '
                         f'stroke="{c}" stroke-width="1"/>')
            o.append(f'<circle cx="{sx(x):.1f}" cy="{sy(v):.1f}" r="{3.1 if name in FOCUS else 2.3}" fill="{c}">'
                     f'<title>{esc(name)} · {esc(x)}: {_fmt(v)} ± {_fmt(ci)}</title></circle>')
    o.append("</svg>")
    return "".join(o)


def bar_chart(items, highlight=(), unit="") -> str:
    """items = [(label, value, ci)] horizontal bars."""
    items = [i for i in items if i[1] is not None]
    if not items:
        return '<p class="nodata">No data.</p>'
    hi = max(v + (c or 0) for _, v, c in items) * 1.12 or 1
    lab_w, W, rh = 168, 440, 21
    H = rh * len(items) + 6
    o = [f'<svg viewBox="0 0 {W} {H}" class="bars" role="img">']
    for i, (name, v, ci) in enumerate(items):
        y = 3 + i * rh
        w = (W - lab_w - 70) * max(v, 0) / hi
        cls = "bar hi" if any(name.startswith(h) for h in highlight) else "bar"
        o.append(f'<text x="{lab_w - 8}" y="{y + 13.5}" class="tick lab" text-anchor="end">{esc(name)}</text>'
                 f'<rect x="{lab_w}" y="{y + 3}" width="{max(w, 1.5):.1f}" height="{rh - 8}" rx="2" class="{cls}"/>'
                 f'<text x="{lab_w + w + 6:.1f}" y="{y + 13.5}" class="val">{_fmt(v)}{" ± " + _fmt(ci) if ci else ""}'
                 f'{esc(unit)}</text>')
    o.append("</svg>")
    return "".join(o)


def grouped_bars(cats, series) -> str:
    """cats = labels; series = [(name, cssvar, [values in 0..1])] vertical grouped bars."""
    W, H, L, B, T = max(460, 34 * len(cats) + 60), 236, 36, 98, 8
    gw = (W - L - 8) / len(cats)
    bw = gw * 0.8 / len(series)
    sy = lambda v: T + (H - T - B) * (1 - v)  # noqa: E731
    o = [f'<svg viewBox="0 0 {W} {H}" class="chart wide" role="img">']
    for t in (0, 0.25, 0.5, 0.75, 1.0):
        o.append(f'<line x1="{L}" x2="{W - 8}" y1="{sy(t):.1f}" y2="{sy(t):.1f}" class="grid"/>'
                 f'<text x="{L - 5}" y="{sy(t) + 3.5:.1f}" class="tick" text-anchor="end">{t:g}</text>')
    for i, c in enumerate(cats):
        x0 = L + i * gw + gw * 0.1
        for j, (name, var, vals) in enumerate(series):
            v = vals[i]
            if v is None:
                continue
            o.append(f'<rect x="{x0 + j * bw:.1f}" y="{sy(v):.1f}" width="{max(bw - 1, 1):.1f}" '
                     f'height="{sy(0) - sy(v):.1f}" fill="var({var})"><title>{esc(c)} · {esc(name)}: {v:.3f}</title></rect>')
        cx = x0 + gw * 0.4
        o.append(f'<text transform="translate({cx:.1f},{H - B + 10}) rotate(55)" class="tick">{esc(c)}</text>')
    o.append("</svg>")
    return "".join(o)


def xy_chart(series, xlabel, log_x=False, xmax=None, ymax=1.0) -> str:
    """series = [(name, cssvar, [(x, y)])] lines (CDFs, PR / ROC curves, trade-off)."""
    allx = [x for _, _, p in series for x, _ in p if x is not None]
    if not allx:
        return '<p class="nodata">No data.</p>'
    W, H, L, R, T, B = 330, 210, 40, 10, 10, 36
    if log_x:
        lo = math.log10(max(min(x for x in allx if x > 0), 1e-3))
        hi = math.log10(xmax or max(allx))
        if hi <= lo:
            hi = lo + 1
        tx = lambda x: (math.log10(max(x, 10 ** lo)) - lo) / (hi - lo)  # noqa: E731
        ticks = [10 ** k for k in range(math.ceil(lo), math.floor(hi) + 1)]
        tpos = lambda t: math.log10(t)  # noqa: E731
    else:
        lo, hi = 0.0, xmax or max(allx) or 1
        tx = lambda x: (x - lo) / (hi - lo)  # noqa: E731
        ticks = _axis_ticks(lo, hi)
        tpos = lambda t: t  # noqa: E731
    sx = lambda x: L + (W - L - R) * min(1, max(0, tx(x)))  # noqa: E731
    sy = lambda y: T + (H - T - B) * (1 - y / ymax)  # noqa: E731
    o = [f'<svg viewBox="0 0 {W} {H}" class="chart" role="img">']
    for t in (0, 0.25, 0.5, 0.75, 1.0):
        o.append(f'<line x1="{L}" x2="{W - R}" y1="{sy(t * ymax):.1f}" y2="{sy(t * ymax):.1f}" class="grid"/>'
                 f'<text x="{L - 5}" y="{sy(t * ymax) + 3.5:.1f}" class="tick" text-anchor="end">{t * ymax:g}</text>')
    for t in ticks:
        if lo - 1e-9 <= tpos(t) <= hi + 1e-9:
            o.append(f'<text x="{sx(t):.1f}" y="{H - 20}" class="tick" text-anchor="middle">{_fmt(t)}</text>')
    o.append(f'<text x="{(L + W - R) / 2:.0f}" y="{H - 5}" class="tick" text-anchor="middle">{esc(xlabel)}</text>')
    for name, var, p in series:
        p = [(x, y) for x, y in p if x is not None and y is not None]
        if not p:
            continue
        d = " ".join(f"{'M' if i == 0 else 'L'}{sx(x):.1f},{sy(y):.1f}" for i, (x, y) in enumerate(p))
        w = 2.4 if name in FOCUS or "window" in name else 1.5
        o.append(f'<path d="{d}" fill="none" stroke="var({var})" stroke-width="{w}"><title>{esc(name)}</title></path>')
        if len(p) <= 8:
            o += [f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="3.5" fill="var({var})"/>' for x, y in p]
    o.append("</svg>")
    return "".join(o)


def legend(names) -> str:
    return '<div class="legend">' + "".join(
        f'<span><i style="background:var({CVAR.get(n, "--c3")})"></i>{esc(n)}</span>' for n in names) + "</div>"


def legend_custom(items) -> str:
    return '<div class="legend small">' + "".join(
        f'<span><i style="background:var({v})"></i>{esc(n)}</span>' for n, v in items) + "</div>"


def table(rows, cols) -> str:
    """Comparison table: rows = aggregate rows for one setting."""
    use = [c for c in cols if any(_f(r.get(c[1])) is not None for r in rows)]
    head = "".join(f'<th title="{esc(n)}">{esc(t)}<span class="dir">{"↓" if b == "low" else "↑"}</span></th>'
                   for t, _, _, b, n in use)
    body = []
    for r in rows:
        name = r.get("label", "")
        cells = []
        for _, c, _, better, _ in use:
            vals = [_f(x.get(c)) for x in rows if _f(x.get(c)) is not None]
            v = _f(r.get(c))
            best = (v is not None and vals and len(set(vals)) > 1
                    and v == (min(vals) if better == "low" else max(vals)))
            ci = _f(r.get(c + "_ci95"))
            cells.append(f'<td class="{"best" if best else ""}">{_fmt(v)}'
                         f'{f"<small> ±{_fmt(ci)}</small>" if ci else ""}</td>')
        body.append(f'<tr class="{"focus" if name in FOCUS else ""}"><th scope="row">'
                    f'<i style="background:var({CVAR.get(name, "--c3")})"></i>{esc(name)}</th>{"".join(cells)}</tr>')
    return (f'<div class="tablewrap"><table><thead><tr><th>scheme</th>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


# --------------------------------------------------------- special figures
def latency_cdfs(sweep: str, key: str, setting: str, block: str) -> str:
    """Latency quantiles averaged over seeds per scheme, from each run's protocol_stats.json."""
    acc: dict = {}
    for r in _read(sweep, "runs.csv"):
        if str(r.get(key)) != str(setting):
            continue
        f = RES / sweep / "runs" / r["run"] / "protocol_stats.json"
        if not f.exists():
            continue
        q = json.loads(f.read_text()).get(block, {}).get("accept_latency_ms", {}).get("quantiles")
        if q:
            acc.setdefault(r["label"], []).append(q)
    series = []
    for name in SCHEMES:
        qs = acc.get(name)
        if qs:
            mq = [sum(q[i] for q in qs) / len(qs) for i in range(len(qs[0]))]
            series.append((name, CVAR[name], [(x, i / (len(mq) - 1)) for i, x in enumerate(mq)]))
    if not series:
        return '<p class="nodata">No latency distributions yet.</p>'
    return xy_chart(series, "latency (ms, log scale)", log_x=True)


def lust_map() -> str:
    """Roads in the LuST box, RSUs with their 300 m range, 60 vehicle tracks at 08:00."""
    d = ROOT / "mobility" / "out" / "lust_peak_d120_s1_st0.1"
    net = ROOT / "mobility" / "real" / "LuSTScenario" / "scenario" / "lust.net.xml"
    if not (d / "scenario.json").exists() or not net.exists():
        return '<p class="nodata">LuST scenario not built.</p>'
    from defusedxml.ElementTree import iterparse
    meta = json.loads((d / "scenario.json").read_text())
    x0, y0, x1, y1 = meta["box"]
    pad = 80
    S = 520 / (x1 - x0 + 2 * pad)
    px = lambda x: (x - x0 + pad) * S  # noqa: E731
    py = lambda y: (y1 - y + pad) * S  # noqa: E731
    roads = []
    for _, el in iterparse(net, events=("end",)):
        if el.tag == "lane" and not el.get("id", "").startswith(":") and el.get("index") == "0":
            pts = [tuple(map(float, p.split(","))) for p in el.get("shape", "").split()]
            if any(x0 - pad <= x <= x1 + pad and y0 - pad <= y <= y1 + pad for x, y in pts):
                roads.append("M" + " L".join(f"{px(x):.1f},{py(y):.1f}" for x, y in pts))
        if el.tag in ("edge", "junction"):
            el.clear()
    tracks: dict = {}
    for _, el in iterparse(d / "fcd.xml", events=("end",)):
        if el.tag == "timestep":
            for v in el.findall("vehicle"):
                vid = v.get("id")
                if vid in tracks or len(tracks) < 60:
                    tracks.setdefault(vid, []).append((float(v.get("x")), float(v.get("y"))))
            el.clear()
    with (d / "rsus.csv").open() as fh:
        rsus = [(float(r["x"]), float(r["y"]), float(r["range_m"])) for r in csv.DictReader(fh)]
    o = ['<svg viewBox="0 0 520 520" class="map" role="img" aria-label="Map of the LuST box">',
         f'<rect x="{px(x0):.1f}" y="{py(y1):.1f}" width="{(x1 - x0) * S:.1f}" height="{(y1 - y0) * S:.1f}" class="box"/>']
    o += [f'<path d="{r}" class="road"/>' for r in roads]
    for t in tracks.values():
        if len(t) > 3:
            o.append('<path d="M' + " L".join(f"{px(x):.1f},{py(y):.1f}" for x, y in t[::5]) + '" class="track"/>')
    for i, (x, y, rng) in enumerate(rsus):
        o.append(f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="{rng * S:.1f}" class="cov"/>'
                 f'<circle cx="{px(x):.1f}" cy="{py(y):.1f}" r="5" class="rsu"><title>rsu{i}</title></circle>')
    o.append(f'<text x="{px(x0) + 4:.1f}" y="{py(y0) - 6:.1f}" class="tick">box 1.35 km</text></svg>')
    return "".join(o)


def attack_timeline() -> str:
    """Per attacker: attack start, first flag, report, local block, revocation (one LuST run)."""
    runs = _read("compare_lust", "runs.csv")
    pick = next((r for r in runs if r.get("label") == "v3-fast" and r.get("real") == "lust:mid"), None)
    if pick is None:
        return '<p class="nodata">LuST runs not finished yet.</p>'
    d = RES / "compare_lust" / "runs" / pick["run"]
    with (d / "attackers.csv").open() as fh:
        attackers = {r["name"]: float(r["start"]) for r in csv.DictReader(fh)}
    owner: dict = {}
    events: dict = {}
    with (d / "metrics.csv").open() as fh:
        for r in csv.DictReader(fh):
            ev, res = r["event"], r["result"].strip()
            if ev == "PID_ASSIGN":
                owner[res] = r["node"]
            elif ev == "PSEUDONYM_CHANGE" and "->" in res:
                owner[res.split("->")[-1].strip()] = r["node"]
            elif ev in ("DETECT_FLAG", "REPORT", "QUARANTINE_BLOCK", "REVOKED_VISIBLE"):
                v = owner.get(res)
                if v in attackers:
                    events.setdefault(v, {}).setdefault(ev, float(r["sim_time"]))
    rows = sorted(attackers.items(), key=lambda kv: events.get(kv[0], {}).get("REPORT", 1e9))[:16]
    if not rows:
        return '<p class="nodata">No attackers in this run.</p>'
    T0 = min(attackers.values()) - 2
    T1 = max(max((t for e in events.values() for t in e.values()), default=40.0), T0 + 10)
    W, rh, L = 560, 18, 72
    H = rh * len(rows) + 30
    sx = lambda t: L + (W - L - 10) * (t - T0) / (T1 - T0)  # noqa: E731
    marks = [("DETECT_FLAG", "--c4", "first flag"), ("REPORT", "--c6", "reported by K RSUs"),
             ("QUARANTINE_BLOCK", "--c5", "blocked locally"), ("REVOKED_VISIBLE", "--c7", "revoked on the ledger")]
    o = [f'<svg viewBox="0 0 {W} {H}" class="chart wide" role="img">']
    for t in _axis_ticks(T0, T1, 5):
        if T0 <= t <= T1:
            o.append(f'<line x1="{sx(t):.1f}" x2="{sx(t):.1f}" y1="4" y2="{H - 22}" class="grid"/>'
                     f'<text x="{sx(t):.1f}" y="{H - 8}" class="tick" text-anchor="middle">{t:g} s</text>')
    for i, (veh, start) in enumerate(rows):
        y = 6 + i * rh
        e = events.get(veh, {})
        end = max([start] + list(e.values()))
        o.append(f'<text x="{L - 6}" y="{y + 9}" class="tick" text-anchor="end">{esc(veh)}</text>'
                 f'<line x1="{sx(start):.1f}" x2="{sx(end):.1f}" y1="{y + 6}" y2="{y + 6}" class="lane"/>'
                 f'<rect x="{sx(start) - 1:.1f}" y="{y}" width="2.5" height="12" class="attack">'
                 f'<title>attack starts {start:g} s</title></rect>')
        for ev, var, label in marks:
            if ev in e:
                o.append(f'<circle cx="{sx(e[ev]):.1f}" cy="{y + 6}" r="4.2" fill="var({var})">'
                         f'<title>{label}: {e[ev]:.2f} s</title></circle>')
    o.append("</svg>")
    leg = "".join(f'<span><i style="background:var({v})"></i>{lab}</span>' for _, v, lab in marks)
    return "".join(o) + f'<div class="legend small"><span><i class="atk"></i>attack starts</span>{leg}</div>'


def tradeoff_scatter(rows) -> str:
    """Privacy (share of pseudonym changes tracked) against neighbour acceptance latency."""
    pts = [(r["label"], _f(r.get("v2v_accept_ms_mean")), _f(r.get("tracking_success")), _f(r.get("ticket_ms_mean")))
           for r in rows if (_f(r.get("v2v_accept_ms_mean")) or 0) > 0 and _f(r.get("tracking_success")) is not None]
    if not pts:
        return '<p class="nodata">No data.</p>'
    W, H, L, B, T, R = 360, 230, 44, 36, 10, 74
    xs = [p[1] for p in pts]
    lo, hi = math.log10(min(xs) * 0.6), math.log10(max(xs) * 1.8)
    ylo = min(0.5, math.floor(min(p[2] for p in pts) * 10) / 10)
    sx = lambda x: L + (W - L - R) * (math.log10(x) - lo) / (hi - lo)  # noqa: E731
    sy = lambda y: T + (H - T - B) * (1 - (y - ylo) / (1.05 - ylo))  # noqa: E731
    o = [f'<svg viewBox="0 0 {W} {H}" class="chart" role="img">']
    t = ylo
    while t <= 1.0001:
        o.append(f'<line x1="{L}" x2="{W - R}" y1="{sy(t):.1f}" y2="{sy(t):.1f}" class="grid"/>'
                 f'<text x="{L - 5}" y="{sy(t) + 3.5:.1f}" class="tick" text-anchor="end">{t:.0%}</text>')
        t += 0.1
    for k in range(math.ceil(lo), math.floor(hi) + 1):
        o.append(f'<text x="{sx(10 ** k):.1f}" y="{H - 20}" class="tick" text-anchor="middle">{_fmt(10 ** k)}</text>')
    o.append(f'<text x="{(L + W - R) / 2:.0f}" y="{H - 5}" class="tick" text-anchor="middle">'
             f'neighbour acceptance (ms, log)</text>')
    for name, x, y, tk in pts:
        o.append(f'<circle cx="{sx(x):.1f}" cy="{sy(y):.1f}" r="{7 if name in FOCUS else 5}" '
                 f'fill="var({CVAR.get(name, "--c3")})"><title>{esc(name)}: {_fmt(x)} ms, {y:.0%} tracked, '
                 f'ticket {_fmt(tk)} ms</title></circle>'
                 f'<text x="{sx(x) + 9:.1f}" y="{sy(y) + 4:.1f}" class="tick lab">{esc(name)}</text>')
    o.append("</svg>")
    return "".join(o)


# ----------------------------------------------------------------- page
def _metric_grid(rows, xkey, xlabels=None) -> str:
    figs = []
    for title, col, unit, better, note in METRICS:
        log = col in ("v2v_accept_ms_mean", "rsu_accept_ms_mean", "ticket_ms_mean")
        figs.append(f'<figure><figcaption><b>{esc(title)}</b> <span class="u">{esc(unit)} '
                    f'{"↓" if better == "low" else "↑"}{" · log" if log else ""}</span><br>'
                    f'<span class="n">{esc(note)}</span></figcaption>{line_chart(rows, col, xkey, xlabels, log=log)}</figure>')
    return '<div class="grid2">' + "".join(figs) + "</div>"


def _significance(sweep: str) -> str:
    md = RES / sweep / "report.md"
    if not md.exists() or "## Significance" not in md.read_text():
        return ""
    part = md.read_text().split("## Significance", 1)[1]
    sig = sum(line.count("**") // 2 for line in part.splitlines() if line.startswith("| v3"))
    return (f'<p class="note">Welch t-tests against Phase-I: {sig} metric × setting pairs differ at p &lt; 0.05 '
            f'(p-values in <code>experiments/results/{sweep}/report.md</code>).</p>')


def section_compare(sweep: str, key: str, labels, lead: str) -> str:
    rows = _read(sweep)
    if not rows:
        return f'<p class="nodata">{esc(sweep)} not run yet.</p>'
    settings = labels or sorted({r[key] for r in rows}, key=lambda x: _f(x) or 0)
    settings = [s for s in settings if any(r.get(key) == s for r in rows)]
    hi, mid = settings[-1], settings[len(settings) // 2]
    nice = lambda s: str(s).replace("lust:", "")  # noqa: E731
    tables = "".join(f'<h3>{esc("LuST window" if key == "real" else key)} = {esc(nice(s))}</h3>'
                     f'{table([r for r in rows if r.get(key) == s], METRICS)}' for s in settings)
    return (f'<p class="lede">{lead}</p>{legend([n for n in SCHEMES if any(r.get("label") == n for r in rows)])}'
            f'{_significance(sweep)}{_metric_grid(rows, key, settings)}'
            f'<div class="grid2 two"><figure><figcaption><b>Neighbour acceptance latency, distribution</b> '
            f'<span class="n">{esc(nice(hi))}, mean of the seeds</span></figcaption>{latency_cdfs(sweep, key, hi, "v2v")}</figure>'
            f'<figure><figcaption><b>RSU acceptance latency, distribution</b> <span class="n">{esc(nice(hi))}</span>'
            f'</figcaption>{latency_cdfs(sweep, key, hi, "rsu_bsm")}</figure>'
            f'<figure><figcaption><b>Privacy against latency</b> <span class="n">{esc(nice(mid))}; lower left is better'
            f'</span></figcaption>{tradeoff_scatter([r for r in rows if r.get(key) == mid])}</figure></div>'
            f'<details><summary>Full tables (mean ± 95 % CI; green = best in column)</summary>{tables}</details>')


def section_ablation() -> str:
    rows = _read("ablation_v3")
    if not rows:
        return '<p class="nodata">Ablation not run yet.</p>'
    cols = [("Getting a ticket (ms)", "ticket_ms_mean"), ("Neighbour acceptance (ms)", "v2v_accept_ms_mean"),
            ("Safety bytes per vehicle-second", "safety_bytes_per_vehicle_s"), ("Neighbour BSMs verifiable", "v2v_verified_ratio"),
            ("Handovers per run", "handover_n"), ("Revoked senders accepted by vehicles", "v2v_revoked_accepted_ratio"),
            ("Attack → first report (s)", "first_report_delay_s_mean"), ("Honest vehicles reported", "honest_reported"),
            ("Pseudonym changes tracked", "tracking_success"), ("Vehicle CPU load", "obu_cpu_util_mean")]
    figs = "".join(f'<figure><figcaption><b>{t}</b></figcaption>'
                   f'{bar_chart([(r["label"], _f(r.get(c)), _f(r.get(c + "_ci95"))) for r in rows], ("v3",))}</figure>'
                   for t, c in cols)
    return ('<p class="lede">100 vehicles on the grid, 3 seeds. Each bar is v2 plus one mechanism; the last two bars are '
            'the combined profiles.</p><div class="grid2 wideitems">' + figs + "</div>")


def section_detection() -> str:
    f = ROOT / "detection" / "results" / "veremi_benchmark.json"
    if not f.exists():
        return '<p class="nodata">Run python -m detection.benchmark.</p>'
    b = json.loads(f.read_text())
    m = b["models"]
    names = [("rules", "--c3"), ("rf", "--c4"), ("hgb", "--c5"), ("hgb_window", "--c6")]
    pretty = {"rules": "rules", "rf": "random forest", "hgb": "gradient boosting",
              "hgb_window": "gradient boosting + window"}
    attacks = [a for a in m["hgb_window"]["per_attack"] if a != "ALL"]
    gb = grouped_bars([a.replace("_", " ") for a in attacks],
                      [(pretty[n], v, [m[n]["per_attack"].get(a, {}).get("f1", [None])[0] for a in attacks])
                       for n, v in names if n in m])
    pr = xy_chart([(pretty[n], v, [tuple(p) for p in m[n].get("curves_split0", {}).get("pr", [])])
                   for n, v in names if n != "rules" and n in m], "recall", xmax=1.0)
    roc = xy_chart([(pretty[n], v, [tuple(p) for p in m[n].get("curves_split0", {}).get("roc", []) if p[0] > 0])
                    for n, v in names if n != "rules" and n in m], "false-positive rate (log)", log_x=True, xmax=1.0)
    rows = "".join(
        f'<tr class="{"focus" if n == "hgb_window" else ""}"><th scope="row">{pretty[n]}</th>'
        f'<td>{m[n]["per_attack"]["ALL"]["f1"][0]:.3f} <small>± {m[n]["per_attack"]["ALL"]["f1"][1]:.3f}</small></td>'
        f'<td>{m[n]["per_attack"]["ALL"]["precision"][0]:.3f}</td><td>{m[n]["per_attack"]["ALL"]["recall"][0]:.3f}</td>'
        f'<td>{m[n]["fpr"][0] * 100:.2f} %</td><td>{m[n]["vehicle_detection_rate"][0]:.0%}</td>'
        f'<td>{m[n]["honest_reported"][0]:.1f} / {m[n]["honest_vehicles"]}</td>'
        f'<td>{_fmt(m[n]["pr_auc"][0], 3) if m[n].get("pr_auc") else "–"}</td></tr>' for n, _ in names if n in m)
    kw = b.get("k_w_tuning_hgb_window_calibrated", [])
    kw_rows = "".join(f'<tr><td>{t["k"]} of {t["w"]}</td><td>{t["detection_rate"]:.0%}</td><td>{t["honest_reported"]}</td></tr>'
                      for t in kw if t["w"] in (5, 10))
    sim = ROOT / "detection" / "models" / "hgb_sim.json"
    sim_note = ""
    if sim.exists():
        s = json.loads(sim.read_text())
        sim_note = (f'<p class="note">Simulator model (<code>detection/train_sim.py</code>): trained on {s["messages"]:,} BSMs '
                    f'from {s["runs"]} grid runs with six attack types; on held-out vehicles it adds no honest report at '
                    f'threshold {s["threshold"]}. On LuST it still reported honest vehicles, so the v3 profiles keep the '
                    f'rules plus the signal-strength check (see the ablation).</p>')
    return (f'<p class="lede">VeReMi Extension (Kamel et al., 2020): {b["messages"]:,} messages from {b["vehicles"]:,} '
            f'vehicles ({b["sample"]:.0%} of the senders), {b["splits"]} train/test splits by vehicle, mean ± 95 % CI.</p>'
            f'<div class="tablewrap"><table><thead><tr><th>model</th><th>F1</th><th>precision</th><th>recall</th>'
            f'<th>false-positive rate</th><th>attacker vehicles reported</th><th>honest reported</th><th>PR-AUC</th>'
            f'</tr></thead><tbody>{rows}</tbody></table></div>'
            f'<figure class="full"><figcaption><b>F1 per attack type</b> <span class="n">constant position offset is '
            f'invisible to kinematics; the simulator adds a signal-strength check for it</span></figcaption>{gb}'
            f'{legend_custom([(pretty[n], v) for n, v in names])}</figure>'
            f'<div class="grid2 two"><figure><figcaption><b>Precision–recall</b> <span class="n">split 0</span></figcaption>'
            f'{pr}</figure><figure><figcaption><b>ROC</b> <span class="n">split 0</span></figcaption>{roc}</figure>'
            f'<figure><figcaption><b>Reporting rule (K of W)</b> <span class="n">gradient boosting + window, split 0'
            f'</span></figcaption><div class="tablewrap"><table><thead><tr><th>rule</th><th>attackers reported</th>'
            f'<th>honest reported</th></tr></thead><tbody>{kw_rows}</tbody></table></div></figure></div>{sim_note}'
            f'<h3>From attack to revocation in the simulator</h3><p class="note">LuST 14:00, v3-fast, one seed: when '
            f'each attacker was flagged, reported by K RSUs, blocked locally and revoked on the ledger.</p>'
            f'{attack_timeline()}')


def section_trust() -> str:
    rows = _read("trust_v3")
    if not rows:
        return '<p class="nodata">Trust experiment not run yet.</p>'
    cols = [("Honest vehicles revoked", "honest_revoked"), ("Attackers caught", "detection_rate"),
            ("Report → first block (s)", "report_to_block_s_mean"), ("False reports filed by the faulty RSUs", "faulty_reports")]
    figs = "".join(f'<figure><figcaption><b>{t}</b></figcaption>'
                   f'{bar_chart([(r["label"], _f(r.get(c)), _f(r.get(c + "_ci95"))) for r in rows], ("v2 +trust", "v3"))}'
                   f'</figure>' for t, c in cols)
    return (f'<p class="lede">Two of the nine RSUs are compromised and report a random honest pseudonym every 5 s for '
            f'180 s; {rows[0].get("n_seeds", "?")} seeds. With plain K = 2 they can revoke honest vehicles together; with '
            f'trust weights each investigation that clears a vehicle lowers their weight.</p>'
            f'{_significance_pair("trust_v3", "Phase-I (K=2)", "v2 +trust-weighted", "honest_revoked")}'
            f'<div class="grid2 wideitems">{figs}</div>')


def _significance_pair(sweep, a, b, col) -> str:
    runs = _read(sweep, "runs.csv")
    va = [_f(r.get(col)) for r in runs if r.get("label") == a and _f(r.get(col)) is not None]
    vb = [_f(r.get(col)) for r in runs if r.get("label") == b and _f(r.get(col)) is not None]
    if len(va) < 2 or len(vb) < 2:
        return ""
    from scipy.stats import ttest_ind
    p = float(ttest_ind(vb, va, equal_var=False).pvalue)
    return (f'<p class="note">{esc(b)} against {esc(a)}, honest vehicles revoked: Welch p = {p:.3g} '
            f'({"significant" if p < 0.05 else "not significant"} at 0.05).</p>')


def section_sensitivity() -> str:
    out = []
    for sweep, key, title, lead, cols in [
        ("sensitivity_obu", "obu_scale", "Vehicle processor speed",
         "150 vehicles; the vehicle unit is 1×, 5× or 10× slower than this PC.",
         [("Neighbour acceptance (ms)", "v2v_accept_ms_mean"), ("Vehicle CPU load", "obu_cpu_util_mean"),
          ("Neighbour BSMs dropped (CPU overload)", "v2v_dropped")]),
        ("sensitivity_attackers", "attacker_ratio", "Share of attackers", "100 vehicles, random-position attack.",
         [("Attackers caught", "detection_rate"), ("Honest vehicles revoked", "honest_revoked"),
          ("Attack → first report (s)", "first_report_delay_s_mean")]),
        ("sensitivity_attack", "attack", "Attack type", "100 vehicles, 10 % attackers of one type each.",
         [("Attackers caught", "detection_rate"), ("Attack → first report (s)", "first_report_delay_s_mean"),
          ("Honest vehicles revoked", "honest_revoked")])]:
        rows = _read(sweep)
        if not rows:
            out.append(f'<h3>{title}</h3><p class="nodata">Not run yet.</p>')
            continue
        settings = sorted({r[key] for r in rows}, key=lambda x: (_f(x) if _f(x) is not None else 0, x))
        figs = "".join(f'<figure><figcaption><b>{t}</b></figcaption>{line_chart(rows, c, key, settings)}</figure>'
                       for t, c in cols)
        out.append(f'<h3>{title}</h3><p class="note">{lead}</p>'
                   f'{legend([n for n in SCHEMES if any(r.get("label") == n for r in rows)])}<div class="grid2">{figs}</div>')
    mix = _read("mixzone_tradeoff")
    if mix:
        pts = sorted(((_f(r.get("silent_share")), _f(r.get("tracking_success")), r.get("mix_silent_max")) for r in mix
                      if _f(r.get("silent_share")) is not None and _f(r.get("tracking_success")) is not None),
                     key=lambda p: p[0])
        fig = xy_chart([("v3-private", "--c7", [(a * 100, b) for a, b, _ in pts])], "share of driving time silent (%)")
        rows = "".join(f'<tr><td>{c} s</td><td>{a:.2%}</td><td>{b:.0%}</td></tr>' for a, b, c in pts)
        out.append('<h3>Mix zones: privacy against safety</h3><p class="note">Longer silence after a pseudonym change makes '
                   'linking harder but hides the vehicle from its neighbours for longer (v3-private, 100 vehicles).</p>'
                   f'<div class="grid2 two"><figure><figcaption><b>Changes tracked against time silent</b></figcaption>'
                   f'{fig}</figure><div class="tablewrap"><table><thead><tr><th>max silence</th><th>driving time silent</th>'
                   f'<th>changes tracked</th></tr></thead><tbody>{rows}</tbody></table></div></div>')
    return "".join(out)


def section_ledger() -> str:
    f = RES / "ledger_consensus" / "summary.json"
    if not f.exists():
        return '<p class="nodata">Run make ledger-bench.</p>'
    data = json.loads(f.read_text())
    names = {"raft_500ms": "Raft, 1 orderer, 500 ms batch", "raft_50ms": "Raft, 1 orderer, 50 ms batch",
             "bft_50ms": "SmartBFT, 4 orderers (f = 1), 50 ms batch"}
    rows = "".join(f'<tr><th scope="row">{names.get(s, s)}</th><td>{r["targetRate"]}</td><td>{r["achievedTps"]}</td>'
                   f'<td>{r["p50Ms"]}</td><td>{r["p95Ms"]}</td><td>{r["failures"]}</td></tr>'
                   for s, rs in data.items() for r in rs)
    bars = bar_chart([(f'{s.replace("_", " ")} @{r["targetRate"]} tx/s', _f(r["p50Ms"]), None)
                      for s, rs in data.items() for r in rs], ("bft",), " ms")
    return (f'<p class="lede">Real Hyperledger Fabric 3.1.5 in Docker (vanetauth chaincode, REST gateway); auth records '
            f'submitted at a fixed rate for 30 s per row. BFT tolerates one malicious orderer of four (n ≥ 3f + 1), as '
            f'the Phase I design proposed.</p><div class="grid2 two"><figure><figcaption><b>Median commit time</b>'
            f'</figcaption>{bars}</figure><div class="tablewrap"><table><thead><tr><th>ordering</th><th>offered tx/s</th>'
            f'<th>achieved</th><th>commit p50 ms</th><th>p95 ms</th><th>failed</th></tr></thead><tbody>{rows}</tbody>'
            f'</table></div></div>')


def overview() -> str:
    """Headline numbers of v3-fast / v3-private against Phase-I."""
    out = []
    for sweep, key, setting, where in [("compare_v3", "vehicles", "150", "Grid, 150 vehicles (5 seeds)"),
                                       ("compare_lust", "real", "lust:peak", "LuST 08:00, ~525 vehicles in the box (3 seeds)")]:
        rows = _read(sweep)
        pick = lambda n: next((r for r in rows if r.get(key) == setting and r.get("label") == n), {})  # noqa: E731
        p, fst, prv = pick("Phase-I"), pick("v3-fast"), pick("v3-private")
        if not p:
            continue
        lines = []
        for title, col, unit, better, _ in METRICS:
            a, b, c = _f(p.get(col)), _f(fst.get(col)), _f(prv.get(col))
            if a is None or b is None:
                continue
            ch = (b - a) / a * 100 if a else None
            good = ch is not None and ((ch < -2) if better == "low" else (ch > 2))
            bad = ch is not None and ((ch > 2) if better == "low" else (ch < -2))
            chip = f'<span class="chip {"good" if good else "cost" if bad else "same"}">{"–" if ch is None else f"{ch:+.0f} %"}</span>'
            lines.append(f'<tr><th scope="row">{esc(title)} <small>{esc(unit)}</small></th><td>{_fmt(a)}</td>'
                         f'<td>{_fmt(b)}</td><td>{_fmt(c)}</td><td>{chip}</td></tr>')
        out.append(f'<h3>{where}</h3><div class="tablewrap"><table class="ov"><thead><tr><th>metric</th><th>Phase-I</th>'
                   f'<th>v3-fast</th><th>v3-private</th><th>v3-fast vs Phase-I</th></tr></thead><tbody>{"".join(lines)}'
                   f'</tbody></table></div>')
    return "".join(out) or '<p class="nodata">Main comparison not run yet.</p>'


TABS = [("overview", "Overview"), ("grid", "Grid"), ("lust", "LuST city"), ("ablation", "Ablation"),
        ("detection", "Detection"), ("trust", "Compromised RSUs"), ("sensitivity", "Sensitivity"), ("ledger", "Ledger")]

NOTES = """<h3>Measured and modelled</h3><ul>
<li>Radio (IEEE 802.11p, 6 Mb/s, 10 MHz) runs in ns-3; mobility comes from SUMO at 0.1 s steps.</li>
<li>Every signature, proof and MAC is computed for real; its time is measured on this PC
(<code>experiments/compute_times_v3.json</code>); vehicles are assumed 5× slower.</li>
<li>Batch verification is priced with the speedup measured with the same pure-Python arithmetic for single and batch checks.</li>
<li>Received power for the signal-strength check follows the scenario's path-loss model plus 4 dB shadowing; it is not read
from the ns-3 PHY.</li>
<li>The compromised-RSU investigation outcome uses the simulation's ground truth. The tracker hears every BSM, so its
success is an upper bound.</li>
<li>LuST was validated with SUMO 0.26; it runs here with SUMO 1.28. VeReMi Extension has no receiver data.</li></ul>"""


def build() -> Path:
    bodies = {
        "overview": overview() + f'<h3>The LuST box</h3><div class="grid2 two"><figure class="mapfig">{lust_map()}'
                    f'<figcaption class="n">Luxembourg city centre, 1.35 km square: roads, 9 RSUs with their 300 m range '
                    f'and 60 real vehicle tracks at 08:00.</figcaption></figure><div class="notes">{NOTES}</div></div>',
        "grid": section_compare("compare_v3", "vehicles", None,
                                "Synthetic 5 × 5 grid (250 m blocks), random trips, 0.1 s mobility; 50 / 100 / 150 vehicles; "
                                "5 seeds; 10 % attackers from 30 s."),
        "lust": section_compare("compare_lust", "real", ["lust:low", "lust:mid", "lust:peak"],
                                "LuST (Luxembourg, calibrated 24 h traffic), densest 1.35 km square; low = 06:00, mid = 14:00, "
                                "peak = 08:00; 3 seeds; 10 % attackers from 30 s."),
        "ablation": section_ablation(), "detection": section_detection(), "trust": section_trust(),
        "sensitivity": section_sensitivity(), "ledger": section_ledger(),
    }
    nav = "".join(f'<button role="tab" id="tab-{k}" aria-controls="p-{k}" data-k="{k}">{v}</button>' for k, v in TABS)
    panels = "".join(f'<section role="tabpanel" id="p-{k}" aria-labelledby="tab-{k}"><h2>{v}</h2>{bodies[k]}</section>'
                     for k, v in TABS)
    OUT.write_text(TEMPLATE.replace("{NAV}", nav).replace("{PANELS}", panels))
    return OUT


TEMPLATE = """<title>VANET v3 Evaluation</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Sans+Condensed:wght@600;700&family=IBM+Plex+Mono:wght@400;500&display=swap">
<style>
/* Layout: report with a sticky tab bar; each tab answers one evaluation question; charts in wrapping grids */
:root {
  --bg: #f5f6f8; --panel: #ffffff; --fg: #18202b; --muted: #5a6575; --rule: #dce1e8; --accent: #0b6e8a;
  --best: #e1f2ea; --best-fg: #12633f; --cost: #fbe9de; --cost-fg: #8a3b12;
  --c1: #9a6b2f; --c2: #8a5aa8; --c3: #7b8594; --c4: #3f8fd2; --c5: #2bb1a3; --c6: #d2491f; --c7: #b8326e;
  --display: "IBM Plex Sans Condensed", "Arial Narrow", sans-serif;
  --body: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, monospace;
}
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg: #11151b; --panel: #192029; --fg: #e3e8ef; --muted: #97a2b2; --rule: #2a3340; --accent: #4fb5d3;
  --best: #173a2b; --best-fg: #8fdcb5; --cost: #3d2417; --cost-fg: #f4b28c;
  --c1: #d0a062; --c2: #b98ad6; --c3: #9aa4b2; --c4: #6cb0ec; --c5: #4fd0c1; --c6: #ff7a4d; --c7: #f06aa6;
  color-scheme: dark; } }
:root[data-theme="dark"] {
  --bg: #11151b; --panel: #192029; --fg: #e3e8ef; --muted: #97a2b2; --rule: #2a3340; --accent: #4fb5d3;
  --best: #173a2b; --best-fg: #8fdcb5; --cost: #3d2417; --cost-fg: #f4b28c;
  --c1: #d0a062; --c2: #b98ad6; --c3: #9aa4b2; --c4: #6cb0ec; --c5: #4fd0c1; --c6: #ff7a4d; --c7: #f06aa6;
  color-scheme: dark; }
body { background: var(--bg); color: var(--fg); font: 15px/1.55 var(--body); }
body::before { content: ""; position: fixed; inset: 0 0 auto; height: env(safe-area-inset-top, 0px); z-index: 10; background: var(--bg); }
main { max-width: 1200px; margin: 0 auto; padding-block: 26px 64px;
  padding-left: max(16px, env(safe-area-inset-left, 0px)); padding-right: max(16px, env(safe-area-inset-right, 0px));
  display: grid; gap: 22px; }
header { display: grid; gap: 6px; }
h1, h2, h3 { font-family: var(--display); margin: 0; text-wrap: balance; }
h1 { font-size: clamp(28px, 4vw, 40px); line-height: 1.1; }
h2 { font-size: 24px; }
h3 { font-size: 17px; margin-top: 18px; }
p { margin: 0; max-width: 78ch; }
.eyebrow { font: 500 12px/1 var(--mono); text-transform: uppercase; letter-spacing: .08em; color: var(--accent); }
.lede, .note { color: var(--muted); }
.note { font-size: 13.5px; }
nav { position: sticky; top: env(safe-area-inset-top, 0px); z-index: 5; background: var(--bg); display: flex; gap: 4px;
  overflow-x: auto; border-bottom: 1px solid var(--rule); padding-block: 6px; }
nav button { font: 500 14px var(--body); color: var(--muted); background: none; border: 0; border-radius: 6px;
  padding: 7px 12px; cursor: pointer; white-space: nowrap; }
nav button:hover { color: var(--fg); }
nav button[aria-selected="true"] { color: var(--fg); background: var(--panel); box-shadow: inset 0 -2px 0 var(--accent); }
nav button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
section[role=tabpanel] { display: grid; gap: 14px; min-width: 0; }
.tablewrap { overflow-x: auto; background: var(--panel); border: 1px solid var(--rule); border-radius: 6px; min-width: 0; }
table { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; font-size: 13px; }
th, td { padding: 6px 10px; text-align: right; border-bottom: 1px solid var(--rule); white-space: nowrap; }
thead th { font: 500 11.5px/1.25 var(--body); color: var(--muted); vertical-align: bottom; white-space: normal; min-width: 64px; }
th[scope=row], thead th:first-child { text-align: left; font-weight: 500; }
tbody tr:last-child th, tbody tr:last-child td { border-bottom: 0; }
tr.focus th, tr.focus td { font-weight: 600; }
td.best { background: var(--best); color: var(--best-fg); }
td small, th small { color: var(--muted); font-weight: 400; }
.dir { margin-left: 3px; color: var(--accent); }
i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: -1px; }
i.atk { background: var(--fg); width: 3px; }
.legend { display: flex; flex-wrap: wrap; gap: 4px 14px; font-size: 13px; }
.legend.small { font-size: 12px; color: var(--muted); }
.grid2 { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr)); gap: 12px; }
.grid2.two { grid-template-columns: repeat(auto-fill, minmax(min(100%, 360px), 1fr)); }
.grid2.wideitems { grid-template-columns: repeat(auto-fill, minmax(min(100%, 460px), 1fr)); }
figure { margin: 0; background: var(--panel); border: 1px solid var(--rule); border-radius: 6px; padding: 10px 12px 8px;
  display: grid; gap: 6px; min-width: 0; align-content: start; }
figure.full { overflow-x: auto; }
figcaption { font-size: 13.5px; line-height: 1.35; }
figcaption .u { font: 12px var(--mono); color: var(--accent); }
.n { font-size: 12px; color: var(--muted); }
svg { width: 100%; height: auto; display: block; }
svg.chart.wide { min-width: 520px; }
.grid { stroke: var(--rule); stroke-width: 1; }
.tick { fill: var(--muted); font: 10px var(--mono); }
.tick.lab { fill: var(--fg); font: 10.5px var(--body); }
.val { fill: var(--fg); font: 10.5px var(--mono); }
.bar { fill: var(--c3); }
.bar.hi { fill: var(--c6); }
.lane { stroke: var(--rule); stroke-width: 2; }
.attack { fill: var(--fg); }
.map { background: var(--bg); border-radius: 4px; }
.map .road { fill: none; stroke: var(--muted); stroke-width: .7; opacity: .55; }
.map .track { fill: none; stroke: var(--c6); stroke-width: 1.1; opacity: .6; }
.map .cov { fill: var(--c4); fill-opacity: .07; stroke: var(--c4); stroke-opacity: .5; stroke-width: .8; }
.map .rsu { fill: var(--c4); stroke: var(--panel); stroke-width: 1.5; }
.map .box { fill: none; stroke: var(--fg); stroke-dasharray: 4 3; stroke-width: 1; }
.chip { display: inline-block; padding: 1px 8px; border-radius: 999px; font: 500 11.5px/1.6 var(--body); }
.chip.good { background: var(--best); color: var(--best-fg); }
.chip.cost { background: var(--cost); color: var(--cost-fg); }
.chip.same { background: var(--rule); color: var(--fg); }
.nodata { color: var(--muted); font-style: italic; }
details { background: var(--panel); border: 1px solid var(--rule); border-radius: 6px; padding: 8px 12px; }
details summary { cursor: pointer; font-weight: 500; }
details[open] { display: grid; gap: 8px; }
.notes ul { padding-left: 18px; margin: 6px 0 0; display: grid; gap: 6px; font-size: 13.5px; }
code { font: 12.5px var(--mono); }
</style>
<main>
<header>
  <span class="eyebrow">BTP · IIIT Kottayam · privacy-preserving VANET authentication</span>
  <h1>VANET v3 Evaluation</h1>
  <p class="lede">ZKP authentication with a permissioned ledger, improved for latency, channel load, detection and privacy,
  compared on ns-3 against ECDSA pseudonym certificates, a central authority and the Phase I design, on a synthetic grid and
  on real Luxembourg traffic. Mean ± 95 % confidence interval over the seeds; ↓ lower is better, ↑ higher.</p>
</header>
<nav role="tablist" aria-label="Evaluation sections">{NAV}</nav>
{PANELS}
</main>
<script>
(function () {
  const tabs = [...document.querySelectorAll('nav [role=tab]')];
  function show(k) {
    tabs.forEach(t => { const on = t.dataset.k === k; t.setAttribute('aria-selected', on); t.tabIndex = on ? 0 : -1; });
    document.querySelectorAll('[role=tabpanel]').forEach(p => { p.hidden = p.id !== 'p-' + k; });
    try { localStorage.setItem('v3tab', k); } catch (e) {}
  }
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => { show(t.dataset.k); try { history.replaceState(null, '', '#' + t.dataset.k); } catch (e) {} });
    t.addEventListener('keydown', e => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
        const n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length]; n.focus(); n.click();
      }
    });
  });
  let start = (location.hash || '').slice(1);
  if (!tabs.some(t => t.dataset.k === start)) { try { start = localStorage.getItem('v3tab') || ''; } catch (e) { start = ''; } }
  show(tabs.some(t => t.dataset.k === start) ? start : 'overview');
})();
</script>
"""

if __name__ == "__main__":
    print(build())
