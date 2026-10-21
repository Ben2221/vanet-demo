"""Live map of a running simulation in the browser (--viz, make viz).

    make viz                      # v3-fast on the grid, http://127.0.0.1:8765
    make viz MAP=lust:low         # real Luxembourg traffic

A small HTTP server in a background thread serves network/viz.html, the road network
(lane shapes from the SUMO net), and every SNAPSHOT_EVERY simulated seconds a snapshot of
every vehicle and RSU: position, pseudonym, ticket, class, revocation state, RSU load and
counters. Clicking a vehicle or RSU on the page shows these details and its recent events.
The narrated event feed is experiments/live.py's. The page can pause the simulation and
change its speed: the snapshot callback holds the simulator back to SPEED x real time.

Ground truth (who is an attacker) is shown for the audience only; no protocol logic reads it.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
from collections import Counter, defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

SNAPSHOT_EVERY = 0.1        # simulated s between snapshots
FEED_KEEP = 2000            # narrated lines kept for the page
NODE_EVENTS = 25            # events kept per node for its details panel
PAGE = Path(__file__).with_name("viz.html")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
LINE = re.compile(r"^\[\s*([0-9.]+)s\]\s+(\S+)\s+(.*)$")

# events counted per node for the details panel
COUNTED = {"AUTH_OK", "HANDOVER_OK", "RENEW_OK", "PSEUDONYM_CHANGE", "AUTH_REJECTED", "AUTH_VERIFY",
           "AUTH_REJECT", "HANDOVER_CHECK", "DETECT_FLAG", "REPORT", "BSM_REJECT", "QUARANTINE_BLOCK",
           "QUARANTINE_SENT", "FAKE_EMERGENCY", "CLUSTER_SWITCH"}
QUIET = {"CBR", "TX_PREAUTH", "RX_PREAUTH", "PREAUTH_OK", "LEDGER_SUBMIT", "LEDGER_VISIBLE",
         "TX_AUTH_RESP", "RX_AUTH_RESP", "TX_AUTH_REQ", "RX_AUTH_REQ", "TX_HANDOVER_REQ",
         "RX_HANDOVER_REQ", "TX_QUARANTINE", "RX_QUARANTINE"}


def roads(net_file: str, bounds: tuple[float, float, float, float], cache_dir: Path) -> list[list[list[int]]]:
    """Lane-0 shapes of every non-internal edge that touches ``bounds`` (cached as JSON)."""
    x0, y0, x1, y1 = bounds
    key = hashlib.sha1(f"{Path(net_file).resolve()}:{bounds}".encode()).hexdigest()[:12]
    cache = cache_dir / f"viz_roads_{key}.json"
    if cache.exists():
        return json.loads(cache.read_text())
    from defusedxml.ElementTree import iterparse
    out = []
    for _, el in iterparse(net_file, events=("end",)):
        if el.tag == "lane" and not el.get("id", "").startswith(":") and el.get("index") == "0":
            pts = [tuple(map(float, p.split(","))) for p in el.get("shape", "").split()]
            if any(x0 <= x <= x1 and y0 <= y <= y1 for x, y in pts):
                out.append([[round(x), round(y)] for x, y in pts])
        if el.tag in ("edge", "junction"):
            el.clear()
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(out, separators=(",", ":")))
    return out


class _Sink:
    """File-like target for a Narrator: keeps its lines (without colours) for the page."""

    def __init__(self, viz: "Viz") -> None:
        self.viz, self.buf = viz, ""

    def write(self, s: str) -> None:
        self.buf += s
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            self.viz.add_line(ANSI.sub("", line))

    def flush(self) -> None:
        pass


class Viz:
    def __init__(self, scenario, net_file: str, port: int = 8765, speed: float = 1.0, title: str = "") -> None:
        self.sc = scenario
        self.env = scenario.env
        self.speed = speed if speed > 0 else 1.0
        self.paused = False
        self.title = title
        self.lock = threading.Lock()
        self.feed: deque[dict] = deque(maxlen=FEED_KEEP)
        self.seq = 0
        self.node_events: dict[str, deque] = defaultdict(lambda: deque(maxlen=NODE_EVENTS))
        self.counts: dict[str, Counter] = defaultdict(Counter)
        self.state = b"{}"
        self.done = False
        self._anchor: tuple[float, float] | None = None       # (wall, sim) for pacing
        rx = [r.position() for r in scenario.rsus]
        rng = max([self._range(r) for r in scenario.rsus] or [300.0])
        pts = rx or [(0.0, 0.0)]
        bounds = (min(p[0] for p in pts) - rng, min(p[1] for p in pts) - rng,
                  max(p[0] for p in pts) + rng, max(p[1] for p in pts) + rng)
        print("viz: reading the road network ...", flush=True)
        self.net = json.dumps({
            "title": title, "bounds": bounds,
            "roads": roads(net_file, bounds, Path(__file__).resolve().parent.parent / "mobility" / "out"),
            "rsus": [{"name": r.name, "x": r.position()[0], "y": r.position()[1], "range": self._range(r)}
                     for r in scenario.rsus],
        }, separators=(",", ":")).encode()
        from experiments.live import Narrator
        self.narrator = Narrator(out=_Sink(self))
        self.env_metrics = scenario.metrics
        self.env_metrics.listeners.append(self._event)
        self.env_metrics.listeners.append(self.narrator.feed)
        self.server = ThreadingHTTPServer(("127.0.0.1", port), self._handler())
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        print(f"viz: open http://127.0.0.1:{port} in a browser", flush=True)

    def _range(self, r) -> float:
        return float(self.sc.rsu_range.get(r.id, 300.0))

    # ------------------------------------------------------------ simulator side
    def start(self) -> None:
        self.sc.backend.schedule(0.0, self._tick)

    def _event(self, sim_time, node, event, nbytes, latency, result) -> None:
        if event in QUIET:
            return
        if event in COUNTED:
            self.counts[node][event] += 1
        lat = "" if latency in (None, "") else f"{float(latency):.2f} ms"
        self.node_events[node].append([round(float(sim_time), 2), event, str(result)[:80], lat])

    def add_line(self, line: str) -> None:
        with self.lock:
            m = LINE.match(line)
            if m:
                self.seq += 1
                self.feed.append({"seq": self.seq, "t": float(m.group(1)), "node": m.group(2), "text": m.group(3)})
            elif line.strip().startswith("└─") and self.feed:
                self.feed[-1]["why"] = line.strip()[2:].strip()
            # status lines ("── t= ...") are dropped: the page has its own counters

    def _tick(self) -> None:
        now = self.sc.backend.now()
        self.state = json.dumps(self._snapshot(now), separators=(",", ":")).encode()
        self._pace(now)
        self.sc.backend.schedule(SNAPSHOT_EVERY, self._tick)

    def _pace(self, now: float) -> None:
        """Hold the simulator at ``speed`` x real time; spin while paused."""
        while self.paused:
            time.sleep(0.05)
            self._anchor = None
        if self._anchor is None:
            self._anchor = (time.time(), now)
        wall0, sim0 = self._anchor
        wait = wall0 + (now - sim0) / self.speed - time.time()
        if wait > 0:
            time.sleep(wait)
        elif wait < -1.0:
            self._anchor = (time.time(), now)    # the simulator is slower than asked: do not catch up

    def _snapshot(self, now: float) -> dict:
        ledger = self.env.ta_ledger
        nar = self.narrator
        vehicles = []
        for n in self.sc.vehicles:
            if not n.active:
                continue
            x, y = n.position()
            vx, vy = n.velocity()
            d = {"name": n.name, "x": round(x, 1), "y": round(y, 1), "h": round(n.heading(), 1),
                 "v": round(math.hypot(vx, vy), 1), "att": n.is_attacker}
            app = n.app
            veh = getattr(app, "vehicle", None)
            if veh is not None:
                pid = veh.current.pid
                t = veh.ticket.get("payload", {}) if isinstance(veh.ticket, dict) else {}
                d.update(pid=pid, cls=veh.vehicle_class, ev=bool(getattr(app, "emergency", False)),
                         ticket=bool(t) and veh.ticket_valid(), rsu=veh.current_rsu_id or t.get("issuer"),
                         exp=round(float(t.get("expiry", 0)) - now, 1) if t else None,
                         svc=t.get("service"), revoked=bool(ledger.is_revoked(pid)),
                         out=getattr(app, "retry_after", 0) == math.inf,
                         pids=len(getattr(app, "assigned", ())), npids=len(veh.pseudonyms))
            vehicles.append(d)
        rsus = []
        for r in self.sc.rsus:
            app = r.app
            d = {"name": r.name, "cbr": round(r.channel_busy_ratio(), 3)}
            cpu = getattr(app, "cpu", None)
            if cpu is not None:
                d.update(queue_ms=round(cpu.backlog() * 1000, 2), busy=round(cpu.busy / max(now, 1e-9), 4))
            core = getattr(app, "rsu", None)
            if core is not None:
                d.update(reported=len(core.reported),
                         quarantined=sum(1 for until in core.quarantine_until.values() if until > now))
            rsus.append(d)
        caught = len(nar.caught)
        return {"t": round(now, 2), "speed": self.speed, "paused": self.paused, "done": self.done,
                "vehicles": vehicles, "rsus": rsus,
                "totals": {"on_road": len(vehicles), "authenticated": len(nar.joined),
                           "handovers": nar.n["handovers"], "renewals": nar.n["renewals"],
                           "attackers": len(nar.attackers), "caught": caught,
                           "false_flags": len(nar.false_flags), "honest_revoked": len(nar.false_alarms),
                           "emergency": len(nar.emergency),
                           "bsms": self.sc.stats.sent_by_type.get("BSM", 0),
                           "bsm_bytes": self.sc.stats.bytes_by_type.get("BSM", 0)}}

    def finish(self) -> None:
        """Last snapshot; keep serving it until Ctrl+C."""
        self.done = True
        self.narrator.finish()
        self.state = json.dumps(self._snapshot(self.sc.backend.now()), separators=(",", ":")).encode()

    # ------------------------------------------------------------------ server
    def _handler(self):
        viz = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a) -> None:      # quiet
                pass

            def _send(self, body: bytes, ctype: str = "application/json") -> None:
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                u = urlparse(self.path)
                q = parse_qs(u.query)
                if u.path == "/":
                    self._send(PAGE.read_bytes(), "text/html; charset=utf-8")
                elif u.path == "/net":
                    self._send(viz.net)
                elif u.path == "/state":
                    self._send(viz.state)
                elif u.path == "/feed":
                    since = int(q.get("since", ["0"])[0])
                    with viz.lock:
                        items = [f for f in viz.feed if f["seq"] > since]
                    self._send(json.dumps(items).encode())
                elif u.path == "/node":
                    name = q.get("name", [""])[0]
                    self._send(json.dumps({"events": list(viz.node_events.get(name, ())),
                                           "counts": dict(viz.counts.get(name, {}))}).encode())
                elif u.path == "/control":
                    if "speed" in q:
                        viz.speed = min(50.0, max(0.1, float(q["speed"][0])))
                        viz._anchor = None
                    if "pause" in q:
                        viz.paused = q["pause"][0] == "1"
                    self._send(json.dumps({"speed": viz.speed, "paused": viz.paused}).encode())
                else:
                    self.send_error(404)

        return H
