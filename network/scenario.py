"""The integrated scenario: where mobility, radio, protocol, detector and
ledger meet.

Scenario wires together
  - a backend (ns-3 or lite) carrying every packet
  - one NodeHandle + protocol object per vehicle and per RSU
  - BSM beaconing on every vehicle that is on the road
  - the ledger bridge (local copies for RSUs, delayed visibility of writes)
  - the metrics CSV and the network statistics
"""

from __future__ import annotations

import inspect
import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

from network import hooks
from network.backend import BROADCAST, Backend
from network.bsm import Attack, Beaconer
from network.hooks import NodeHandle
from network.ledger_bridge import LedgerBridge
from network.metrics import MetricsLog, NetStats

# default names for the first byte of a message, used only for logging when the
# protocol does not provide message_type(data)
DEFAULT_TYPES = {1: "BEACON", 2: "AUTH_REQ", 3: "AUTH_RESP", 4: "HANDOVER_REQ",
                 5: "PREAUTH", 6: "BSM", 7: "HANDOVER_RESP", 8: "ECHO"}
HIGH_PRIORITY = {"BSM", "BEACON", "TESLA_KEY"}       # sent on AC_VO, everything else on AC_BE
PERIODIC = {"BSM", "BEACON", "TESLA_KEY"}          # 10 Hz traffic: TX_/RX_ rows only with --log-bsm


@dataclass
class VehicleSpec:
    node_id: int
    name: str
    first_seen: float
    last_seen: float


@dataclass
class RsuSpec:
    node_id: int
    name: str
    x: float
    y: float
    range_m: float


@dataclass
class ScenarioEnv:
    """Shared context handed to protocol.setup() and to every protocol object."""
    config: dict
    ledger_client: object
    bridge: LedgerBridge
    ta_ledger: object                      # LedgerView with the TA identity
    vehicles: list = field(default_factory=list)
    rsus: list = field(default_factory=list)
    detector: object = None
    rng: random.Random = None
    out_dir: Path = None
    shared: dict = field(default_factory=dict)   # free space for protocol-wide state

    def node_by_id(self, node_id: int) -> NodeHandle:
        return self._by_id[node_id]

    def node(self, name: str) -> NodeHandle:
        for n in self.vehicles + self.rsus:
            if n.name == name:
                return n
        raise KeyError(name)


class Scenario:
    def __init__(self, backend: Backend, vehicles: list[VehicleSpec], rsus: list[RsuSpec],
                 protocol: ModuleType, ledger_client, out_dir: Path, *, duration: float,
                 seed: int = 1, beacon_rate: float = 10.0, bsm_size: int = 200,
                 congestion_control: bool = False, cbr_threshold: float = 0.6,
                 pdr_range: float = 300.0, log_bsm: bool = False, detector=None,
                 attacker_ratio: float = 0.0, attack: str = "const_pos", attack_start: float = 0.0,
                 compute_times: dict | None = None, ledger_sync: float = 1.0, backbone_ms: float = 2.0,
                 config: dict | None = None) -> None:
        self.backend = backend
        self.duration = duration
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.rng = random.Random(seed)
        self.protocol = protocol
        self.log_bsm = log_bsm
        self.backbone_delay = backbone_ms / 1000.0
        self.compute_times = compute_times or {}
        self.metrics = MetricsLog(self.out_dir / "metrics.csv")
        self.stats = NetStats(pdr_range)
        self.pdr_range = pdr_range
        self.cbr: dict[int, float] = {}
        self._busy_prev: dict[int, float] = {}
        self._msg_type = getattr(protocol, "message_type", None)

        self.bridge = LedgerBridge(ledger_client, backend.now, backend.schedule,
                                   log=self._ledger_log, sync_interval=ledger_sync,
                                   sync_identity=rsus[0].name if rsus else "TA")
        self.env = ScenarioEnv(config=config or {}, ledger_client=ledger_client, bridge=self.bridge,
                               ta_ledger=self.bridge.view("TA"), detector=detector,
                               rng=self.rng, out_dir=self.out_dir)

        # ---- nodes
        self.vehicles: list[NodeHandle] = []
        self.rsus: list[NodeHandle] = []
        self.node_by_id: dict[int, NodeHandle] = {}
        self.node_by_name: dict[str, NodeHandle] = {}
        self.rsu_pos: dict[int, tuple[float, float]] = {}
        self.rsu_range: dict[int, float] = {}
        for v in vehicles:
            h = NodeHandle(self, v.node_id, v.name, "vehicle")
            h.first_seen, h.last_seen = v.first_seen, v.last_seen
            h.detector = detector
            self._add(h)
            self.vehicles.append(h)
        for r in rsus:
            h = NodeHandle(self, r.node_id, r.name, "rsu")
            h.ledger = self.bridge.view(r.name)
            h.detector = detector
            self.rsu_pos[r.node_id] = (r.x, r.y)
            self.rsu_range[r.node_id] = r.range_m
            self._add(h)
            self.rsus.append(h)
        self.env.vehicles = self.vehicles
        self.env.rsus = self.rsus
        self.env._by_id = self.node_by_id

        # ---- attackers (ground truth written to attackers.csv for evaluation)
        self.attacks: dict[int, Attack] = {}
        n_att = int(round(attacker_ratio * len(self.vehicles)))
        for h in self.rng.sample(self.vehicles, n_att) if n_att else []:
            h.is_attacker = True
            self.attacks[h.id] = Attack(attack, random.Random(self.rng.random()))
        self.attack_start = attack_start
        with (self.out_dir / "attackers.csv").open("w") as f:
            f.write("node_id,name,attack,start\n")
            for nid, a in sorted(self.attacks.items()):
                f.write(f"{nid},{self.node_by_id[nid].name},{a.kind},{attack_start}\n")

        self.beaconers = {
            h.id: Beaconer(self, h, beacon_rate, bsm_size, congestion_control, cbr_threshold, None)
            for h in self.vehicles
        }
        backend.set_rx_handler(self._on_rx)

        # ---- protocol objects
        for h in self.vehicles:
            h.app = protocol.create_vehicle(h, self.env)
        for h in self.rsus:
            h.app = protocol.create_rsu(h, self.env)
        self._rx_takes_src = {}

    def _add(self, h: NodeHandle) -> None:
        self.node_by_id[h.id] = h
        self.node_by_name[h.name] = h

    # ------------------------------------------------------------------ logs
    def _ledger_log(self, who: str, event: str, nbytes: int = 0, latency_ms=None, result: str = "") -> None:
        self.metrics.log(self.backend.now(), who, event, nbytes, latency_ms, result)

    def msg_type(self, data: bytes) -> str:
        if self._msg_type is not None:
            try:
                return str(self._msg_type(data))
            except Exception:
                pass
        return DEFAULT_TYPES.get(data[0], f"T{data[0]}") if data else "EMPTY"

    # ---------------------------------------------------------------- packets
    def send(self, h: NodeHandle, dst: int, data: bytes, priority: int | None = None) -> None:
        if not h.active:
            return                      # a vehicle that is not on the road has no radio
        mtype = self.msg_type(data)
        prio = priority if priority is not None else (6 if mtype in HIGH_PRIORITY else 0)
        expected = None
        if dst == BROADCAST:
            expected = {}
            for j, dist in self.backend.nodes_in_range(h.id, self.pdr_range):
                n = self.node_by_id.get(j)
                if n is not None and n.active:
                    expected[j] = dist
        uid = self.backend.send(h.id, dst, data, prio)
        t = self.backend.now()
        self.stats.on_send(uid, h.id, t, mtype, len(data), expected)
        if mtype not in PERIODIC or self.log_bsm:
            dst_name = "broadcast" if dst == BROADCAST else self.node_by_id[dst].name
            self.metrics.log(t, h.name, f"TX_{mtype}", len(data), None, dst_name)

    def _on_rx(self, node: int, src: int, data: bytes, uid: int, t: float) -> None:
        h = self.node_by_id.get(node)
        if h is None:
            return
        rec = self.stats.inflight.get(uid)
        unicast = rec is not None and rec[4] is None
        delay_ms = self.stats.on_receive(uid, node, t, unicast_dst=unicast)
        if not h.active:
            return
        mtype = self.msg_type(data)
        if mtype not in PERIODIC or self.log_bsm:
            src_name = self.node_by_id[src].name if src in self.node_by_id else str(src)
            self.metrics.log(t, h.name, f"RX_{mtype}", len(data), delay_ms, src_name)
        self._deliver(h, src, data, t)

    def backbone_send(self, h: NodeHandle, dst: int, data: bytes, delay: float = 0.0) -> None:
        """RSU-to-RSU wired backbone: fixed latency, no radio, no PDR accounting."""
        mtype = self.msg_type(data)
        dst_h = self.node_by_id[dst]

        def sent() -> None:
            t0 = self.backend.now()
            self.metrics.log(t0, h.name, f"TX_{mtype}", len(data), None, f"backbone:{dst_h.name}")

            def arrive() -> None:
                t = self.backend.now()
                self.metrics.log(t, dst_h.name, f"RX_{mtype}", len(data), (t - t0) * 1000, f"backbone:{h.name}")
                self._deliver(dst_h, h.id, data, t)

            self.backend.schedule(self.backbone_delay, arrive)

        if delay > 0:
            self.backend.schedule(delay, sent)
        else:
            sent()

    def _deliver(self, h: NodeHandle, src: int, data: bytes, t: float) -> None:
        if h.app is None:
            return
        # last_sender is valid only while on_receive runs; restored afterwards so a
        # delivery nested in the handler (zero-delay backbone, ...) cannot leave it wrong
        prev, h.last_sender = h.last_sender, src
        try:
            self._call_app(h, src, data, t)
        finally:
            h.last_sender = prev

    def _call_app(self, h: NodeHandle, src: int, data: bytes, t: float) -> None:
        app = h.app
        fn = app.on_receive
        takes_src = self._rx_takes_src.get(type(app))
        if takes_src is None:
            try:
                takes_src = "src" in inspect.signature(fn).parameters
            except (TypeError, ValueError):
                takes_src = False
            self._rx_takes_src[type(app)] = takes_src
        if takes_src:
            fn(h, data, t, src=src)
        else:
            fn(h, data, t)

    # --------------------------------------------------------------- lifecycle
    def _vehicle_enter(self, h: NodeHandle) -> None:
        h.active = True
        h.log("ENTER", result=f"({h.position()[0]:.0f},{h.position()[1]:.0f})")
        if hasattr(h.app, "on_start"):
            h.app.on_start(h)
        self.beaconers[h.id].start()

    def _vehicle_leave(self, h: NodeHandle) -> None:
        self.beaconers[h.id].stop()
        if hasattr(h.app, "on_stop"):
            h.app.on_stop(h)
        h.active = False
        h.log("LEAVE")

    def _start_attacks(self) -> None:
        for nid, a in self.attacks.items():
            self.beaconers[nid].attack = a
            self.node_by_id[nid].log("ATTACK_START", result=a.kind)

    def _tick(self) -> None:
        """Once per simulated second: channel busy ratio and PDR bookkeeping."""
        t = self.backend.now()
        for h in self.vehicles + self.rsus:
            if h.kind == "vehicle" and not h.active:
                continue
            busy = self.backend.busy_time(h.id)
            cbr = min(1.0, max(0.0, busy - self._busy_prev.get(h.id, 0.0)))
            self._busy_prev[h.id] = busy
            self.cbr[h.id] = cbr
            if h.kind == "rsu":
                self.stats.cbr_samples[h.name].append(cbr)
                self.metrics.log(t, h.name, "CBR", 0, None, f"{cbr:.4f}")
        self.stats.flush(t)
        if t + 1.0 <= self.duration:
            self.backend.schedule(1.0, self._tick)

    def run(self) -> dict:
        hooks._bind(self)
        try:
            if hasattr(self.protocol, "setup"):
                self.protocol.setup(self.env)
            for h in self.rsus:
                self._busy_prev[h.id] = 0.0
                if hasattr(h.app, "on_start"):
                    self.backend.schedule(0.0, lambda h=h: h.app.on_start(h))
            for h in self.vehicles:
                if h.first_seen < self.duration:
                    self.backend.schedule(h.first_seen, lambda h=h: self._vehicle_enter(h))
                if h.last_seen < self.duration:
                    self.backend.schedule(h.last_seen, lambda h=h: self._vehicle_leave(h))
            if self.attacks:
                self.backend.schedule(self.attack_start, self._start_attacks)
            self.backend.schedule(1.0, self._tick)
            self.bridge.start()
            self.backend.run(self.duration)
            if hasattr(self.protocol, "teardown"):
                self.protocol.teardown(self.env)
        finally:
            hooks._bind(None)
        return self.finish()

    def finish(self) -> dict:
        backend_stats = self.backend.finish(self.out_dir)
        self.bridge.close()
        summary = {
            "duration_s": self.duration,
            "vehicles": len(self.vehicles),
            "rsus": len(self.rsus),
            "attackers": len(self.attacks),
            **self.stats.summary(),
            "ledger": self.bridge.stats(),
            "network_backend": backend_stats,
            "metrics_rows": self.metrics.rows,
        }
        self.metrics.close()
        (self.out_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
        return summary
