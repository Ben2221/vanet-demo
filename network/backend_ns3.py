"""ns-3 backend: IEEE 802.11p in ns-3, driven from Python.

Needs ns-3 3.44 or newer with Python bindings (``pip install ns3`` on Linux
with Python 3.11-3.13, or a build with --enable-python-bindings).

ns-3's Python bindings are cppyy based. Wiring callbacks from C++ back into
Python is fragile through the generated bindings, so the ns-3 side of this
backend is a small C++ "glue" layer compiled at runtime with cppyy.cppdef().
Python talks to it with plain numbers and strings:

  - Setup(...) builds nodes, 802.11p devices, IPv4/UDP, mobility (vehicles from
    the ns-2 file through Ns2MobilityHelper, RSUs at fixed positions), one UDP
    socket per node and the PHY State trace used for the channel busy ratio
  - payloads cross the boundary as hex strings (binary-safe, no encoding issues)
  - Schedule(delay, id) and the receive callback call into ONE Python dispatcher
    each; Python keeps every callable in a dict, so nothing is garbage-collected
    while ns-3 still holds it
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import Callable

from network.backend import BROADCAST, Backend, RxHandler
from network.radio import RadioConfig

GLUE = r"""
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/propagation-module.h"
#include <cmath>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace vanetglue {
using namespace ns3;

static NodeContainer g_nodes;
static NetDeviceContainer g_devices;
static std::vector<Ptr<Socket>> g_sock;
static std::vector<double> g_busy;
static uint16_t g_port = 4000;
static std::function<void(uint64_t)> g_dispatch;
// extra modules (FlowMonitor, NetAnim) register their teardown here, so their
// objects die before the simulator and not in static destructors at exit
static std::vector<std::function<void()>> g_cleanup;
static std::function<void(uint32_t, uint32_t, std::string, uint64_t, double)> g_rx;

static std::string ToHex(const uint8_t* b, uint32_t n) {
    static const char* H = "0123456789abcdef";
    std::string s(2 * n, '0');
    for (uint32_t i = 0; i < n; i++) { s[2 * i] = H[b[i] >> 4]; s[2 * i + 1] = H[b[i] & 15]; }
    return s;
}

static uint8_t Nib(char c) {
    return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : c - 'A' + 10;
}

void SetDispatcher(std::function<void(uint64_t)> f) { g_dispatch = f; }
void SetRxHandler(std::function<void(uint32_t, uint32_t, std::string, uint64_t, double)> f) { g_rx = f; }

static void Fire(uint64_t id) { if (g_dispatch) g_dispatch(id); }
void Schedule(double delay, uint64_t id) { Simulator::Schedule(Seconds(delay), &Fire, id); }
double Now() { return Simulator::Now().GetSeconds(); }

static void OnRecv(Ptr<Socket> s) {
    Address from;
    Ptr<Packet> p;
    while ((p = s->RecvFrom(from))) {
        uint32_t n = p->GetSize();
        std::vector<uint8_t> buf(n);
        p->CopyData(buf.data(), n);
        uint32_t src = InetSocketAddress::ConvertFrom(from).GetIpv4().Get();
        if (g_rx) g_rx(s->GetNode()->GetId(), src, ToHex(buf.data(), n), p->GetUid(),
                       Simulator::Now().GetSeconds());
    }
}

static void PhyState(std::string ctx, Time start, Time dur, WifiPhyState st) {
    size_t a = ctx.find("/NodeList/") + 10;
    size_t b = ctx.find('/', a);
    uint32_t id = std::stoul(ctx.substr(a, b - a));
    if (id < g_busy.size() && (st == WifiPhyState::TX || st == WifiPhyState::RX || st == WifiPhyState::CCA_BUSY))
        g_busy[id] += dur.GetSeconds();
}

void Setup(uint32_t nVeh, std::string rsuXY, std::string ns2File, uint32_t seedRun,
           double txPower, double rxSens, double plExp, double refLoss,
           std::string mode, bool nakagami, double nakM, uint16_t port) {
    RngSeedManager::SetSeed(12345);
    RngSeedManager::SetRun(seedRun);
    g_port = port;

    std::vector<std::pair<double, double>> rsus;
    std::stringstream ss(rsuXY);
    std::string item;
    while (std::getline(ss, item, ';')) {
        if (item.empty()) continue;
        size_t c = item.find(',');
        rsus.push_back({std::stod(item.substr(0, c)), std::stod(item.substr(c + 1))});
    }
    uint32_t n = nVeh + rsus.size();
    g_nodes.Create(n);
    g_busy.assign(n, 0.0);

    // mobility: vehicles from the ns-2 file (node ids 0..nVeh-1), RSUs fixed
    if (nVeh > 0 && !ns2File.empty()) {
        Ns2MobilityHelper ns2(ns2File);
        ns2.Install(g_nodes.Begin(), g_nodes.Begin() + nVeh);
    } else if (nVeh > 0) {
        // live TraCI coupling: Python sets position and velocity after each SUMO step
        for (uint32_t i = 0; i < nVeh; i++) {
            Ptr<ConstantVelocityMobilityModel> m = CreateObject<ConstantVelocityMobilityModel>();
            m->SetPosition(Vector(-3000.0, -3000.0, 0.0));   // parked, as in fcd_to_ns2.py
            g_nodes.Get(i)->AggregateObject(m);
        }
    }
    if (!rsus.empty()) {
        NodeContainer rsuNodes;
        Ptr<ListPositionAllocator> alloc = CreateObject<ListPositionAllocator>();
        for (uint32_t i = 0; i < rsus.size(); i++) {
            rsuNodes.Add(g_nodes.Get(nVeh + i));
            alloc->Add(Vector(rsus[i].first, rsus[i].second, 0.0));
        }
        MobilityHelper mh;
        mh.SetPositionAllocator(alloc);
        mh.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mh.Install(rsuNodes);
    }

    // radio: 802.11p, 10 MHz, log-distance path loss (+ optional Nakagami fading)
    YansWifiChannelHelper ch;
    ch.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    ch.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                          "Exponent", DoubleValue(plExp),
                          "ReferenceDistance", DoubleValue(1.0),
                          "ReferenceLoss", DoubleValue(refLoss));
    if (nakagami)
        ch.AddPropagationLoss("ns3::NakagamiPropagationLossModel",
                              "m0", DoubleValue(nakM), "m1", DoubleValue(nakM), "m2", DoubleValue(nakM));
    YansWifiPhyHelper phy;
    phy.SetChannel(ch.Create());
    phy.Set("TxPowerStart", DoubleValue(txPower));   // ns-3 default is ~16 dBm: set it explicitly
    phy.Set("TxPowerEnd", DoubleValue(txPower));
    phy.Set("TxPowerLevels", UintegerValue(1));
    phy.Set("RxSensitivity", DoubleValue(rxSens));
    // ns-3 also drops frames whose preamble is below the preamble-detection
    // MinimumRssi (default -82 dBm) and senses CCA at -82 dBm: align both with
    // the receive threshold, or the range shrinks to ~250 m
    phy.Set("CcaSensitivity", DoubleValue(rxSens));
    phy.SetPreambleDetectionModel("ns3::ThresholdPreambleDetectionModel",
                                  "MinimumRssi", DoubleValue(rxSens),
                                  "Threshold", DoubleValue(4.0));

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue(mode),
                                 "ControlMode", StringValue(mode),
                                 "NonUnicastMode", StringValue(mode));
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac", "QosSupported", BooleanValue(true));
    g_devices = wifi.Install(phy, mac, g_nodes);

    InternetStackHelper inet;
    inet.Install(g_nodes);
    Ipv4AddressHelper ip;
    ip.SetBase("10.1.0.0", "255.255.0.0");
    ip.Assign(g_devices);

    g_sock.clear();
    for (uint32_t i = 0; i < n; i++) {
        Ptr<Socket> s = Socket::CreateSocket(g_nodes.Get(i), UdpSocketFactory::GetTypeId());
        s->Bind(InetSocketAddress(Ipv4Address::GetAny(), g_port));
        s->SetAllowBroadcast(true);
        s->SetRecvCallback(MakeCallback(&OnRecv));
        g_sock.push_back(s);
    }

    Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/State/State",
                    MakeCallback(&PhyState));
}

uint32_t NodeIp(uint32_t id) {
    return g_nodes.Get(id)->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal().Get();
}

uint64_t Send(uint32_t node, uint32_t dstIp, const std::string& hex, uint8_t prio) {
    std::vector<uint8_t> b(hex.size() / 2);
    for (size_t i = 0; i < b.size(); i++) b[i] = (Nib(hex[2 * i]) << 4) | Nib(hex[2 * i + 1]);
    Ptr<Packet> p = Create<Packet>(b.data(), b.size());
    SocketPriorityTag tag;   // user priority -> EDCA access category
    tag.SetPriority(prio);
    p->ReplacePacketTag(tag);
    uint64_t uid = p->GetUid();
    g_sock[node]->SendTo(p, 0, InetSocketAddress(Ipv4Address(dstIp), g_port));
    return uid;
}

std::vector<double> PosVel(uint32_t id) {
    Ptr<MobilityModel> m = g_nodes.Get(id)->GetObject<MobilityModel>();
    Vector p = m->GetPosition();
    Vector v = m->GetVelocity();
    return {p.x, p.y, v.x, v.y};
}

// flattened (id, distance) pairs of the nodes within r of node id
std::vector<double> InRange(uint32_t id, double r) {
    std::vector<double> out;
    Vector p = g_nodes.Get(id)->GetObject<MobilityModel>()->GetPosition();
    for (uint32_t i = 0; i < g_nodes.GetN(); i++) {
        if (i == id) continue;
        Vector q = g_nodes.Get(i)->GetObject<MobilityModel>()->GetPosition();
        double dx = p.x - q.x, dy = p.y - q.y;
        double d2 = dx * dx + dy * dy;
        if (d2 <= r * r) { out.push_back(i); out.push_back(std::sqrt(d2)); }
    }
    return out;
}

void SetPosVel(uint32_t id, double x, double y, double vx, double vy) {
    Ptr<ConstantVelocityMobilityModel> m = g_nodes.Get(id)->GetObject<ConstantVelocityMobilityModel>();
    m->SetPosition(Vector(x, y, 0.0));
    m->SetVelocity(Vector(vx, vy, 0.0));
}

double Busy(uint32_t id) { return g_busy[id]; }
uint32_t NumNodes() { return g_nodes.GetN(); }

void Run(double until) {
    Simulator::Stop(Seconds(until));
    Simulator::Run();
}

void Destroy() {
    for (auto& f : g_cleanup) f();
    g_cleanup.clear();
    for (auto& s : g_sock) s->Close();
    g_sock.clear();
    Simulator::Destroy();
    g_devices = NetDeviceContainer();
    g_nodes = NodeContainer();
}
}  // namespace vanetglue
"""

FLOWMON_GLUE = r"""
#include "ns3/flow-monitor-module.h"
namespace vanetglue {
static ns3::FlowMonitorHelper* g_fmh = nullptr;
static ns3::Ptr<ns3::FlowMonitor> g_fm;
void EnableFlowMonitor() {
    g_fmh = new ns3::FlowMonitorHelper();
    g_fm = g_fmh->InstallAll();
    g_cleanup.push_back([]() { g_fm = nullptr; delete g_fmh; g_fmh = nullptr; });
}
// returns "flows,txPackets,rxPackets,lostPackets,txBytes,rxBytes,delaySumS,jitterSumS"
std::string FlowMonitorReport(std::string xmlFile) {
    if (!g_fm) return "";
    g_fm->CheckForLostPackets();
    if (!xmlFile.empty()) g_fm->SerializeToXmlFile(xmlFile, true, true);
    uint64_t flows = 0, tx = 0, rx = 0, lost = 0, txb = 0, rxb = 0;
    double delay = 0, jitter = 0;
    for (auto& kv : g_fm->GetFlowStats()) {
        flows++;
        tx += kv.second.txPackets; rx += kv.second.rxPackets; lost += kv.second.lostPackets;
        txb += kv.second.txBytes; rxb += kv.second.rxBytes;
        delay += kv.second.delaySum.GetSeconds(); jitter += kv.second.jitterSum.GetSeconds();
    }
    std::ostringstream o;
    o << flows << "," << tx << "," << rx << "," << lost << "," << txb << "," << rxb << "," << delay << "," << jitter;
    return o.str();
}
}
"""

NETANIM_GLUE = r"""
#include "ns3/netanim-module.h"
namespace vanetglue {
static ns3::AnimationInterface* g_anim = nullptr;
void EnableNetAnim(std::string file, uint32_t nVeh, bool packets, double pollS) {
    g_anim = new ns3::AnimationInterface(file);
    g_cleanup.push_back([]() { delete g_anim; g_anim = nullptr; });
    g_anim->SetMobilityPollInterval(ns3::Seconds(pollS));
    if (!packets) g_anim->SkipPacketTracing();
    g_anim->EnablePacketMetadata(false);
    for (uint32_t i = 0; i < g_nodes.GetN(); i++) {
        if (i < nVeh) {
            g_anim->UpdateNodeColor(i, 30, 110, 220);
            g_anim->UpdateNodeSize(i, 8, 8);
        } else {
            g_anim->UpdateNodeColor(i, 220, 60, 40);
            g_anim->UpdateNodeSize(i, 20, 20);
            g_anim->UpdateNodeDescription(i, "rsu" + std::to_string(i - nVeh));
        }
    }
}
void DescribeNode(uint32_t id, std::string text) { if (g_anim) g_anim->UpdateNodeDescription(id, text); }
}
"""

BROADCAST_IP = 0xFFFFFFFF


class Ns3Backend(Backend):
    name = "ns3"

    def __init__(self, trace: Path | None, n_vehicles: int, rsu_positions: list[tuple[float, float]],
                 radio: RadioConfig, seed: int = 1, port: int = 4000, flowmon: bool = True,
                 netanim: str | None = None, netanim_packets: bool = False) -> None:
        try:
            from ns import ns
        except ImportError as exc:
            raise RuntimeError(
                "ns-3 Python bindings not found. Install with 'pip install ns3' (Linux, "
                "Python 3.11-3.13) or build ns-3 with --enable-python-bindings, "
                "or run with --backend lite."
            ) from exc
        self.ns = ns
        cppyy = ns.cppyy
        cppyy.cppdef(GLUE)
        if flowmon:
            cppyy.cppdef(FLOWMON_GLUE)
        if netanim:
            cppyy.cppdef(NETANIM_GLUE)
        self.g = cppyy.gbl.vanetglue
        self.n_vehicles = n_vehicles
        self._flowmon = flowmon
        self._callbacks: dict[int, Callable[[], None]] = {}
        self._ids = itertools.count(1)
        self._rx: RxHandler | None = None
        # bound methods kept on self so cppyy's std::function wrappers stay valid
        self._dispatch_ref = self._dispatch
        self._rx_ref = self._on_rx
        self.g.SetDispatcher(self._dispatch_ref)
        self.g.SetRxHandler(self._rx_ref)

        rsu_xy = ";".join(f"{x:.3f},{y:.3f}" for x, y in rsu_positions)
        self.g.Setup(n_vehicles, rsu_xy, str(trace) if trace else "", seed,
                     radio.tx_power_dbm, radio.rx_sensitivity_dbm, radio.path_loss_exponent,
                     radio.reference_loss_db, radio.ns3_mode, radio.fading == "nakagami",
                     radio.nakagami_m, port)
        self.n = int(self.g.NumNodes())
        self._ip_of = [int(self.g.NodeIp(i)) for i in range(self.n)]
        self._node_of_ip = {ip: i for i, ip in enumerate(self._ip_of)}
        if flowmon:
            self.g.EnableFlowMonitor()
        if netanim:
            self.g.EnableNetAnim(str(netanim), n_vehicles, netanim_packets, 0.5)

    def _dispatch(self, cb_id: int) -> None:
        fn = self._callbacks.pop(int(cb_id), None)
        if fn is not None:
            fn()

    def _on_rx(self, node: int, src_ip: int, hexdata: str, uid: int, t: float) -> None:
        if self._rx is None:
            return
        src = self._node_of_ip.get(int(src_ip), -1)
        self._rx(int(node), src, bytes.fromhex(str(hexdata)), int(uid), float(t))

    def now(self) -> float:
        return float(self.g.Now())

    def schedule(self, delay: float, fn: Callable[[], None]) -> None:
        cb_id = next(self._ids)
        self._callbacks[cb_id] = fn
        self.g.Schedule(max(0.0, float(delay)), cb_id)

    def send(self, src: int, dst: int, payload: bytes, priority: int = 0) -> int:
        ip = BROADCAST_IP if dst == BROADCAST else self._ip_of[dst]
        return int(self.g.Send(src, ip, payload.hex(), priority))

    def set_rx_handler(self, handler: RxHandler) -> None:
        self._rx = handler

    def position(self, node: int) -> tuple[float, float]:
        v = self.g.PosVel(node)
        return float(v[0]), float(v[1])

    def velocity(self, node: int) -> tuple[float, float]:
        v = self.g.PosVel(node)
        return float(v[2]), float(v[3])

    def nodes_in_range(self, node: int, radius: float) -> list[tuple[int, float]]:
        v = list(self.g.InRange(node, radius))
        return [(int(v[i]), float(v[i + 1])) for i in range(0, len(v), 2)]

    def busy_time(self, node: int) -> float:
        return float(self.g.Busy(node))

    def set_pos_vel(self, node: int, x: float, y: float, vx: float, vy: float) -> None:
        """Live mobility (TraCI): only for vehicles created without an ns-2 trace."""
        self.g.SetPosVel(node, float(x), float(y), float(vx), float(vy))

    def describe(self, node: int, text: str) -> None:
        if hasattr(self.g, "DescribeNode"):
            self.g.DescribeNode(node, text)

    def run(self, until: float) -> None:
        self.g.Run(until)

    def finish(self, out_dir) -> dict:
        out: dict = {"backend": "ns3"}
        if self._flowmon:
            rep = str(self.g.FlowMonitorReport(str(Path(out_dir) / "flowmon.xml")))
            if rep:
                keys = ["flows", "tx_packets", "rx_packets", "lost_packets", "tx_bytes", "rx_bytes",
                        "delay_sum_s", "jitter_sum_s"]
                vals = rep.split(",")
                fm = {k: float(v) for k, v in zip(keys, vals)}
                fm["mean_delay_ms"] = 1000 * fm["delay_sum_s"] / fm["rx_packets"] if fm["rx_packets"] else None
                fm["delivery_ratio"] = fm["rx_packets"] / fm["tx_packets"] if fm["tx_packets"] else None
                out["flowmon"] = fm
        self.g.Destroy()
        return out
