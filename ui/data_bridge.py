# ui/data_bridge.py
import threading

from core.flow_tracker import FlowTracker
from analysis.statistics import TrafficStatistics
from analysis.risk_engine import RiskEngine
from analysis.topology import TopologyGraph
from core.capture_engine import PacketCaptureEngine

# ---------------- SHARED STATE ----------------
flow_tracker = FlowTracker()
stats = TrafficStatistics()
risk_engine = RiskEngine()
topology = TopologyGraph()

_capture_started = False


# ---------------- CAPTURE CONTROL ----------------
def start_capture():
    global _capture_started

    if _capture_started:
        return

    def on_packet(packet):
        flow_tracker.update(packet)
        stats.update(packet)

    engine = PacketCaptureEngine(packet_callback=on_packet)

    t = threading.Thread(
        target=engine.start,
        daemon=True
    )
    t.start()

    _capture_started = True


# ---------------- DATA ACCESSORS ----------------
def get_summary():
    return {
        "total_packets": stats.total_packets,
        "active_flows": len(list(flow_tracker.get_flows())),
        "protocols": stats.protocol_counts
    }


def get_risk_flows(limit=10):
    flows = list(flow_tracker.get_flows())
    risky = []

    for f in flows:
        risk, reasons = risk_engine.compute_risk(f)

        if risk > 0:
            risky.append({
                "src": f.key[0],
                "dst": f.key[1],
                "protocol": f.key[4],
                "packets": f.packet_count,
                "risk": round(risk, 2),
                "reasons": ", ".join(reasons)
            })

    risky.sort(key=lambda x: x["risk"], reverse=True)
    return risky[:limit]



def get_topology():
    flows = list(flow_tracker.get_flows())

    topology.build(
        flows=flows,
        risk_engine=risk_engine,
        mode="all"
    )

    return topology.export()
