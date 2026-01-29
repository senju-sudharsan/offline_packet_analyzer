from core.capture_engine import PacketCaptureEngine
from core.flow_tracker import FlowTracker
from analysis.statistics import TrafficStatistics
from analysis.risk_engine import RiskEngine
from analysis.topology import TopologyGraph

# OUTPUT MODES: "RAW", "SUMMARY", "SILENT"
OUTPUT_MODE = "SUMMARY"


def start_cli(interface=None):
    flow_tracker = FlowTracker()
    stats = TrafficStatistics()
    risk_engine = RiskEngine()
    topology = TopologyGraph()

    def on_packet(packet):
        flow_tracker.update(packet)
        stats.update(packet)

        # ---- RAW MODE (old behavior) ----
        if OUTPUT_MODE == "RAW":
            print(f"[{packet.protocol}] {packet.src_ip} -> {packet.dst_ip}")

        flows = list(flow_tracker.get_flows())

        # ---- SUMMARY MODE ----
        if OUTPUT_MODE == "SUMMARY" and stats.total_packets % 50 == 0:
            topology.build(
                flows=flows,
                risk_engine=risk_engine,
                mode="filtered"
            )

            graph = topology.export()

            print("\n========= NETWORK SUMMARY =========")
            print(f"Packets captured : {stats.total_packets}")
            print(f"Active flows     : {len(flows)}")
            print(f"Protocols        : {stats.protocol_counts}")

            if graph["edges"]:
                top = graph["edges"][0]
                print("\nTop Risk Flow:")
                print(f"  {top['src']} → {top['dst']}")
                print(f"  Protocol : {top['protocol']}")
                print(f"  Risk     : {top['risk']}")
                if top["reasons"]:
                    print(f"  Reasons  : {', '.join(top['reasons'])}")

            print("==================================\n")

        # ---- SILENT MODE ----
        # No printing at all (used later for UI)

    engine = PacketCaptureEngine(
        interface=interface,
        packet_callback=on_packet
    )
    engine.start()
