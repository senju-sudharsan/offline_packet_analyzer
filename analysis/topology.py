# Network topology graph generator (data only)

class TopologyGraph:
    def __init__(self):
        self.nodes = set()
        self.edges = []

    def build(self, flows, risk_engine, mode="filtered",
              risk_threshold=0.6, top_n=20):
        """
        mode:
          - 'raw'       : include all flows
          - 'filtered'  : include high-risk / top-N flows
        """

        edges = []

        for flow in flows:
            risk, reasons = risk_engine.compute_risk(flow)
            src, dst, _, _, proto = flow.key

            edge = {
                "src": src,
                "dst": dst,
                "protocol": proto,
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "risk": round(risk, 2),
                "reasons": reasons
            }
            edges.append(edge)

        if mode == "filtered":
            # prioritize risky & heavy flows
            edges = sorted(
                edges,
                key=lambda e: (e["risk"], e["packet_count"]),
                reverse=True
            )
            edges = [
                e for e in edges
                if e["risk"] >= risk_threshold
            ][:top_n]

        # Build node set
        for e in edges:
            self.nodes.add(e["src"])
            self.nodes.add(e["dst"])

        self.edges = edges

    def export(self):
        return {
            "nodes": list(self.nodes),
            "edges": self.edges
        }
