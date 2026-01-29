from models.flow import Flow

class FlowTracker:
    def __init__(self):
        self.flows = {}

    def update(self, packet):
        key = (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol
        )

        if key not in self.flows:
            self.flows[key] = Flow(key)

        self.flows[key].update(packet)

    def get_flows(self):
        return self.flows.values()
