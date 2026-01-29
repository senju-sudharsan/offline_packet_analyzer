class TrafficStatistics:
    def __init__(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = {}

    def update(self, packet):
        self.total_packets += 1
        self.total_bytes += packet.size

        proto = packet.protocol
        if proto not in self.protocol_counts:
            self.protocol_counts[proto] = 0
        self.protocol_counts[proto] += 1
