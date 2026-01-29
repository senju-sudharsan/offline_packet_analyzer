from datetime import datetime

class Flow:
    def __init__(self, key):
        self.key = key  # (src_ip, dst_ip, src_port, dst_port, protocol)

        self.packet_count = 0
        self.byte_count = 0
        self.start_time = datetime.now()
        self.end_time = self.start_time

        self.unique_dst_ports = set()

    def update(self, packet):
        self.packet_count += 1
        self.byte_count += packet.size
        self.end_time = packet.timestamp

        if packet.dst_port:
            self.unique_dst_ports.add(packet.dst_port)

    def duration(self):
        delta = (self.end_time - self.start_time).total_seconds()
        return max(delta, 1.0)

    def packets_per_second(self):
        return self.packet_count / self.duration()
