
class ThreatDetector:
    def __init__(self):
        self.syn_counter = {}

    def analyze(self, packet):
        if packet.protocol == "TCP":
            key = packet.src_ip
            self.syn_counter[key] = self.syn_counter.get(key, 0) + 1
            if self.syn_counter[key] > 100:
                return f"Possible SYN flood from {key}"
        return None
