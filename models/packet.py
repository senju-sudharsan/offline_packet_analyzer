
class Packet:
    def __init__(self, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size, payload):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.size = size
        self.payload = payload
