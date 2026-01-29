
from models.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

def parse_packet(pkt):
    if IP not in pkt:
        return None

    proto = "OTHER"
    src_port = dst_port = None

    if TCP in pkt:
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"

    return Packet(
        timestamp=datetime.now(),
        src_ip=pkt[IP].src,
        dst_ip=pkt[IP].dst,
        protocol=proto,
        src_port=src_port,
        dst_port=dst_port,
        size=len(pkt),
        payload=bytes(pkt[IP].payload)
    )
