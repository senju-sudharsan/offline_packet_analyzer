# Internal packet capture engine (Scapy hidden here)

from scapy.all import sniff
from core.packet_parser import parse_packet


class PacketCaptureEngine:
    def __init__(self, interface=None, packet_callback=None):
        self.interface = interface
        self.packet_callback = packet_callback

    def _handle_packet(self, raw_packet):
        packet = parse_packet(raw_packet)
        if packet and self.packet_callback:
            self.packet_callback(packet)

    def start(self):
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False
        )
