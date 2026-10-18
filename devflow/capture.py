import socket
import struct
from devflow.dissector import Dissector

class CaptureEngine:
    def __init__(self, socketio=None, interface="lo"):
        self.interface = interface
        self.socketio = socketio
        self.sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.sniffer.bind((self.interface, 0))

    def start(self):
        print(f"[*] Sniffer running on {self.interface}...")
        while True:
            raw_data, _ = self.sniffer.recvfrom(65535)
            self.process_packet(raw_data)

    def process_packet(self, raw_data):
        eth_header = raw_data[:14]
        eth_type = struct.unpack("!6s6sH", eth_header)[2]

        if eth_type == 0x0800:  # IPv4
            ihl = raw_data[14] & 0x0F
            ip_header_length = ihl * 4

            # --- Issue #1 Code Starts Here ---
            protocol, src_ip, dest_ip = Dissector.parse_ipv4(raw_data)

            if protocol == 6:  # TCP
                tcp_offset = 14 + ip_header_length
                src_port, dest_port, tcp_header_length = Dissector.parse_tcp(raw_data, tcp_offset)

                # The Feedback-Loop Filter: Ignore dashboard traffic
                if src_port == 5000 or dest_port == 5000:
                    return

                # Temporary print to verify Issue 1 works before moving to Application Layer
                print(f"[TCP Caught] {src_ip}:{src_port} -> {dest_ip}:{dest_port}")
            # --- Issue #1 Code Ends Here ---

if __name__ == "__main__":
    engine = CaptureEngine(interface="lo")
    engine.start()