import socket
import struct

# TODO (Teammate 1): Create devflow/dissector.py and import it here
# TODO (Teammate 2): Create devflow/metrics.py and import it here

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
        # 1. Parse Ethernet Header (14 bytes)
        eth_header = raw_data[:14]
        eth_type = struct.unpack("!6s6sH", eth_header)[2]

        if eth_type == 0x0800:  # IPv4
            ihl = raw_data[14] & 0x0F
            ip_header_length = ihl * 4

            # TODO (Teammate 1): Parse IPv4 header to extract Source and Destination IP
            
            # TODO (Teammate 1): Check if Protocol is 6 (TCP). If so, parse TCP header for Ports
            
            # TODO (Teammate 1): Filter out port 5000 so the dashboard doesn't capture its own traffic!
            
            # TODO (Teammate 1): Decode the Application Layer payload (HTTP or PostgreSQL)
            
            # TODO (Teammate 2): Pass ports to Metrics module to track request/response latency
            
            # TODO: Emit final formatted JSON event to self.socketio
            pass

if __name__ == "__main__":
    # Local terminal testing mode
    engine = CaptureEngine(interface="lo")
    engine.start()