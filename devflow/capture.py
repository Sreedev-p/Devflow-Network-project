
import socket
import struct


DASHBOARD_PORT = 5000
ETHERNET_HEADER_LENGTH = 14
IPV4_ETHERTYPE = 0x0800
TCP_PROTOCOL = 6


class CaptureEngine:

    def __init__(self, socketio=None, interface="lo"):
        self.interface = interface
        self.socketio = socketio

        self.sniffer = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(0x0003)
        )

        self.sniffer.bind((self.interface, 0))

    def start(self):
        print(f"[*] Sniffer running on {self.interface}...")

        try:
            while True:
                raw_data, _ = self.sniffer.recvfrom(65535)

                try:
                    self.process_packet(raw_data)
                except (ValueError, struct.error, IndexError) as exc:
                    print(f"[!] Invalid packet: {exc}")

        except KeyboardInterrupt:
            print("\n[*] Stopping sniffer...")

        finally:
            self.sniffer.close()

    def process_packet(self, raw_data):

        # --------------------------------------------------
        # STEP 1: Validate and parse Ethernet header
        # --------------------------------------------------

        if len(raw_data) < ETHERNET_HEADER_LENGTH:
            return

        eth_type = struct.unpack_from("!H", raw_data, 12)[0]

        # Process IPv4 packets only.
        if eth_type != IPV4_ETHERTYPE:
            return

        ip_offset = ETHERNET_HEADER_LENGTH

        # Minimum IPv4 header length is 20 bytes.
        if len(raw_data) < ip_offset + 20:
            return

        # --------------------------------------------------
        # STEP 2: Parse IPv4 header
        # --------------------------------------------------

        version_ihl = raw_data[ip_offset]

        version = version_ihl >> 4
        ihl = version_ihl & 0x0F

        # Validate IPv4 version and header length.
        if version != 4 or ihl < 5:
            return

        ip_header_length = ihl * 4

        if len(raw_data) < ip_offset + ip_header_length:
            return

        # Extract total IPv4 packet length.
        total_length = struct.unpack_from(
            "!H", raw_data, ip_offset + 2
        )[0]

        if total_length < ip_header_length:
            return

        ip_end = ip_offset + total_length

        if len(raw_data) < ip_end:
            return

        # Extract protocol and source/destination IP addresses.
        # Format: skip 9 bytes, read 1-byte protocol,
        # skip 2 bytes, then read two 4-byte IPv4 addresses.
        ip_fields = struct.unpack_from(
            "!9xB2x4s4s",
            raw_data,
            ip_offset
        )

        protocol = ip_fields[0]
        src_ip = socket.inet_ntoa(ip_fields[1])
        dst_ip = socket.inet_ntoa(ip_fields[2])

        # TCP protocol number is 6.
        if protocol != TCP_PROTOCOL:
            return

        # --------------------------------------------------
        # STEP 3: Reject IPv4 fragments
        # --------------------------------------------------

        flags_fragment = struct.unpack_from(
            "!H", raw_data, ip_offset + 6
        )[0]

        # Reject packets with the More Fragments flag or
        # a nonzero fragment offset.
        if flags_fragment & 0x3FFF:
            return

        # --------------------------------------------------
        # STEP 4: Parse TCP header
        # --------------------------------------------------

        tcp_offset = ip_offset + ip_header_length

        ip_payload_length = total_length - ip_header_length

        # A minimum TCP header is 20 bytes.
        if ip_payload_length < 20:
            return

        tcp_src_port, tcp_dst_port = struct.unpack_from(
            "!HH",
            raw_data,
            tcp_offset
        )

        # TCP data offset is the upper 4 bits of byte 12.
        tcp_data_offset = raw_data[tcp_offset + 12] >> 4

        if tcp_data_offset < 5:
            return

        tcp_header_length = tcp_data_offset * 4

        if tcp_header_length > ip_payload_length:
            return

        # --------------------------------------------------
        # STEP 5: Filter dashboard traffic
        # --------------------------------------------------

        if (
            tcp_src_port == DASHBOARD_PORT
            or tcp_dst_port == DASHBOARD_PORT
        ):
            return

        # --------------------------------------------------
        # STEP 6: Extract application payload
        # --------------------------------------------------

        payload_offset = tcp_offset + tcp_header_length

        payload = raw_data[payload_offset:ip_end]

        if not payload:
            return

        # --------------------------------------------------
        # STEP 7: Classify application-layer traffic
        # --------------------------------------------------

        event_type = self.classify_payload(
            payload,
            tcp_src_port,
            tcp_dst_port
        )

        if event_type is None:
            return

        # --------------------------------------------------
        # STEP 8: Build network event
        # --------------------------------------------------

        if event_type == "SQL Query":
            # SQL query latency is not calculated here.
            latency = None
        else:
            # The metrics module will calculate latency
            # when it is integrated.
            latency = None

        decoded_payload = payload.decode(
            "utf-8",
            errors="replace"
        ).strip()

        first_line = (
            decoded_payload.splitlines()[0]
            if decoded_payload
            else ""
        )

        event = {
            "type": event_type,
            "connection": (
                f"{src_ip}:{tcp_src_port} -> "
                f"{dst_ip}:{tcp_dst_port}"
            ),
            "payload": first_line[:1000],
            "latency": latency
        }

        # --------------------------------------------------
        # STEP 9: Emit event to frontend
        # --------------------------------------------------

        if self.socketio is not None:
            self.socketio.emit(
                "network_event",
                event
            )

        return event

    @staticmethod
    def classify_payload(payload, src_port, dst_port):

        if not payload:
            return None

        # PostgreSQL Simple Query protocol.
        # 'Q' is ASCII 81.
        if (
            (src_port == 5432 or dst_port == 5432)
            and len(payload) > 5
            and payload[0] == 81
        ):
            return "SQL Query"

        # HTTP request detection.
        http_methods = (
            b"GET ",
            b"POST ",
            b"PUT ",
            b"DELETE "
        )

        if payload.startswith(http_methods):
            return "HTTP Request"

        # HTTP response detection.
        if b"HTTP/1." in payload[:64]:
            return "HTTP Response"

        return None


if __name__ == "__main__":

    engine = CaptureEngine(interface="lo")

    try:
        engine.start()
    finally:
        engine.sniffer.close()
