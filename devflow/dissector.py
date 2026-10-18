import struct
import socket

class Dissector:
    @staticmethod
    def parse_ipv4(raw_data):
        # IPv4 header starts after the 14-byte Ethernet header
        ipv4_header = raw_data[14:34]
        
        # Unpack format: skip 8 bytes, 1 byte (Protocol), skip 2 bytes, 4 bytes (Src IP), 4 bytes (Dest IP)
        unpacked = struct.unpack("!8xB2x4s4s", ipv4_header)
        
        protocol = unpacked[0]
        src_ip = socket.inet_ntoa(unpacked[1])
        dest_ip = socket.inet_ntoa(unpacked[2])
        
        return protocol, src_ip, dest_ip

    @staticmethod
    def parse_tcp(raw_data, tcp_offset):
        # TCP header is at least 20 bytes long
        tcp_header = raw_data[tcp_offset:tcp_offset+20]
        
        # Unpack format: 2 bytes (Src Port), 2 bytes (Dest Port), skip 8 bytes (Seq/Ack), 2 bytes (Flags/Offset)
        unpacked = struct.unpack("!HH8xH", tcp_header[:14])
        
        src_port = unpacked[0]
        dest_port = unpacked[1]
        
        # The data offset (header length) is stored in the top 4 bits of the 12th byte
        data_offset = (unpacked[2] >> 12) * 4
        
        return src_port, dest_port, data_offset