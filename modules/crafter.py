from struct import unpack, pack
import socket
from collections import namedtuple
import random
from .structures import *


class Crafter():
    @staticmethod
    def get_checksum(header):
        s = 0
        hex_header = int(header.hex(), 16)
        while hex_header > 0:
            s += hex_header & 0xFFFF
            hex_header = hex_header >> 16

        result = 0
        while s > 0:
            result += s & 0xFFFF
            s = s >> 16
        result ^= 0xFFFF
        
        return result


    @staticmethod
    def get_ip_header(src_ip, dst_ip, proto=socket.IPPROTO_TCP):
        IP_HEADER_MASK = '!BBHHHBBH4s4s'
        version = 4
        ihl = 5
        version_ihl = (version << 4) + ihl
        dscp_ecn = 0
        packet_len = 20
        identificator = 1

        # flags
        first_flag = 0
        df = 1
        mf = 0
        flags = (df << 1) + mf

        fragment_offset = 0
        flags_offset = (flags << 13) + fragment_offset
        ttl = 255
        checksum = 0
        src_ip = socket.inet_aton(src_ip)
        dst_ip = socket.inet_aton(dst_ip)

        packet_without_checksum = pack(IP_HEADER_MASK, version_ihl, dscp_ecn, packet_len, identificator, flags_offset, ttl, proto, checksum, src_ip, dst_ip)

        return packet_without_checksum


    @staticmethod
    def get_tcp_header(src_ip,  src_port, dst_ip, dst_port, seq_num, window_size=64240):
        src_ip = socket.inet_aton(src_ip)
        dst_ip = socket.inet_aton(dst_ip)

        sn = seq_num
        header_len = 5
        reservered = 0
        ack_num = 0

        #flags
        urg = 0
        ack_flag = 0
        psh = 0
        rst = 0
        syn = 1
        fin = 0
        flags = (urg << 5) + (ack_flag << 4) + (psh << 3) + (rst << 2) + (syn << 1) + fin

        header_flags = (header_len << 12) + flags
        checksum = 0
        urgent_pointer = 0
        tcp_header = pack('!HHIIHHHH', src_port, dst_port, sn, ack_num, header_flags, window_size, checksum, urgent_pointer)

        protocol = socket.IPPROTO_TCP
        pseudo_header = pack('!4s4sBBH', src_ip, dst_ip, 0, protocol, len(tcp_header))


        header = pseudo_header + tcp_header
        checksum = Crafter.get_checksum(header)

        return pack('!HHIIHHHH', src_port, dst_port, sn, ack_num, header_flags, window_size, checksum, urgent_pointer)


    @staticmethod
    def get_tcp_packet(src_ip, src_port, dst_ip, dst_port):
        seq_num = random.randint(1000, 0xFFFFFFFF - 1)
        ip_header = Crafter.get_ip_header(src_ip, dst_ip)
        tcp_header = Crafter.get_tcp_header(src_ip, src_port, dst_ip, dst_port, seq_num)

        return ip_header + tcp_header, seq_num


    @staticmethod
    def unpack_tcp(tcp_packet):
        tcp_header = unpack('!HHIIHHHH', tcp_packet)
        src_port = int(tcp_header[0])
        dst_port = int(tcp_header[1])
        ack_num = int(tcp_header[3])
        rst_flag = (tcp_header[4] & 0x4) >> 2

        return TCP_data(src_port, dst_port, ack_num, rst_flag)


    @staticmethod
    def unpack_ip(packet):
        eth_len = 0
        mac_header = packet[:eth_len]
        ip_header = packet[eth_len: 20 + eth_len]
        ip_header = unpack('!BBHHHBBH4s4s', ip_header)
        ip_header_len = (ip_header[0] & 0xF) * 4
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])

        return IP_data(ip_header_len, src_ip, dst_ip)