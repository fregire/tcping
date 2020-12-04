from struct import pack, unpack
import socket
import sys
import random
import time
import select
import argparse
from collections import namedtuple


NOT_ALLOWED = "Not allowed"
OK = "OK"
ABORTED = "Aborted"

TCP_data = namedtuple('TCP_data', ['src_port', 'dst_port', 'ack', 'rst'])
IP_data = namedtuple('IP_data', ['len', 'src_ip', 'dst_ip'])


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


def get_ip_header(src_ip, dst_ip):
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
    proto = socket.IPPROTO_TCP
    checksum = 0
    src_ip = socket.inet_aton(src_ip)
    dst_ip = socket.inet_aton(dst_ip)

    packet_without_checksum = pack(IP_HEADER_MASK, version_ihl, dscp_ecn, packet_len, identificator, flags_offset, ttl, proto, checksum, src_ip, dst_ip)

    return packet_without_checksum


def get_tcp_header(src_ip,  src_port, dst_ip, dst_port, seq_num):
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
    window_size = 64240
    checksum = 0
    urgent_pointer = 0
    tcp_header = pack('!HHIIHHHH', src_port, dst_port, sn, ack_num, header_flags, window_size, checksum, urgent_pointer)

    protocol = socket.IPPROTO_TCP
    pseudo_header = pack('!4s4sBBH', src_ip, dst_ip, 0, protocol, len(tcp_header))


    header = pseudo_header + tcp_header
    checksum = get_checksum(header)

    return pack('!HHIIHHHH', src_port, dst_port, sn, ack_num, header_flags, window_size, checksum, urgent_pointer)


def get_packet(src_ip, src_port, dst_ip, dst_port):
    seq_num = random.randint(1000, 0xFFFFFFFF)
    ip_header = get_ip_header(src_ip, dst_ip)
    tcp_header = get_tcp_header(src_ip, src_port, dst_ip, dst_port, seq_num)

    return ip_header + tcp_header, seq_num


def get_curr_addr(dst_ip, dst_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, dst_port))
        ip = s.getsockname()[0]
        port = s.getsockname()[1]
    except Exception:
        ip = '127.0.0.1'
        port = 6
    finally:
        s.close()

    return ip, port

def unpack_tcp(tcp_packet):
    tcp_header = unpack('!HHIIHHHH', tcp_packet)
    src_port = int(tcp_header[0])
    dst_port = int(tcp_header[1])
    ack_num = int(tcp_header[3])
    rst_flag = (tcp_header[4] & 0x4) >> 2

    return TCP_data(src_port, dst_port, ack_num, rst_flag)


def is_unreachable(icmp_packet):
    icmp_type = icmp_packet[0]

    return icmp_type == 3


def unpack_ip(packet):
    eth_len = 0
    mac_header = packet[:eth_len]
    ip_header = packet[eth_len: 20 + eth_len]
    ip_header = unpack('!BBHHHBBH4s4s', ip_header)
    ip_header_len = (ip_header[0] & 0xF) * 4
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])

    return IP_data(ip_header_len, src_ip, dst_ip)



def tcping(ip, port, time_to_abort_s):
    dst_ip = ip
    dst_port = port
    s_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s_tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s_tcp.setblocking(0)
    s_icmp.setblocking(0)
    s_tcp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s_icmp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        dst_ip = socket.gethostbyname(dst_ip)
    except socket.gaierror:
        return ABORTED

    src_ip, src_port = get_curr_addr(dst_ip, dst_port)
    packet, seq_num = get_packet(src_ip, src_port, dst_ip, dst_port)
    ack_num = seq_num + 1

    start = time.monotonic()
    s_tcp.sendto(packet, (dst_ip, dst_port))

    while True:
        ## Start checking time
        elapsed = time.monotonic() - start
        if elapsed > time_to_abort_s:
            return ABORTED
        ## End checking time

        readers, _, _ = select.select([s_tcp, s_icmp], [], [])

        for reader in readers:
            ## Start checking time
            elapsed = time.monotonic() - start
            if elapsed > time_to_abort_s:
                return ABORTED
            ## End checking timeout

            data = reader.recvfrom(65565)
            ip_data = unpack_ip(data[0])
            data = data[0][ip_data.len:]

            if src_ip == ip_data.dst_ip and dst_ip == ip_data.src_ip:
                if reader is s_tcp:
                    recvd_tcp = unpack_tcp(data[0: 20])

                    if recvd_tcp.ack == ack_num and recvd_tcp.dst_port == src_port and recvd_tcp.src_port == dst_port:
                        if recvd_tcp.rst:
                            return NOT_ALLOWED
                        else:
                            return OK
                        return

                if reader is s_icmp:
                    if is_unreachable(data):
                        return NOT_ALLOWED
                    else:
                        return OK

                    return
            ## Start checking time
            elapsed = time.monotonic() - start
            if elapsed > time_to_abort_s:
                return ABORTED
            ## End checking time
