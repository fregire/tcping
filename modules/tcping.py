from struct import pack, unpack
import socket
import sys
import random
import time
import select
import argparse
from collections import namedtuple
import threading
import statistics
from .crafter import Crafter
from .statistics import Stat
from .structures import *


def show_result(result):
    if result.state == State.ABORTED:
        print(result.state)
    else:
        print(result.state, result.response_time)


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


def is_unreachable(icmp_packet):
    icmp_type = icmp_packet[0]

    return icmp_type == 3


def get_socket(sock_proto):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto)
    s.setblocking(0)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    return s


def is_tcp_packets_matches(request, response):
    return (request.ack == response.ack and
            request.src_port == response.dst_port and 
            request.dst_port == response.src_port)


def is_ip_packets_matches(request, response):
    return request.src_ip == response.dst_ip and request.dst_ip == response.src_ip


def get_result(
    s_tcp, 
    s_icmp, 
    src_ip, 
    src_tcp, 
    result, 
    response_time, 
    start_time=time.monotonic()):

    while True:
        readers, _, _ = select.select([s_tcp, s_icmp], [], [])

        if time.monotonic() - start_time > response_time:
            return Result(State.ABORTED, time.monotonic() - start_time)

        for reader in readers:
            data = reader.recvfrom(65565)
            ip_data = Crafter.unpack_ip(data[0])
            data = data[0][ip_data.len:]

            if is_ip_packets_matches(src_ip, ip_data):
                if reader is s_tcp:
                    recvd_tcp = Crafter.unpack_tcp(data[0: 20])

                    if is_tcp_packets_matches(src_tcp, recvd_tcp):
                        if recvd_tcp.rst:
                            return Result(State.NOT_ALLOWED, time.monotonic() - start_time)
                        else:
                            return Result(State.OK, time.monotonic() - start_time)

                if reader is s_icmp:
                    if is_unreachable(data):
                        return Result(State.NOT_ALLOWED, time.monotonic() - start_time)
                    else:
                        return Result(State.OK, time.monotonic() - start_time)


def get_response(ip, port, result, response_time):
    dst_ip = ip
    dst_port = port
    s_icmp = get_socket(socket.IPPROTO_ICMP)
    s_tcp = get_socket(socket.IPPROTO_TCP)
    s_icmp.setblocking(0)
    s_tcp.setblocking(0)

    try:
        dst_ip = socket.gethostbyname(dst_ip)
    except socket.gaierror:
        result.append(ABORTED)
        return

    src_ip, src_port = get_curr_addr(dst_ip, dst_port)
    packet, seq_num = Crafter.get_tcp_packet(src_ip, src_port, dst_ip, dst_port)
    ack_num = seq_num + 1
    src_tcp = TCP_data(src_port, dst_port, ack_num, 0)
    src_ip = IP_data(0, src_ip, dst_ip)
    s_tcp.sendto(packet, (dst_ip, dst_port))
    start_time = time.monotonic()

    with s_tcp:
        with s_icmp:
            if time.monotonic() - start_time <= response_time:
                result.append(get_result(
                    s_tcp, 
                    s_icmp, 
                    src_ip, 
                    src_tcp, 
                    result, 
                    response_time,
                    start_time))

            

def tcping(ip, port, packets_amount, send_interval, response_time):
    result = []
    inited = False
    stat = Stat()

    for _ in range(packets_amount):
        if inited:
            time.sleep(send_interval)
        else:
            inited = True

        th = threading.Thread(target=get_response, args=(ip, port, result, response_time))
        th.daemon = True
        th.start()
        th.join(timeout=response_time)

        repsonse_res = Result(State.ABORTED, 0)

        if result:
            repsonse_res = result[0]

        stat.update(repsonse_res)
        show_result(repsonse_res)


        result.clear()
    
    print(stat.get_formatted_res())