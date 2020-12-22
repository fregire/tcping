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
from .crafter import *
from .statistics import Stat
from .structures import TCP_data, IP_data, Result, State, Protos
from .network import Network


STATES_NAMES = {
    State.ABORTED: 'Aborted',
    State.OK: 'Ok',
    State.NOT_ALLOWED: 'Not allowed'
}


class TCPing:
    def __init__(self):
        self.network = Network()

    @staticmethod
    def get_formatted_result(result):
        if result.state == State.ABORTED:
            return STATES_NAMES[result.state]

        return f'{STATES_NAMES[result.state]} {result.response_time}'

    @staticmethod
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

    @staticmethod
    def is_unreachable(icmp_type):
        return icmp_type == 3

    @staticmethod
    def get_socket(sock_proto):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setblocking(0)

        return s

    @staticmethod
    def is_tcp_packets_matches(request, response):
        return (request.ack == response.ack and
                request.src_port == response.dst_port and
                request.dst_port == response.src_port)

    @staticmethod
    def is_ip_packets_matches(request, response):
        return (request.src_ip == response.dst_ip and
                request.dst_ip == response.src_ip)

    def handle_tcp(self, recvd_tcp, src_tcp, start_time):
        if self.is_tcp_packets_matches(src_tcp, recvd_tcp):
            if recvd_tcp.rst:
                return Result(State.NOT_ALLOWED, time.monotonic() - start_time)
            else:
                return Result(State.OK, time.monotonic() - start_time)

    def handle_icmp(self, recvd_icmp, src_ip, start_time):
        icmp_data = unpack_icmp(recvd_icmp)
        if self.is_unreachable(icmp_data.type):
            ip_data = unpack_ip(icmp_data.load)
            if (src_ip.src_ip == ip_data.src_ip and
                src_ip.dst_ip == ip_data.dst_ip):
                return Result(State.NOT_ALLOWED, time.monotonic() - start_time)
        else:
            return Result(State.OK, time.monotonic() - start_time)

    def handle_packet(self, data, src_ip, src_tcp, start_time):
        ip_data = unpack_ip(data)
        result = None

        if ip_data.proto == Protos.TCP:
            if self.is_ip_packets_matches(src_ip, ip_data):
                recvd_tcp = unpack_tcp(ip_data.load[0: 20])
                result = self.handle_tcp(recvd_tcp, src_tcp, start_time)

        if ip_data.proto == Protos.ICMP:
            result = self.handle_icmp(ip_data.load, src_ip, start_time)

        if result:
            return result

    def get_result(
        self,
        src_ip,
        src_tcp,
        response_time,
        start_time=time.monotonic()):

        while True:
            if time.monotonic() - start_time > response_time:
                return Result(State.ABORTED, time.monotonic() - start_time)
            recvd = self.network.recv()
            if recvd:
                data, addr = recvd
            else:
                continue

            res = self.handle_packet(data, src_ip, src_tcp, start_time)

            if res:
                return res

    def get_response(self, ip, port, result, response_time):
        dst_ip = ip
        dst_port = port

        try:
            dst_ip = socket.gethostbyname(dst_ip)
        except socket.gaierror:
            result.append(Result(State.ABORTED, 0))
            return

        src_ip, src_port = self.get_curr_addr(dst_ip, dst_port)
        packet, seq_num = get_tcp_packet(
            src_ip,
            src_port,
            dst_ip,
            dst_port)
        ack_num = seq_num + 1
        src_tcp = TCP_data(src_port, dst_port, ack_num, 0)
        src_ip_packet = IP_data(0, 6, src_ip, dst_ip, b'')
        self.network.send(packet, (dst_ip, dst_port))
        start_time = time.monotonic()

        res = self.get_result(
                src_ip_packet,
                src_tcp,
                response_time,
                start_time)

        if time.monotonic() - start_time <= response_time:
            result.append(res)

    def ping(self, ip, port, packets_amount, send_interval, response_time):
        result = []
        inited = False
        stat = Stat()
        # мин времея отправки и интервала отправки через селект с временем
        for _ in range(packets_amount):
            if inited:
                time.sleep(send_interval)
            else:
                inited = True

            th = threading.Thread(
                target=self.get_response,
                args=(ip, port, result, response_time),
                daemon=True)
            th.start()
            th.join(timeout=response_time)

            repsonse_res = Result(State.ABORTED, 0)

            if result:
                repsonse_res = result[0]

            stat.update(repsonse_res)
            print(self.get_formatted_result(repsonse_res))

            result.clear()

        print(stat.get_formatted_res())
