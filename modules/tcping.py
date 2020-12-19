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
from .structures import *


STATES_NAMES = {
    State.ABORTED: 'Aborted',
    State.OK: 'Ok',
    State.NOT_ALLOWED: 'Not allowed'
}


class TCPing():
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

    def handle_icmp(self, packet, start_time):
        icmp_type = packet[0]

        if self.is_unreachable(icmp_type):
            return Result(State.NOT_ALLOWED, time.monotonic() - start_time)
        else:
            return Result(State.OK, time.monotonic() - start_time)

    def get_result(
        self,
        s_tcp,
        s_icmp,
        src_ip,
        src_tcp,
        response_time,
        start_time=time.monotonic()):
        while True:
            readers, _, _ = select.select([s_tcp, s_icmp], [], [])

            if time.monotonic() - start_time > response_time:
                return Result(State.ABORTED, time.monotonic() - start_time)

            for reader in readers:
                data, addr = reader.recvfrom(65565)
                ip_data = unpack_ip(data)
                ip_load = data[ip_data.len:]
                res = None

                if self.is_ip_packets_matches(src_ip, ip_data):
                    if reader is s_tcp:
                        recvd_tcp = unpack_tcp(ip_load[0: 20])
                        res = self.handle_tcp(recvd_tcp, src_tcp, start_time)

                    if reader is s_icmp:
                        res = self.handle_icmp(ip_load, start_time)

                    if res:
                        return res

    def get_response(self, ip, port, result, response_time):
        dst_ip = ip
        dst_port = port
        s_icmp = self.get_socket(socket.IPPROTO_ICMP)
        s_tcp = self.get_socket(socket.IPPROTO_TCP)

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
        src_ip = IP_data(0, src_ip, dst_ip)
        s_tcp.sendto(packet, (dst_ip, dst_port))
        start_time = time.monotonic()

        with s_tcp:
            with s_icmp:
                res = self.get_result(
                        s_tcp,
                        s_icmp,
                        src_ip,
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
