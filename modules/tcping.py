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
from .structures import TCP, IP, Result, State, Protos
from .network import Network


STATES_NAMES = {
    State.TIMEOUT: 'Timeout',
    State.ERROR: 'Something goes wrong',
    State.OK: 'Ok',
    State.NOT_ALLOWED: 'Not allowed'
}

Packet = namedtuple('Packet', ['all', 'ip', 'tcp'])


class TCPing:
    def __init__(self):
        self.network = Network()

    @staticmethod
    def get_formatted_result(result):
        if result.state == State.TIMEOUT or result.state == State.ERROR:
            return STATES_NAMES[result.state]

        return f'{STATES_NAMES[result.state]} {result.response_time}'

    @staticmethod
    def get_curr_addr(dst_ip, dport):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((dst_ip, dport))
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
    def is_tcp_packets_matches(request, response):
        return (request.ack == response.ack and
                request.sport == response.dport and
                request.dport == response.sport)

    @staticmethod
    def is_ip_packets_matches(request, response):
        return (request.src == response.dst and
                request.dst == response.src)

    def handle_tcp(self, recvd_tcp, src_tcp, start_time):
        if self.is_tcp_packets_matches(src_tcp, recvd_tcp):
            if recvd_tcp.rst:
                return Result(State.NOT_ALLOWED, time.monotonic() - start_time)
            else:
                return Result(State.OK, time.monotonic() - start_time)

    def handle_icmp(self, recvd_icmp, src_ip, start_time):
        icmp_data = unpack_icmp(recvd_icmp)
        if self.is_unreachable(icmp_data.type):
            IP = unpack_ip(icmp_data.load)
            if (src_ip.src == IP.src and
                src_ip.dst == IP.dst):
                return Result(State.NOT_ALLOWED, time.monotonic() - start_time)
        else:
            return Result(State.OK, time.monotonic() - start_time)

    def handle_packet(self, data, src_pack, start_time):
        IP = unpack_ip(data)
        result = None
        if IP.proto == Protos.TCP:
            if self.is_ip_packets_matches(src_pack.ip, IP):
                recvd_tcp = unpack_tcp(IP.load[0: 20])
                result = self.handle_tcp(recvd_tcp, src_pack.tcp, start_time)

        if IP.proto == Protos.ICMP:
            result = self.handle_icmp(IP.load, src_pack.ip, start_time)

        return result

    def get_send_packet(self, ip, port):
        dst_ip = ip
        dport = port

        try:
            dst_ip = socket.gethostbyname(dst_ip)
        except socket.gaierror:
            return None

        src_ip, sport = self.get_curr_addr(dst_ip, dport)
        packet, seq_num = get_tcp_packet(
            src_ip,
            sport,
            dst_ip,
            dport)
        ack_num = seq_num + 1
        ip_pack = IP(0, 6, src_ip, dst_ip, b'')
        tcp_pack = TCP(sport, dport, ack_num, 0)

        return Packet(packet, ip_pack, tcp_pack)

    def ping(self, ip, port, packets_amount, send_interval, response_time):
        result = []
        inited = False
        stat = Stat()
        match_packs = {}
        curr_interval = 0
        send_counter = 0
        timeout = min(response_time, send_interval)

        while True:
            if curr_interval <= 0 and send_counter < packets_amount:
                curr_interval = send_interval
                packet = self.get_send_packet(ip, port)

                if not packet:
                    print(self.get_formatted_result(Result(State.ERROR, 0)))

                self.network.send(packet.all, (ip, port))
                match_packs.update({packet: (time.monotonic(), response_time)})
                send_counter += 1

            if send_counter == packets_amount and not match_packs:
                break

            # Выбираем таймаут чтения данных
            if curr_interval != 0:
                timeout = curr_interval
            for match_pack in match_packs:
                timeout = min(match_packs[match_pack][1], timeout)

            # Получаем пакеты с таймаутом
            packets, elapsed_time = self.network.recv(timeout)
            curr_interval -= elapsed_time

            # Удаляем пакеты, которые уже превысили время ответа
            packets_to_delete = []
            for match_pack in match_packs:
                start_time = match_packs[match_pack][0]
                pack_resp = match_packs[match_pack][1] - elapsed_time
                match_packs[match_pack] = (start_time, pack_resp)

                if pack_resp <= 0:
                    print(self.get_formatted_result(
                        Result(State.TIMEOUT, 0)))
                    packets_to_delete.append(match_pack)
                    continue

            for match_pack in packets_to_delete:
                del match_packs[match_pack]
            packets_to_delete.clear()

            if not packets:
                continue

            # Смотрим какие пакеты нам подходят
            for pack in packets:
                for match_pack in match_packs:
                    start_time = match_packs[match_pack][0]
                    res = self.handle_packet(
                        pack,
                        match_pack,
                        start_time)

                    if res:
                        packets_to_delete.append(match_pack)
                        print(self.get_formatted_result(res))

                # Удаляем пакеты, на которые есть ответ
                for match_pack in packets_to_delete:
                    del match_packs[match_pack]
