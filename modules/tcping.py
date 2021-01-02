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
    State.UNREACHABLE: 'Host unreachable',
    State.OK: 'Ok',
    State.NOT_ALLOWED: 'Not allowed'
}

Packet = namedtuple('Packet', ['all', 'ip', 'tcp'])

# TODO: Обрабатывать несколько пар (ip, port) - список этих пар и по каждой паре отправляять пакеты
class TCPing:
    def __init__(self, hide_succ_pings=False):
        self.network = Network()
        self.hide_succ_pings = hide_succ_pings
        self.dns = {}

    @staticmethod
    def get_formatted_time(t):
        return '{:.4f}'.format(t)

    @staticmethod
    def get_formatted_addr(addr):
        return f'{addr[0]}:{addr[1]}'

    def get_formatted_result(self, result):
        if result.state == State.TIMEOUT or result.state == State.ERROR:
            return STATES_NAMES[result.state]
        formatted_time = self.get_formatted_time(result.response_time)
        addr = result.addr
        url = self.get_url(result.addr[0])
        if url:
            addr = (url, result.addr[1])
        formatted_addr = self.get_formatted_addr(addr)

        return f'{STATES_NAMES[result.state]} ' \
            f'{formatted_time} {formatted_addr}'

    def update_dns(self, ip, url):
        self.dns.update({ip: url})

    def get_url(self, ip):
        if ip in self.dns:
            return self.dns[ip]

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
                return State.NOT_ALLOWED, time.monotonic() - start_time
            else:
                return State.OK, time.monotonic() - start_time

    def handle_icmp(self, recvd_icmp, src_ip, start_time):
        icmp_data = unpack_icmp(recvd_icmp)
        if self.is_unreachable(icmp_data.type):
            IP = unpack_ip(icmp_data.load)
            if (src_ip.src == IP.src and
                src_ip.dst == IP.dst):
                return State.UNREACHABLE, time.monotonic() - start_time
        else:
            return State.OK, time.monotonic() - start_time

    def handle_packet(self, data, src_pack, start_time):
        IP = unpack_ip(data)
        result = None

        if IP.proto == Protos.TCP:
            if self.is_ip_packets_matches(src_pack.ip, IP):
                recvd_tcp = unpack_tcp(IP.load[0: 20])
                result = self.handle_tcp(recvd_tcp, src_pack.tcp, start_time)

        if IP.proto == Protos.ICMP:
            result = self.handle_icmp(IP.load, src_pack.ip, start_time)

        if result:
            state, elapsed_time = result
            return Result(
                state, 
                elapsed_time, 
                (src_pack.ip.dst, src_pack.tcp.dport))

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

        if ip != dst_ip:
            self.update_dns(dst_ip, ip)

        return Packet(packet, ip_pack, tcp_pack)

    def get_result(self, match_packs, timeout):
        result = []
        packets, elapsed_time = self.network.recv(timeout)

        # Удаляем пакеты, которые уже превысили время ответа
        packets_to_delete = []
        for match_pack in match_packs:
            start_time = match_packs[match_pack][0]
            pack_resp = match_packs[match_pack][1] - elapsed_time
            match_packs[match_pack] = (start_time, pack_resp)

            if pack_resp <= 0:
                result.append(
                    Result(
                        State.TIMEOUT, 
                        None, 
                        (match_pack.ip.dst, match_pack.tcp.dport)))
                packets_to_delete.append(match_pack)
                continue

        for match_pack in packets_to_delete:
            del match_packs[match_pack]
        packets_to_delete.clear()

        if not packets:
            return result, elapsed_time

        # Смотрим какие пакеты нам подходят
        for pack in packets:
            for match_pack in match_packs:
                start_time = match_packs[match_pack][0]
                res = self.handle_packet(
                    pack,
                    match_pack,
                    start_time)

                if res:
                    result.append(res)
                    packets_to_delete.append(match_pack)

            # Удаляем пакеты, на которые есть ответ
            for match_pack in packets_to_delete:
                del match_packs[match_pack]

        return result, elapsed_time

    def ping(self, addrs, packets_amount, send_interval, response_time):
        result = []
        inited = False
        stat = Stat()
        match_packs = {}
        curr_interval = 0
        send_counter = 0
        timeout = min(response_time, send_interval)

        while True:
            # Если интервал прошел, то отправляем снова
            if curr_interval <= 0 and send_counter < packets_amount:
                curr_interval = send_interval

                send_packs = []
                for addr in addrs:
                    packet = self.get_send_packet(addr[0], int(addr[1]))

                    if not packet:
                        print(self.get_formatted_result(
                            Result(State.ERROR, None, addr)))

                    send_packs.append(packet)

                for pack in send_packs:
                    self.network.send(pack.all, (pack.ip.dst, pack.tcp.dport))
                    match_packs.update({pack: (time.monotonic(), response_time)})

                send_counter += 1

            if send_counter == packets_amount and not match_packs:
                break

            # Выбираем таймаут чтения данных
            if curr_interval != 0:
                timeout = curr_interval
            for match_pack in match_packs:
                timeout = min(match_packs[match_pack][1], timeout)

            results, elapsed_time = self.get_result(match_packs, timeout)
            curr_interval -= elapsed_time

            for result in results:
                stat.update(result)

                if result.state == State.OK and self.hide_succ_pings:
                    continue

                print(self.get_formatted_result(result))

        print(stat.get_formatted_result())
