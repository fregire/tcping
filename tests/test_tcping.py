from modules import crafter
import unittest
from scapy.all import *
import socket
from modules import tcping
from modules.structures import *
from scapy.all import *


AVAILABLE_TYPE = 0
UNREACHABLE_TYPE = 3
SRC_PORT = 123
DST_PORT = 321
SEQ = 456
ACK = SEQ + 1
RST = 0
REQUEST = TCP_data(SRC_PORT, DST_PORT, ACK, RST)


class TestTCPing(unittest.TestCase):
    def setUp(self):
        self.tcping = tcping.TCPing()

    def get_sock(self, sock_proto):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setblocking(0)

        return s

    def test_formatted_result(self):
        aborted_result = Result(State.ABORTED, 10)
        result = Result(State.OK, 10)

        self.assertEqual(
            self.tcping.get_formatted_result(aborted_result),
            'Aborted')
        self.assertEqual(
            self.tcping.get_formatted_result(result),
            'Ok 10')

    def test_unreachable_port(self):
        self.assertEqual(
            self.tcping.is_unreachable(UNREACHABLE_TYPE),
            True)
        self.assertEqual(
            self.tcping.is_unreachable(5),
            False)

    def tcp_matches(self, response, expected_res):
        self.assertEqual(
            self.tcping.is_tcp_packets_matches(REQUEST, response),
            expected_res)

    def test_tcp_matching(self):
        self.tcp_matches(TCP_data(DST_PORT, SRC_PORT, ACK, RST), True)
        self.tcp_matches(TCP_data(DST_PORT, SRC_PORT - 2, ACK, RST), False)
        self.tcp_matches(TCP_data(DST_PORT, SRC_PORT, ACK + 2, RST), False)
        self.tcp_matches(TCP_data(DST_PORT - 2, SRC_PORT, ACK, RST), False)

    def handle_tcp(self, response, expected_res):
        res = self.tcping.handle_tcp(response, REQUEST, 0)
        res_state = None
        if res:
            res_state = res.state

        self.assertEqual(
            res_state,
            expected_res)

    def test_handle_tcp(self):
        self.handle_tcp(
            TCP_data(DST_PORT, SRC_PORT, ACK, RST),
            State.OK)
        self.handle_tcp(
            TCP_data(DST_PORT, SRC_PORT, ACK, 1),
            State.NOT_ALLOWED)
        self.handle_tcp(
            TCP_data(DST_PORT, SRC_PORT, 90, 0),
            None)

    def test_handle_icmp(self):
        start_time = 0
        unreachable_packet = raw(ICMP(type=UNREACHABLE_TYPE))
        available_packet = raw(ICMP(type=AVAILABLE_TYPE))

        res = self.tcping.handle_icmp(unreachable_packet, start_time)
        self.assertEqual(res.state, State.NOT_ALLOWED)

        res = self.tcping.handle_icmp(available_packet, start_time)
        self.assertEqual(res.state, State.OK)
