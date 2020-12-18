from modules import crafter
import unittest
from scapy.all import IP,TCP,ICMP,raw
import socket

SRC_IP = '192.168.0.106'
DST_IP = '51.75.74.114'
SRC_PORT = 41932
DST_PORT = 80
SEQ = 2578989655
WINDOW_SIZE = 64240
PROTO = socket.IPPROTO_TCP
TTL = 255
CHECKSUM = 0
IP_FLAGS = 2


class TestCrafter(unittest.TestCase):
    def setUp(self):
        self.crafter = crafter.Crafter()

    def get_ip_packet(self):
        return IP(
            src=SRC_IP,
            dst=DST_IP,
            flags=IP_FLAGS,
            ttl=TTL,
            proto=PROTO,
            chksum=CHECKSUM,
            len=20,
            ihl=5)

    def test_tcp_crafting(self):
        actual = self.crafter.get_tcp_header(
            SRC_IP,
            SRC_PORT,
            DST_IP,
            DST_PORT,
            SEQ,
            WINDOW_SIZE)
        expected = IP(src=SRC_IP, dst=DST_IP)/TCP(
            seq=SEQ, dport=DST_PORT, sport=SRC_PORT, window=WINDOW_SIZE)

        self.assertEqual(actual, raw(expected[TCP]))

    def test_ip_crafting(self):
        actual = self.crafter.get_ip_header(SRC_IP, DST_IP, PROTO)
        expected = self.get_ip_packet()

        self.assertEqual(actual, raw(expected))

    def test_unpack_tcp(self):
        ack = SEQ + 1
        packet = TCP(ack=ack, dport=DST_PORT, sport=SRC_PORT, flags=4)
        result = self.crafter.unpack_tcp(raw(packet))

        self.assertEqual(result.src_port, SRC_PORT)
        self.assertEqual(result.dst_port, DST_PORT)
        self.assertEqual(result.ack, ack)
        self.assertEqual(result.rst, 1)

    def test_unpack_ip(self):
        ip_len = 20
        packet = IP(src=SRC_IP, dst=DST_IP, len=ip_len)
        result = self.crafter.unpack_ip(raw(packet))

        self.assertEqual(result.len, ip_len)
        self.assertEqual(result.src_ip, SRC_IP)
        self.assertEqual(result.dst_ip, DST_IP)


if __name__ == '__main__':
    unittest.main()
