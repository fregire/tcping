import unittest
import socket
from modules.crafter import *

#TCP packet
SRC_IP = '192.168.0.106'
DST_IP = '51.75.74.114'
SPORT = 41932
DPORT = 80
SEQ = 2578989655
WINDOW_SIZE = 64240
TCP_HEADER = b'\xa3\xcc\x00P\x99\xb8BW\x00\x00\x00\x00P\x02\xfa\xf0\xf5\xf5\x00\x00'

# IP packet
PROTO = socket.IPPROTO_TCP
TTL = 255
CHECKSUM = 0
IP_FLAGS = 2
IP_LEN = 20
VERSION=4
ID=1
IHL=5
IP_HEADER = b'E\x00\x00\x14\x00\x01@\x00\xff\x06\x00\x00\xc0\xa8\x00j3KJr'

FULL_PACKET = IP_HEADER + TCP_HEADER


# ICMP packet
ICMP_REPLY = b'\x00\x00\x2f\x4c\x00\x01\x00\x01\x5c\xde\xe6\x5f\x00\x00\x00\x00\xca\xa0\x04\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'
ICMP_UNREACHABLE = b'\x03\x01\x7f\x41\x00\x00\x00\x00\x45\x00\x00\x28\x00\x01\x40\x00\xff\x06\xf9\xa6\xc0\xa8\x00\x6b\xc0\xa8\x00\x6c\xcc\x47\x00\x5a\xc4\x87\x52\x45\x00\x00\x00\x00\x50\x02\xfa\xf0\x4f\x5b\x00\x00'


class TestCrafter(unittest.TestCase):
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
        actual = get_tcp_header(
            SRC_IP,
            SPORT,
            DST_IP,
            DPORT,
            SEQ,
            WINDOW_SIZE)

        self.assertEqual(actual, TCP_HEADER)

    def test_unpack_tcp(self):
        ack = SEQ + 1
        result = unpack_tcp(TCP_HEADER)

        self.assertEqual(result.sport, SPORT)
        self.assertEqual(result.dport, DPORT)
        self.assertEqual(result.ack, 0)
        self.assertEqual(result.rst, 0)

    def test_ip_crafting(self):
        result = get_ip_header(SRC_IP, DST_IP)

        self.assertEqual(result, IP_HEADER)

    def test_packet_crafting(self):
        result = get_tcp_packet(SRC_IP, SPORT, DST_IP, DPORT, SEQ)

        self.assertEqual(result[0], FULL_PACKET)

    def test_unpack_ip(self):
        ip_len = 20
        result = unpack_ip(IP_HEADER)

        self.assertEqual(result.len, IP_LEN)
        self.assertEqual(result.src, SRC_IP)
        self.assertEqual(result.dst, DST_IP)

    def test_unpack_icmp(self):
        result = unpack_icmp(ICMP_REPLY)

        self.assertEqual(result.type, 0)
        self.assertEqual(result.load, b'')

        result = unpack_icmp(ICMP_UNREACHABLE)

        self.assertEqual(result.type, 3)
        self.assertEqual(result.load, ICMP_UNREACHABLE[8:])

if __name__ == '__main__':
    unittest.main()
