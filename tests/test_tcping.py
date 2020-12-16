from modules import crafter
import unittest
from scapy.all import *
import socket
from modules import tcping
from modules.structures import *


UNREACHABLE_TYPE = 3


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


	def test_tcp_matching(self):
		src_port, dst_port, seq = 123, 321, 456
		ack = seq + 1
		rst = 0

		request = TCP_data(src_port, dst_port, ack, rst)
		response = TCP_data(dst_port, src_port, ack, rst)

		self.assertEqual(
			self.tcping.is_tcp_packets_matches(request, response),
			True)

		response = TCP_data(dst_port, src_port - 2, ack, rst)
		self.assertEqual(
			self.tcping.is_tcp_packets_matches(request, response),
			False)

		response = TCP_data(dst_port, src_port, ack + 2, rst)
		self.assertEqual(
			self.tcping.is_tcp_packets_matches(request, response),
			False)

		response = TCP_data(dst_port - 2, src_port, ack, rst)
		self.assertEqual(
			self.tcping.is_tcp_packets_matches(request, response),
			False)