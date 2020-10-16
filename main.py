from struct import pack
import socket
import sys
import scapy


def get_checksum(header):

	return 0



def get_ip_header(src_ip, dest_ip):
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
	dest_ip = socket.inet_aton(dest_ip)

	packet_without_checksum = pack(IP_HEADER_MASK, version_ihl, dscp_ecn, packet_len, identificator, flags_offset, ttl, proto, checksum, src_ip, dest_ip)

	return packet_without_checksum


def get_tcp_header(source_ip,  source_port, dest_ip, dest_port):
	source_ip = socket.inet_aton(source_ip)
	dest_ip = socket.inet_aton(dest_ip)

	sn = 0
	ack = 0
	header_len = 5
	reservered = 0

	#flags
	urg = 0
	ack = 0
	psh = 0
	rst = 0
	syn = 1
	fin = 0
	flags = (urg << 5) + (ack << 4) + (psh << 3) + (rst << 2) + (syn << 1) + fin

	header_flags = (header_len << 12) + flags
	window_size = 64240
	checksum = 0
	urgent_pointer = 0
	tcp_header = pack('!HHIIHHHH', source_port, dest_port, sn, ack, header_flags, window_size, checksum, urgent_pointer)

	protocol = socket.IPPROTO_TCP
	pseudo_header = pack('!4s4sBBH', source_ip, dest_ip, 0, protocol, len(tcp_header))

	header = pseudo_header + tcp_header
	checksum = get_checksum(header)

	return pack('!HHIIHHHH', source_port, dest_port, sn, ack, header_flags, window_size, checksum, urgent_pointer)


def parse_args():
	args = sys.argv
	ip = args[1]
	port = None

	if len(args) > 2:
		port = args[2]

	return ip, port


def main():
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	dest_ip = '64.233.165.139'
	dest_port = 80
	src_ip = '192.168.106'
	src_port = 3228
	packet = get_ip_header(src_ip, dest_ip) + get_tcp_header(src_ip, src_port, dest_ip, dest_port)
	print(packet)

	s.sendto(packet, (dest_ip, dest_port))


if __name__ == '__main__':
	main()