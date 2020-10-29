from struct import pack
import socket
import sys

	
def get_checksum(header):
	s = 0
	hex_header = int(header.hex(), 16)
	while hex_header > 0:
		s += hex_header & 0xFFFF
		hex_header = hex_header >> 16

	result = 0
	while s > 0:
		result += s & 0xFFFF
		s = s >> 16
	result ^= 0xFFFF
	
	return result


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


def get_tcp_header(src_ip,  src_port, dest_ip, dest_port):
	src_ip = socket.inet_aton(src_ip)
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
	tcp_header = pack('!HHIIHHHH', src_port, dest_port, sn, ack, header_flags, window_size, checksum, urgent_pointer)

	protocol = socket.IPPROTO_TCP
	pseudo_header = pack('!4s4sBBH', src_ip, dest_ip, 0, protocol, len(tcp_header))


	header = pseudo_header + tcp_header
	checksum = get_checksum(header)

	return pack('!HHIIHHHH', src_port, dest_port, sn, ack, header_flags, window_size, checksum, urgent_pointer)


def parse_args():
	args = sys.argv
	ip = args[1]
	port = None

	if len(args) > 2:
		port = args[2]

	return ip, int(port)


def get_packet(src_ip, src_port, dest_ip, dest_port):
	ip_header = get_ip_header(src_ip, dest_ip)
	tcp_header = get_tcp_header(src_ip, src_port, dest_ip, dest_port)

	return ip_header + tcp_header


def get_curr_addr():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	random_ip = '10.255.255.255'
	random_port = 0
	try:
	    # doesn't even have to be reachable
	    s.connect((random_ip, random_port))
	    IP = s.getsockname()[0]
	    PORT = s.getsockname()[1]
	except Exception:
	    IP = '127.0.0.1'
	    PORT = 6
	finally:
	    s.close()

	return IP, PORT

def main():
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	dest_ip, dest_port = parse_args()
	dest_ip = socket.gethostbyname(dest_ip)
	src_ip, src_port = get_curr_addr()
	packet = get_packet(src_ip, src_port, dest_ip, dest_port)

	s.sendto(packet, (dest_ip, dest_port))

	while True:
		data = s.recvfrom(1024)
		print(data)


if __name__ == '__main__':
	main()