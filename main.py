from struct import pack
import socket
import sys



LOCAL_PORT = 23011
LOCAL_HOST = '127.0.0.1'


def checksum(msg):
	msg = str(msg)
	s = 0
	for i in range(0, len(msg), 2):
		if (i+1) < len(msg):
		    a = ord(msg[i]) 
		    b = ord(msg[i+1])
		    s = s + (a+(b << 8))
		elif (i+1)==len(msg):
		    s += ord(msg[i])
		else:
		    raise "Something Wrong here"

	s = (s>>16) + (s & 0xffff);
	s = ~s & 0xffff

	return s


def get_ip_header(source_ip, dest_ip):
	# ip header fields
	ihl = 5
	version = 4
	tos = 0
	tot_len = 20 + 20	
	id = 54321	
	frag_off = 0
	ttl = 255
	protocol = socket.IPPROTO_TCP
	check = 10	
	saddr = socket.inet_aton ( source_ip )
	daddr = socket.inet_aton ( dest_ip )

	ihl_version = (version << 4) + ihl
	ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)

	return ip_header


def get_syn_packet(source_ip, source_port, dest_ip, dest_port):
	packet = '';
	ip_header = get_ip_header(source_ip, dest_ip)
	

	# tcp header fields	
	seq = 10
	ack_seq = 0
	doff = 5
	#tcp flags
	fin = rst = psh = ack = urg = 0
	syn = 1
	window = socket.htons(5840)
	check = 0
	urg_ptr = 0

	offset_res = (doff << 4) + 0
	tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)

	tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)

	source_address = socket.inet_aton(source_ip)
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_header)

	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
	psh = psh + tcp_header;

	tcp_checksum = checksum(psh)

	tcp_header = pack('!HHLLBBHHH' , source_port, dest_port, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)

	packet = ip_header + tcp_header

	return packet


def parse_args():
	args = sys.argv
	ip = args[1]
	port = None

	if len(args) > 2:
		port = args[2]

	return ip, port


def main():
	#main.py host_name port
	#checksum и get_syn_packet взяты с https://www.binarytides.com/raw-socket-programming-in-python-linux/
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	dest_host_name, dest_port = parse_args()
	dest_ip = socket.gethostbyname(dest_host_name) 
	dest_port = 80 if dest_port is None else dest_port

	packet = get_syn_packet(LOCAL_HOST, LOCAL_PORT, dest_ip, dest_port)

	s.sendto(packet, (dest_ip, 0))
	'''
	while True:
		data = s.recvfrom(1024)
		print(data)
	'''


if __name__ == '__main__':
	main()