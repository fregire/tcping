import socket



def main():
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	print(s.getsockname())


if __name__ == '__main__':
	main()