import socket


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
        PORT = s.getsockname()[1]
    except Exception:
        IP = '127.0.0.1'
        PORT = 80
    finally:
        s.close()
    return IP, PORT


def main():
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	print(s.getsockname())


if __name__ == '__main__':
	main()