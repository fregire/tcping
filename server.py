import socket


def main():
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind(('localhost', 3200))
	print(server.getsockname()[0])
	server.listen()

	while True:
		client, addr = server.accept()
		print(addr)



if __name__ == '__main__':
	main()