import socket
import select


class Network:
    def __init__(self):
        self.s_icmp = self.get_socket(socket.IPPROTO_ICMP)
        self.s_tcp = self.get_socket(socket.IPPROTO_TCP)

    @staticmethod
    def get_socket(sock_proto):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_proto)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setblocking(0)

        return s

    def recv(self):
        while True:
            readers, _, _ = select.select([self.s_icmp, self.s_tcp], [], [])

            for reader in readers:
                data, addr = reader.recvfrom(65565)

                if data:
                    return data, addr

    def send(self, data, addr):
        self.s_tcp.sendto(data, addr)
