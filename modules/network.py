import socket
import select
import time


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

    def recv(self, timeout):
        start_time = time.monotonic()
        result = []

        while True:
            readers, _, _ = select.select(
                [self.s_icmp, self.s_tcp],
                [],
                [],
                timeout)
            if not readers:
                return None, timeout
            else:
                for reader in readers:
                    data, addr = reader.recvfrom(65565)
                    result.append(data)

                return result, time.monotonic() - start_time

    def send(self, data, addr):
        self.s_tcp.send(data)
