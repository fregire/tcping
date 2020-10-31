class Packet():
    def __init__(self, src_addr, dst_addr, ack_num, rst_flag):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.ack_num = ack_num
        self.rst_flag = rst_flag