from collections import namedtuple


TCP_data = namedtuple('TCP_data', ['src_port', 'dst_port', 'ack', 'rst'])
IP_data = namedtuple('IP_data', ['len', 'proto', 'src_ip', 'dst_ip', 'load'])
ICMP_data = namedtuple('ICMP_data', ['type', 'load'])
Result = namedtuple('Result', ['state', 'response_time'])


class State:
    NOT_ALLOWED = 0
    OK = 1
    ABORTED = 2


class Protos:
    ICMP = 1
    TCP = 6
