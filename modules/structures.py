from collections import namedtuple


TCP = namedtuple('TCP', ['sport', 'dport', 'ack', 'rst'])
IP = namedtuple('IP', ['len', 'proto', 'src', 'dst', 'load'])
ICMP = namedtuple('ICMP', ['type', 'load'])
Result = namedtuple('Result', ['state', 'response_time', 'addr'])


class State:
    NOT_ALLOWED = 0
    OK = 1
    ERROR = 2,
    TIMEOUT = 3,
    UNREACHABLE = 4


class Protos:
    ICMP = 1
    TCP = 6
