
TCP_data = namedtuple('TCP_data', ['src_port', 'dst_port', 'ack', 'rst'])
IP_data = namedtuple('IP_data', ['len', 'src_ip', 'dst_ip'])
Result = namedtuple('Result', ['state', 'response_time'])

def test():
	pass