from modules import tcping
import argparse


def parse_args():
    parser = argparse.ArgumentParser(description='Аналог команды ping с помощью tcp')
    parser.add_argument('ip', help='IP адрес', type=str)
    parser.add_argument('port', help='Порт', type=int)
    parser.add_argument('-a', '--amount', default=1, help='Число отправляемых пакетов', type=int)
    parser.add_argument('-t', '--timeout', default=10, help='Время ожидания ответа', type=int)
    parser.add_argument('-i', '--interval', default=10, help='Интервал отправки пакетов', type=int)


    return parser.parse_args()


def main():
	args = parse_args()
	tcping.tcping(args.ip, args.port, args.timeout)



if __name__ == '__main__':
	main()