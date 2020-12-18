from modules import tcping
import argparse
import socket


def parse_args():
    parser = argparse.ArgumentParser(
        description='Аналог команды ping с помощью tcp')
    parser.add_argument(
        'ip',
        help='IP адрес',
        type=str)
    parser.add_argument(
        'port',
        help='Порт',
        type=int)
    parser.add_argument(
        '-a',
        '--amount',
        default=1,
        help='Число отправляемых пакетов',
        type=int)
    parser.add_argument(
        '-t',
        '--timeout',
        default=10,
        help='Время ожидания ответа',
        type=float)
    parser.add_argument(
        '-i',
        '--interval',
        default=0,
        help='Интервал отправки пакетов',
        type=float)
    return parser.parse_args()


def main():
    args = parse_args()
    tcping.TCPing().ping(
        args.ip,
        args.port,
        args.amount,
        args.interval,
        args.timeout)


if __name__ == '__main__':
    main()
