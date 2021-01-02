from modules import tcping
import argparse
import socket


DEFAULT_PORT = 80


def valid_addr(addr):
    try:
        return addr.split(':')
    except Exception as e:
        msg = f'Not a valid address: {addr}'
        raise  argparse.ArgumentTypeError(msg)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Аналог команды ping с помощью tcp')
    parser.add_argument(
        'addrs',
        help='Адреса для пинга в формате ip:port',
        type=valid_addr,
        nargs='+')
    '''
    parser.add_argument(
        'ip',
        help='IP адрес',
        type=str)
    parser.add_argument(
        'port',
        help='Порт',
        type=int)
    '''
    parser.add_argument(
        '-a',
        '--amount',
        default=1,
        help='Число отправляемых пакетов',
        type=int)
    parser.add_argument(
        '-t',
        '--timeout',
        default=4,
        help='Время ожидания ответа',
        type=float)
    parser.add_argument(
        '-i',
        '--interval',
        default=5,
        help='Интервал отправки пакетов',
        type=float)
    parser.add_argument(
        '-hp',
        '--hide-succ-pings',
        help='Скрыть успешные пинги',
        action='store_true')

    return parser.parse_args()


def main():
    args = parse_args()
    tcping.TCPing(args.hide_succ_pings).ping(
        args.addrs,
        args.amount,
        args.interval,
        args.timeout)


if __name__ == '__main__':
    main()
