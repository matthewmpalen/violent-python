from argparse import ArgumentParser
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import ThreadPoolExecutor
import socket
import logging

logging.basicConfig(level=logging.WARNING, 
    filename='logs/vulnerable.py.log', filemode='w')
logger = logging.getLogger(__name__)

def get_ports():
    for port in [21, 22, 25, 80, 110]:
        yield port

def get_banner(ip, port):
    """
    Makes a blocking socket request for a banner.
    """
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024)
        s.close()
        return banner
    except ConnectionRefusedError as e:
        logger.error('Connection refused for {0}:{1}'.format(ip, port))
    except socket.timeout as e:
        logger.error('Banner request for {0}:{1} timed out'.format(ip, port))

    return None

def get_vulnerable_banners():
    output = []
    with open('vulnerable_banners.txt', 'r') as f:
        for line in f:
            output.append(line.strip('\n'))

    return output

VULNERABLE_BANNERS = get_vulnerable_banners()

def check_vulnerable_banner(banner):
    for b in VULNERABLE_BANNERS:
        if b in banner:
            return True

    return False

def print_banner(ip, port, banner):
    print('[+] {0}:{1}    {2}'.format(ip, port,  banner))

def banner_request(ip, port):
    banner = get_banner(ip, port)
    if banner:
        print_banner(ip, port, banner)
        
        if check_vulnerable_banner(banner):
            print('[+] {0} is vulnerable!'.format(banner))
        else:
            print('[-] {0} is not vulnerable'.format(banner))

def main():
    """
    Makes banner requests with a ThreadPoolExecutor.
    """
    arg_parser = ArgumentParser()
    arg_parser.add_argument('--ip', help='IP address', required=True)
    arg_parser.add_argument('--pool', help='Executor pool type', 
        choices=('thread', 'process'), required=True)
    arg_parser.add_argument('--workers', help='Number of executor workers', 
        type=int, choices=range(1, 9), required=True)
    args = arg_parser.parse_args()

    ip = args.ip
    pool = args.pool
    workers = args.workers

    if pool == 'process':
        executor = ProcessPoolExecutor(max_workers=workers)
    elif pool == 'thread':
        executor = ThreadPoolExecutor(max_workers=workers)

    for i in range(1, 256):
        for port in get_ports():
            executor.submit(banner_request, '{0}.{1}'.format(ip, i), port)

    print('[!] Finished spawning banner requests')

if __name__ == '__main__':
    main()
