from argparse import ArgumentParser
import socket
import logging
from threading import Thread
import time

logging.basicConfig(level=logging.WARNING, 
    filename='logs/vulnerable.py.log', filemode='w')
logger = logging.getLogger(__name__)

def get_ports():
    for port in range(1, 255):
        yield port

def get_banner(ip, port):
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
    Spawns a thread for each blocking banner request.
    """
    arg_parser = ArgumentParser()
    arg_parser.add_argument('--ip', help='IP address')
    args = arg_parser.parse_args()
    ip = args.ip

    for port in get_ports():
        thread = Thread(target=banner_request, args=(ip, port))
        thread.start()

    print('Finished spawning banner requests')

if __name__ == '__main__':
    main()
