from argparse import ArgumentParser
import asyncio
import socket
import logging

logging.basicConfig(level=logging.WARNING, 
    filename='logs/vulnerable_asyncio.py.log', filemode='w')
logger = logging.getLogger(__name__)

def get_ports():
    for port in range(1, 255):
        yield port

@asyncio.coroutine
def get_banner(ip, port):
    """
    Makes a request for a banner.
    Note: wait_for timeout seems to be broken. Does not raise a TimeoutError 
    after desired time.
    """
    fut = asyncio.open_connection(ip, port)

    try:
        reader, writer = yield from asyncio.wait_for(fut, 2)
        banner = yield from reader.read(1024)
        return banner
    except ConnectionRefusedError as e:
        logger.error('Connection refused for {0}:{1}'.format(ip, port))
    except asyncio.TimeoutError as e:
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

@asyncio.coroutine
def banner_request(ip, port):
    banner = yield from get_banner(ip, port)
    if banner:
        print_banner(ip, port, banner)
        
        if check_vulnerable_banner(banner):
            print('[+] {0} is vulnerable!'.format(banner))
        else:
            print('[-] {0} is not vulnerable'.format(banner))

def main():
    """
    Makes banner requests with asyncio tasks.
    """
    arg_parser = ArgumentParser()
    arg_parser.add_argument('--ip', help='IP address')
    args = arg_parser.parse_args()
    ip = args.ip

    tasks = []
    for port in get_ports():
        tasks.append(asyncio.async(banner_request(ip, port)))

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.wait(tasks))
    print('[!] Finished spawning banner requests')

    loop.close()

if __name__ == '__main__':
    main()
