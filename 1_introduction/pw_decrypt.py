from crypt import crypt
import logging
from itertools import product
import string

logging.basicConfig(level=logging.INFO, filename='logs/pw_decrypt.py.log', 
    filemode='w')
logger = logging.getLogger(__name__)

MAX_SALT_LENGTH = 3
SALT_CHARS = string.digits + string.ascii_letters + './'

def get_salts():
    for i in range(MAX_SALT_LENGTH):
        results = product(SALT_CHARS, repeat=i)
        for r in results:
            yield ''.join(r)

def get_dictionary_words():
    with open('dictionary.txt', 'r') as f:
        return f.read().splitlines()

DICTIONARY_WORDS = get_dictionary_words()

def get_password(user, encrypted_pw, salt):
    print('[?] Cracking password for {0} (encrypted_pw={1}, salt={2})'.format(
        user, encrypted_pw, salt))

    for word in DICTIONARY_WORDS:
        crypt_word = crypt(word, salt=salt)

        if crypt_word == encrypted_pw:
            return word

    return None

def main():
    """
    Brute force Unix password cracker.
    """

    with open('passwords.txt', 'r') as f:
        for line in f.readlines():
            if ':' in line:
                tokens = line.split(':')
                user = tokens[0]
                encrypted_pw = tokens[1].strip(' ')
                found = False

                for salt in get_salts():
                    password = get_password(user, encrypted_pw, salt)

                    if password:
                        found = True
                        break

                if found:
                    msg = '[+] Found password for {0}: {1}'.format(user, 
                        password)
                else:
                    msg = '[-] Password not found for {0}'.format(user)

                print(msg)
                logger.info(msg)

    print('[!] Finished')

if __name__ == '__main__':
    main()
