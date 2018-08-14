__all__ = ['CryptoKey', 'IPCoder']

import time
import hashlib
import Crypto.Random.random as random #pip install pycrypto

class CryptoKey(object):
    KEY_CHECK_HASH_BUMP = 'xyzzy'
    SALT_SIZE = 32 # 256 bit
    def __init__(self, password, salt=None, rounds=None, key_check=None, computation_time=1.0):
        self.salt = salt
        self.rounds = rounds
        self.key_check = key_check
        self.computation_time = computation_time
        self.key = None
        if salt == None:
            self.__generate_key(password)
        else:
            key_check_passed = self.__verify_key(password)
            if not key_check_passed:
                raise Exception('Wrong password: key check mismatch')
    
    def __generate_key(self, password):
        '''Generates a key from a password using salting and stretching'''
        salt = ''.join(chr(random.randint(0, 0xFF)) for i in range(CryptoKey.SALT_SIZE))
        start_time = time.time()
        end_time = start_time + self.computation_time
        x = hashlib.sha256(password + salt)
        rounds = 0
        while time.time() <= end_time:
            rounds += 1
            next_to_last_x = x
            x = hashlib.sha256(x.digest() + password + salt)
        
        self.salt = salt
        self.rounds = rounds
        self.key = x.digest()
        self.key_check = hashlib.sha256(CryptoKey.KEY_CHECK_HASH_BUMP + next_to_last_x.digest() + password + salt).digest()
        
    def __verify_key(self, password):
        x = hashlib.sha256(password + self.salt)
        r = 0
        while r < self.rounds:
            r += 1
            x = hashlib.sha256(x.digest() + password + self.salt)
            if r == self.rounds - 1 and self.key_check:
                key_check = hashlib.sha256(CryptoKey.KEY_CHECK_HASH_BUMP + x.digest() + password + self.salt).digest()
                if key_check != self.key_check:
                    return False
        self.key = x.digest()
        return True

import netaddr
import netaddr.strategy
import struct
from Crypto.Cipher import AES

class IPCoder(object):
    """docstring for IPCoder"""
    BLOCK_SIZE = 16
    PADDING = ' '
    pad = lambda self, s: s + (IPCoder.BLOCK_SIZE - len(s) % IPCoder.BLOCK_SIZE) * IPCoder.PADDING
   
    def __init__(self, key, iv):
        super(IPCoder, self).__init__()
        self.key = key
        self.iv = iv
    
    def __pack_ip(self, ip):
        ip_int = int(ip)
        word_count = ip._module.width / 8
        words = netaddr.strategy.int_to_words(ip_int, 8, word_count)
        packed = struct.pack('>' + 'B' * len(words), *words)
        return packed

    def __unpack_ip(self, packed):
        n = len(packed)
        words = struct.unpack('>' + 'B' * n, packed)
        ip_int = netaddr.strategy.words_to_int(words, 8, n)
        # explicity provide IP version to prevent ::1 from becoming 0.0.0.1
        if n == 4:
            version = 4
        elif n == 16:
            version = 6
        else:
            version = None
        return netaddr.IPAddress(ip_int, version)

    def encrypt(self, ip):
        """docstring for encrypt"""
        encryptor = AES.new(self.key, AES.MODE_CBC, self.iv) 
        plaintext = self.__pack_ip(ip)
        plaintext = self.pad(plaintext)
        cyphertext = encryptor.encrypt(plaintext)
        return cyphertext
    
    def decrypt(self, cyphertext):
        """docstring for decrypt"""
        decryptor = AES.new(self.key, AES.MODE_CBC, self.iv) 
        plaintext = decryptor.decrypt(cyphertext)
        plaintext = plaintext.rstrip(IPCoder.PADDING)
        ip_int = self.__unpack_ip(plaintext)
        return netaddr.IPAddress(ip_int)
        