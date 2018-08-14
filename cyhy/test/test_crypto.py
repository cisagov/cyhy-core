#!/usr/bin/env py.test -v

import os
import sys

import pytest

import struct
import hashlib
import Crypto.Random.random as random
from base64 import b64encode, b64decode

from bson.binary import Binary
import netaddr
import netaddr.strategy

from cyhy.db import CryptoKey, IPCoder
from common_fixtures import *

CORRECT_PASSWORD = 'foobar'
INCORRECT_PASSWORD = 'fubar'
COMP_TIME = 0.1

PASSWORD = 'foobar'
ADDRESSES = ('192.168.100.200',  '0.0.0.0', '255.255.255.255', '2001:470:8:82b:e0ca:14cc:4a6d:973f', '::1')
_ID = 0
    
@pytest.fixture(scope="module")
def key():
    k = CryptoKey(CORRECT_PASSWORD, computation_time=COMP_TIME)
    return k
    
@pytest.fixture
def collection(database):
    col = database['secret']
    return col

class TestCryptoKey:
    def test_key_creation(self, key):
        print
        print 'rounds:   ', key.rounds
        print 'salt:     ', b64encode(key.salt)    
        print 'key check:', b64encode(key.key_check)
        print 'key:      ', b64encode(key.key)
        assert key.rounds != None
        assert key.salt != None
        assert key.key_check != None
        assert key.key != None
 
    def test_good_key_check(self, key):
        k = CryptoKey(CORRECT_PASSWORD, key.salt, key.rounds, key.key_check)
        assert k.key == key.key

    def test_bad_key_check(self, key):
        with pytest.raises(Exception):
            k = CryptoKey(INCORRECT_PASSWORD, key.salt, key.rounds, key.key_check)
            assert k.key == None

    def test_no_key_check(self, key):    
        k = CryptoKey(INCORRECT_PASSWORD, key.salt, key.rounds)
        assert k.key != None
        assert k.key != key.key


@pytest.mark.parametrize(("address"), ADDRESSES, scope="class")
class TestIPCoderToMemory:
    def test_encrypt_to_memory(self, key, address):
        print
        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
        coder = IPCoder(key.key, iv)
        ip = netaddr.IPAddress(address)
        ciphertext = coder.encrypt(ip)
    
        print 'ip:', ip
        print 'iv :', b64encode(iv)
        print 'ciphertext:', b64encode(ciphertext)
    
        TestIPCoderToMemory.rec = {
               'iv':Binary(iv),
               'ip':Binary(ciphertext)
              }
              
    def test_decrypt_from_memory(self, key, address):
        print

        iv = TestIPCoderToMemory.rec['iv']
        ciphertext = TestIPCoderToMemory.rec['ip']
        print 'iv :', b64encode(iv)
        print 'ciphertext:', b64encode(ciphertext)
    
        coder = IPCoder(key.key, iv)
        ip = coder.decrypt(ciphertext)
    
        print 'ip:', ip
        assert ip == netaddr.IPAddress(address)

#@pytest.mark.xfail(run=False, reason='requires local mongodb')
@pytest.mark.parametrize(("address"), ADDRESSES, scope="class")
class TestIPCoderToDatabase:
    def test_encrypt_to_database(self, collection, key, address):
        print
        iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
        coder = IPCoder(key.key, iv)
        ip = netaddr.IPAddress(address)
        ciphertext = coder.encrypt(ip)
    
        print 'ip:', ip
        print 'iv :', b64encode(iv)
        print 'ciphertext:', b64encode(ciphertext)
    
        rec = {'_id':_ID,
               'iv':Binary(iv),
               'ip':Binary(ciphertext)
              }
        collection.update({'_id':_ID}, rec, upsert=True)
    
    def test_decrypt_from_database(self, collection, key, address):
        print
        rec = collection.find_one({'_id':_ID})  
        iv = rec['iv']
        ciphertext = rec['ip']
        print 'iv :', b64encode(iv)
        print 'ciphertext:', b64encode(ciphertext)
    
        coder = IPCoder(key.key, iv)
        ip = coder.decrypt(ciphertext)
    
        print 'ip:', ip
        assert ip == netaddr.IPAddress(address)