from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
from i2p.i2cp import client
from unittest import TestCase

import queue
import time

class TestEchoHandler(client.I2CPHandler):

    def __init__(self, data, srcport, dstport, dgrams):
        self.data = data
        self.srcport = srcport
        self.dstport = dstport
        self.results = queue.Queue()
        self.num_dgram = dgrams

    def got_dgram(self, dest, data, srcport, dstport):
        result = dest.base32(), data, srcport, dstport
        self.results.put_nowait(result)

    def session_made(self, conn):
        self.dest = conn.dest
        for n in range(self.num_dgram):
            print('send %d' % n)
            conn.send_dgram(self.dest, self.data, srcport=self.srcport, dstport=self.dstport)

"""
class TestI2CP(TestCase):


    def setUp(self):
        self.dgram_data = 'test 12345'.encode('utf-8')
        self.srcport = 5555
        self.dstport = 55555
        self.dgrams = 20

    def test_dgrams(self):
        handler = TestEchoHandler(self.dgram_data, self.srcport, self.dstport, self.dgrams)
        c = client.Connection(handler, session_options={'i2cp.dontPublishLeaseset':'true'})
        c.open()
        c.start()
        counter = 0
        for n in range(self.dgrams):
            print ('recv %d' % n)
            b32, data, srcport, dstport = handler.results.get(1)
            assert b32 == c.dest.base32()
            assert data == self.dgram_data
            assert srcport == self.srcport
            assert dstport == self.dstport
            counter += 1
        c.close()
        del c
        assert counter == self.dgrams
"""
