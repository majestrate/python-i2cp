from i2p.i2cp import client
from unittest import TestCase


class EchoHandler(client.I2CPHandler):
    pass

class SendHandler(client.I2CPHandler):
    
    def __init__(self, dest, data, srcport, dstport):
        self.data = data
        self.srcport = srcport
        self.dstport = dstport

    def got_dgram(self, dest, data, srcport, dstport):
        assert dest.base32() == self.dest.base32()
        assert data == self.data
        assert srcport == self.srcport
        assert dstport == self.dstport

class TestI2CP(TestCase):
    

    def setUp(self):
        self.dgram_data = 'test 12345'
    
