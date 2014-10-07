from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *

from i2p.i2cp import client
from unittest import TestCase


class DummyHandler(client.I2CPHandler):
    pass

class TestI2CP(TestCase):


    def setUp(self):
        self.dgram_data = 'test 12345'
        self.handler = DummyHandler()


    def test_connect(self):
        c = client.Connection(self.handler)
        c.open()
        assert c.is_open()
        c.close()
        assert not c.is_open()


    def test_lookup(self):
        dest = client.lookup('irc.postman.i2p')
        assert dest is not None
        assert dest.base32() == 'mpvr7qmek2yz2ekegp5rur573z7e77vp3xqt2lfbco5i6nkfppcq.b32.i2p'



