from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
from i2p.i2cp import util
from unittest import TestCase
import os

class TestUtil(TestCase):

    def setUp(self):
        self.data_str = 'testdata1234567890'
        self.data_bytes = self.data_str.encode('utf-8')
        self.desthash_valid = 'mpvr7qmek2yz2ekegp5rur573z7e77vp3xqt2lfbco5i6nkfppcq.b32.i2p'
        self.desthash_short = 'tooshort.b32.i2p'
        self.desthash_valid_bytes = self.desthash_valid.encode('utf-8')
        self.desthash_invalid_bytes = b'wutwut.b32.i2p'
        self.desthash_name = 'wut.i2p'
        self.desthash_junk = ( '\x37\x01' * 26 ) + '.b32.i2p'
        self.desthash_len = 60


    def test_i2p_compress(self):
        compressed_bytes = util.i2p_compress(self.data_bytes)
        compressed_str = util.i2p_compress(self.data_str)
        assert util.i2p_decompress(compressed_bytes) == self.data_bytes
        assert util.i2p_decompress(compressed_str) == self.data_bytes

    def test_assert_portnum_valid(self):
        for port in range(0, 2**16):
            assert util.check_portnum(port)

    def test_assert_portnum_high(self):
        assert not util.check_portnum(2**16)

    def test_assert_portnum_neg(self):
        assert not util.check_portnum(-1)

    def test_assert_portnum_bad_types(self):
        assert not util.check_portnum('')
        assert not util.check_portnum(b'')
        assert not util.check_portnum(bytearray())
        assert not util.check_portnum(0.0)
        assert not util.check_portnum(None)

    def test_isdesthash(self):
        assert not util.isdesthash(self.desthash_short)
        assert not util.isdesthash(self.desthash_invalid_bytes)
        assert not util.isdesthash(self.desthash_name)
        assert util.isdesthash(self.desthash_valid)
        assert util.isdesthash(self.desthash_valid_bytes)
        assert len(self.desthash_junk) == self.desthash_len
        assert len(self.desthash_valid) == self.desthash_len
        assert len(self.desthash_valid_bytes) == self.desthash_len


    def test_i2p_base64(self):
        encoded_bytes = util.i2p_b64encode(self.data_bytes)
        encoded_str = util.i2p_b64encode(self.data_str)
        decoded_bytes = util.i2p_b64decode(encoded_bytes)
        decoded_str = util.i2p_b64decode(encoded_str)
        assert encoded_str == encoded_bytes
        assert decoded_bytes == decoded_str
        assert decoded_bytes == self.data_bytes
        assert decoded_str == self.data_bytes
