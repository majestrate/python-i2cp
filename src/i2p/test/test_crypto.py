from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
from unittest import TestCase

from i2p import crypto


class TestDSAKey(TestCase):

    def setUp(self):
        self.data = 'test 12345'.encode('utf-8')

    def test_sign_verify_valid(self):
        key = crypto.DSAKey()
        assert key is not None

        sig = key.sign(self.data)
        assert sig is not None
        assert len(sig) == 40

        assert key.verify(self.data, sig)

    def test_sign_verify_invalid(self):
        key = crypto.DSAKey()
        assert key is not None

        badsig = b'\x00' * 40
        assert len(badsig) == 40

        assert not key.verify(self.data, badsig)
