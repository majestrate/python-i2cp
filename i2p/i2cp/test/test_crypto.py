from __future__ import absolute_import, division, print_function, unicode_literals
from unittest import TestCase
from i2p.i2cp import crypto, exceptions

class TestCrypto(TestCase):


    def setUp(self):
        self.data = 'test 12345'.encode('utf-8')


    def test_dsa_sign_verfiy_valid(self):
        key = crypto.DSAGenerate()

        assert key is not None
        assert key.has_private()

        sig = crypto.DSA_SHA1_SIGN(key, self.data)

        assert sig is not None
        assert len(sig) == 40

        try:
            crypto.DSA_SHA1_VERIFY(key, self.data, sig)
        except exceptions.I2CPException:
            assert False
        else:
            assert True


    def test_dsa_sign_verfiy_invalid(self):
        key = crypto.DSAGenerate()

        assert key is not None
        assert key.has_private()

        badsig = b'\x00' * 40
        assert len(badsig) == 40

        try:
            crypto.DSA_SHA1_VERIFY(key, self.data, badsig)
        except exceptions.I2CPException:
            assert True
        else:
            assert False
