from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
from unittest import TestCase
from i2p import crypto, datatypes

DSA_ELGAMAL_KEY_CERT = b'BQAEAAAAAA=='
DSA_ELGAMAL_KEY_CERT_PAYLOAD = b'AAAAAA=='

def assert_DSA_ElGamal(cert):
    assert len(cert.data) == 4
    assert cert.sigtype == crypto.SigType.DSA_SHA1
    assert cert.enctype == crypto.EncType.ELGAMAL_2048
    assert cert.extra_sigkey_data is None
    assert cert.extra_enckey_data is None

class TestKeyCertificate(TestCase):

    def test_parse(self):
        cert = datatypes.KeyCertificate.parse(DSA_ELGAMAL_KEY_CERT)
        assert_DSA_ElGamal(cert)

    def test_create_and_serialize(self):
        cert = datatypes.KeyCertificate(DSA_ELGAMAL_KEY_CERT_PAYLOAD)
        assert_DSA_ElGamal(cert)
        assert cert.serialize(True) == DSA_ELGAMAL_KEY_CERT
