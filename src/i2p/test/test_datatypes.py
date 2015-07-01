from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
from unittest import TestCase
from i2p import crypto, datatypes

DSA_ELGAMAL_KEY_CERT = b'BQAEAAAAAA=='
DSA_ELGAMAL_KEY_CERT_PAYLOAD = b'AAAAAA=='
STATS_I2P_DEST_DSA = b'Okd5sN9hFWx-sr0HH8EFaxkeIMi6PC5eGTcjM1KB7uQ0ffCUJ2nVKzcsKZFHQc7pLONjOs2LmG5H-2SheVH504EfLZnoB7vxoamhOMENnDABkIRGGoRisc5AcJXQ759LraLRdiGSR0WTHQ0O1TU0hAz7vAv3SOaDp9OwNDr9u902qFzzTKjUTG5vMTayjTkLo2kOwi6NVchDeEj9M7mjj5ySgySbD48QpzBgcqw1R27oIoHQmjgbtbmV2sBL-2Tpyh3lRe1Vip0-K0Sf4D-Zv78MzSh8ibdxNcZACmZiVODpgMj2ejWJHxAEz41RsfBpazPV0d38Mfg4wzaS95R5hBBo6SdAM4h5vcZ5ESRiheLxJbW0vBpLRd4mNvtKOrcEtyCvtvsP3FpA-6IKVswyZpHgr3wn6ndDHiVCiLAQZws4MsIUE1nkfxKpKtAnFZtPrrB8eh7QO9CkH2JBhj7bG0ED6mV5~X5iqi52UpsZ8gnjZTgyG5pOF8RcFrk86kHxAAAA'

def assert_KeyCert_DSA_ElGamal(cert):
    assert len(cert.data) == 4
    assert cert.sigtype == crypto.SigType.DSA_SHA1
    assert cert.enctype == crypto.EncType.ELGAMAL_2048
    assert cert.extra_sigkey_data is None
    assert cert.extra_enckey_data is None

class TestKeyCertificate(TestCase):

    def test_parse(self):
        cert = datatypes.KeyCertificate(raw=DSA_ELGAMAL_KEY_CERT, b64=True)
        assert_KeyCert_DSA_ElGamal(cert)

    def test_create_and_serialize(self):
        cert = datatypes.KeyCertificate(DSA_ELGAMAL_KEY_CERT_PAYLOAD)
        assert_KeyCert_DSA_ElGamal(cert)
        assert cert.serialize(True) == DSA_ELGAMAL_KEY_CERT


class TestDestination(TestCase):

    def test_parse(self):
        dest = datatypes.Destination(raw=STATS_I2P_DEST_DSA, b64=True)
        assert dest.cert.type == datatypes.CertificateType.NULL
        assert len(dest.cert.data) == 0
