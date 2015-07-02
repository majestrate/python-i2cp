from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
from unittest import TestCase

from i2p import crypto, datatypes

DSA_ELGAMAL_KEY_CERT = b'BQAEAAAAAA=='
DSA_ELGAMAL_KEY_CERT_PAYLOAD = b'AAAAAA=='
STATS_I2P_DEST_DSA = 'Okd5sN9hFWx-sr0HH8EFaxkeIMi6PC5eGTcjM1KB7uQ0ffCUJ2nVKzcsKZFHQc7pLONjOs2LmG5H-2SheVH504EfLZnoB7vxoamhOMENnDABkIRGGoRisc5AcJXQ759LraLRdiGSR0WTHQ0O1TU0hAz7vAv3SOaDp9OwNDr9u902qFzzTKjUTG5vMTayjTkLo2kOwi6NVchDeEj9M7mjj5ySgySbD48QpzBgcqw1R27oIoHQmjgbtbmV2sBL-2Tpyh3lRe1Vip0-K0Sf4D-Zv78MzSh8ibdxNcZACmZiVODpgMj2ejWJHxAEz41RsfBpazPV0d38Mfg4wzaS95R5hBBo6SdAM4h5vcZ5ESRiheLxJbW0vBpLRd4mNvtKOrcEtyCvtvsP3FpA-6IKVswyZpHgr3wn6ndDHiVCiLAQZws4MsIUE1nkfxKpKtAnFZtPrrB8eh7QO9CkH2JBhj7bG0ED6mV5~X5iqi52UpsZ8gnjZTgyG5pOF8RcFrk86kHxAAAA'
STATS_I2P_DEST_DSA_B32 = '7tbay5p4kzeekxvyvbf6v7eauazemsnnl2aoyqhg5jzpr5eke7tq.b32.i2p'


def assert_KeyCert_DSA_ElGamal(cert):
    assert len(cert.data) == 4
    assert cert.sigtype == crypto.SigType.DSA_SHA1
    assert cert.enctype == crypto.EncType.ELGAMAL_2048
    assert len(cert.extra_sigkey_data) == 0
    assert len(cert.extra_enckey_data) == 0


class TestKeyCertificate(TestCase):

    def test_parse(self):
        cert = datatypes.KeyCertificate(raw=DSA_ELGAMAL_KEY_CERT, b64=True)
        assert_KeyCert_DSA_ElGamal(cert)

    def test_create_and_serialize(self):
        cert = datatypes.KeyCertificate(DSA_ELGAMAL_KEY_CERT_PAYLOAD, b64=True)
        assert_KeyCert_DSA_ElGamal(cert)
        assert cert.serialize(True) == DSA_ELGAMAL_KEY_CERT


class TestDestination(TestCase):

    def test_parse(self):
        dest = datatypes.Destination(raw=STATS_I2P_DEST_DSA, b64=True)
        assert dest.cert.type == datatypes.CertificateType.NULL
        assert len(dest.cert.data) == 0

    def test_serialize(self):
        dest = datatypes.Destination(crypto.ElGamalKey(), crypto.DSAKey(), datatypes.Certificate())
        data = dest.serialize()
        dest2 = datatypes.Destination(raw=data)
        assert dest2.enckey.key.y == dest.enckey.key.y
        assert dest2.sigkey.key.y == dest.sigkey.key.y
        assert dest2.cert.type == dest.cert.type

    def test_base64(self):
        dest = datatypes.Destination(raw=STATS_I2P_DEST_DSA, b64=True)
        assert dest.base64() == STATS_I2P_DEST_DSA

    def test_base32(self):
        dest = datatypes.Destination(raw=STATS_I2P_DEST_DSA, b64=True)
        assert dest.base32() == STATS_I2P_DEST_DSA_B32


class TestLeaseSet(TestCase):

    def test_serialize(self):
        dest = datatypes.Destination(crypto.ElGamalKey(), crypto.DSAKey(), datatypes.Certificate())
        lease = datatypes.Lease(b'f'*32, 1, datatypes.Date(1))
        ls = datatypes.LeaseSet(dest=dest, ls_enckey=crypto.ElGamalKey(), ls_sigkey=crypto.DSAKey(), leases=[lease])
        data = ls.serialize()
        dest.dsa_verify(data[:-40], data[-40:])

    def test_parse(self):
        dest = datatypes.Destination(crypto.ElGamalKey(), crypto.DSAKey(), datatypes.Certificate())
        lease = datatypes.Lease(b'f'*32, 1, datatypes.Date(1))
        ls = datatypes.LeaseSet(dest=dest, ls_enckey=crypto.ElGamalKey(), ls_sigkey=crypto.DSAKey(), leases=[lease])
        data = ls.serialize()
        ls2 = datatypes.LeaseSet(raw=data)
        assert ls2.dest.base64() == ls.dest.base64()
        assert ls2.enckey.key.y == ls.enckey.key.y
        assert ls2.sigkey.key.y == ls.sigkey.key.y
        assert len(ls2.leases) == len(ls.leases)
