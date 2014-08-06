from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from future.builtins import int
from future.builtins import open
from future import standard_library
standard_library.install_hooks()

from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import ElGamal, DSA
from Crypto.Random.random import StrongRandom as random
from .util import *
import codecs
import math
import string

sha1 = lambda x: SHA.new(x).digest()
sha256 = lambda x: SHA256.new(x).digest()

elgamal_p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
elgamal_g = 2
dsa_seed = int('86108236b8526e296e923a4015b4282845b572cc', 16)
dsa_p = int('9C05B2AA960D9B97B8931963C9CC9E8C3026E9B8ED92FAD0A69CC886D5BF8015FCADAE31A0AD18FAB3F01B00A358DE237655C4964AFAA2B337E96AD316B9FB1CC564B5AEC5B69A9FF6C3E4548707FEF8503D91DD8602E867E6D35D2235C1869CE2479C3B9D5401DE04E0727FB33D6511285D4CF29538D9E3B6051F5B22CC1C93', 16)
dsa_q = int('A5DFC28FEF4CA1E286744CD8EED9D29D684046B7', 16)
dsa_g = int('0C1F4D27D40093B429E962D7223824E0BBC47E7C832A39236FC683AF84889581075FF9082ED32353D4374D7301CDA1D23C431F4698599DDA02451824FF369752593647CC3DDC197DE985E43D136CDCFC6BD5409CD2F450821142A5E6F8EB1C3AB5D0484B8129FCF17BCE4F7F33321C3CB3DBB14A905E7B2B3E93BE4708CBCC82', 16)

# we don't use ElGamal so it's not going to be tested

def ElGamalKey(pub=None, priv=None, fd=None):
    """
    make ElGamal KeyPair Object
    """
    if fd is not None:
        pub = int.from_bytes(fd.read(256), 'big')
        priv = int.from_bytes(fd.read(256), 'big')
    if priv:
        return ElGamal.construct((elgamal_p, elgamal_g, pub, priv))
    return ElGamal.construct((elgamal_p, elgamal_g, pub))

def ElGamalPublicKey(data=None):
    """
    parse ElGamal PublicKey from raw data
    """
    return ElGamalKey(int.from_bytes(data,'big'))

def ElGamalGenerate():
    """
    Generate ElGamal KeyPair
    """
    x = random().randint(2, elgamal_p)
    y = pow(elgamal_g, x, elgamal_p)
    return ElGamalKey(y, x)

def gen_elgamal_key(fname=None,fd=None):

    key = ElGamalGenerate()

    doclose = fd is None
    if doclose:
        fd = open(fname, 'wb')

    fd.write(key.y.to_bytes(256, 'big'))
    fd.write(key.x.to_bytes(256, 'big'))

    if doclose:
        fd.close()


def elgamal_public_key_to_bytes(key):
    return key.y.to_bytes(256, 'big')

def elgamal_private_key_to_bytes(key):
    return key.x.to_bytes(256, 'big')

def DSAKey(pub=None, priv=None, fd=None):
    """
    make DSA KeyPair Object
    """
    if fd is not None:
        pub = int.from_bytes(fd.read(128), 'big')
        priv = int.from_bytes(fd.read(128), 'big')
    if priv:
        return DSA.construct((pub, dsa_g, dsa_p, dsa_q, priv))
    return DSA.construct((pub, dsa_g, dsa_p, dsa_q))


def DSAPublicKey(data=None):
    """
    make DSA KeyPair Object
    """
    if data is None:
        data = b'\x00' * 128
    y = int.from_bytes(data,'big')
    return DSAKey(y, None)

def DSAGenerate():
    """
    Generate DSA KeyPair
    this needs an audit
    """
    x = random().randint(1, 2 ** 160)
    y = pow(dsa_g, x, dsa_p)
    return DSAKey(y, x)


def DSA_SHA1_SIGN(key, data):
    """
    generate DSA-SHA1 signature
    """
    if key.has_private():
        k = random().randint(1, key.q - 1)
        R, S =  key.sign(sha1(data), k)
        return R.to_bytes(20,'big') + S.to_bytes(20,'big')

def DSA_SHA1_VERIFY(key, data, sig):
    """
    verify DSA-SHA1 signature
    """
    R, S = int.from_bytes(sig[:20],'big'), int.from_bytes(sig[20:],'big')
    assert key.verify(sha1(data), (R,S))

def dsa_public_key_to_bytes(key):
    return key.y.to_bytes(128, 'big')

def dsa_private_key_to_bytes(key):
    return key.x.to_bytes(20, 'big')

def dsa_public_key_from_bytes(data):
    return DSAKey(int.from_bytes(data,'big'))

def gen_dsa_key(fname=None,fd=None):
    dsakey = DSAGenerate()
    nofname = fd is None
    if nofname:
        fd = open(fname, 'wb')

    y, x = dsakey.y , dsakey.x
    fd.write(y.to_bytes(128, 'big'))
    fd.write(x.to_bytes(128, 'big'))
    if nofname:
        fd.close()

def load_dsa_key(fname):
    with open(fname, 'rb') as rf:
        return DSAKey(fd=rf)

def gen_keypair(fd):
    gen_elgamal_key(fd)
    gen_dsa_key(fd)

def dump_keypair(enckey, sigkey, fd):
    fd.write(enckey.y.to_bytes(256,'big'))
    fd.write(enckey.x.to_bytes(256,'big'))
    fd.write(sigkey.y.to_bytes(128,'big'))
    fd.write(sigkey.x.to_bytes(128,'big'))


def load_keypair(fd):
    enckey = ElGamalKey(fd=fd)
    sigkey = DSAKey(fd=fd)
    return enckey, sigkey

if __name__ == '__main__':
    data = b'testdata'
    print ('generate dsa key...')
    dkey = DSAGenerate()
    print ('sign...')
    sig = DSA_SHA1_SIGN(dkey, data)
    print ('verify...')
    DSA_SHA1_VERIFY(dkey, data, sig)
