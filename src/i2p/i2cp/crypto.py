from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import ElGamal, DSA
from Crypto.Random.random import StrongRandom as random
from pyelliptic.ecc import ECC
from .util import *
from .exceptions import *
import codecs
from enum import Enum
import math
import string
#import nacl.signing as nacl

sha1 = lambda x: SHA.new(x).digest()
sha256 = lambda x: SHA256.new(x).digest()

#
# Parameters
#

elgamal_p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
elgamal_g = 2
ELGAMAL_2048_SPEC = (elgamal_p, elgamal_g)

dsa_seed = int('86108236b8526e296e923a4015b4282845b572cc', 16)
dsa_p = int('9C05B2AA960D9B97B8931963C9CC9E8C3026E9B8ED92FAD0A69CC886D5BF8015FCADAE31A0AD18FAB3F01B00A358DE237655C4964AFAA2B337E96AD316B9FB1CC564B5AEC5B69A9FF6C3E4548707FEF8503D91DD8602E867E6D35D2235C1869CE2479C3B9D5401DE04E0727FB33D6511285D4CF29538D9E3B6051F5B22CC1C93', 16)
dsa_q = int('A5DFC28FEF4CA1E286744CD8EED9D29D684046B7', 16)
dsa_g = int('0C1F4D27D40093B429E962D7223824E0BBC47E7C832A39236FC683AF84889581075FF9082ED32353D4374D7301CDA1D23C431F4698599DDA02451824FF369752593647CC3DDC197DE985E43D136CDCFC6BD5409CD2F450821142A5E6F8EB1C3AB5D0484B8129FCF17BCE4F7F33321C3CB3DBB14A905E7B2B3E93BE4708CBCC82', 16)
DSA_SHA1_SPEC = (dsa_g, dsa_p, dsa_q)

P256_SPEC = None
P384_SPEC = None
P521_SPEC = None
F4_2048_SPEC = None
F4_3072_SPEC = None
F4_4096_SPEC = None
Ed25519_SHA_512_SPEC = None


#
# Algorithms
#

class EncAlgo(Enum):
    ELGAMAL = "ElGamal"
    EC = "EC"

class SigAlgo(Enum):
    DSA = "DSA"
    EC = "EC"
    EdDSA = "EdDSA"
    RSA = "RSA"

class EncType(Enum):
    ELGAMAL_2048 = (0, 256, 256, EncAlgo.ELGAMAL, "ElGamal/None/NoPadding", ELGAMAL_2048_SPEC, "0")
    EC_P256 = (1, 64, 32, EncAlgo.EC, "EC/None/NoPadding", P256_SPEC, "0.9.20")
    EC_P384 = (2, 96, 48, EncAlgo.EC, "EC/None/NoPadding", P384_SPEC, "0.9.20")
    EC_P521 = (3, 132, 66, EncAlgo.EC, "EC/None/NoPadding", P521_SPEC, "0.9.20")

    @property
    def code(self):
        return self.value[0]

    @property
    def pubkey_len(self):
        return self.value[1]

    @property
    def privkey_len(self):
        return self.value[2]

    @property
    def base_algo(self):
        return self.value[3]

    @property
    def algo_name(self):
        return self.value[4]

    @property
    def spec(self):
        return self.value[5]

    @property
    def since(self):
        return self.value[6]

    @property
    def is_available(self):
        return self.spec is not None

    @staticmethod
    def get_by_code(code):
        for enc in EncType:
            if enc.code == code:
                return enc
        return None

class SigType(Enum):
    DSA_SHA1 = (0, 128, 20, 20, 40, SigAlgo.DSA, "SHA-1", "SHA1withDSA", DSA_SHA1_SPEC, "0")
    ECDSA_SHA256_P256 = (1, 64, 32, 32, 64, SigAlgo.EC, "SHA-256", "SHA256withECDSA", P256_SPEC, "0.9.12")
    ECDSA_SHA384_P384 = (2, 96, 48, 48, 96, SigAlgo.EC, "SHA-384", "SHA384withECDSA", P384_SPEC, "0.9.12")
    ECDSA_SHA512_P521 = (3, 132, 66, 64, 132, SigAlgo.EC, "SHA-512", "SHA512withECDSA", P521_SPEC, "0.9.12")
    RSA_SHA256_2048 = (4, 256, 512, 32, 256, SigAlgo.RSA, "SHA-256", "SHA256withRSA", F4_2048_SPEC, "0.9.12")
    RSA_SHA384_3072 = (5, 384, 768, 48, 384, SigAlgo.RSA, "SHA-384", "SHA384withRSA", F4_3072_SPEC, "0.9.12")
    RSA_SHA512_4096 = (6, 512, 1024, 64, 512, SigAlgo.RSA, "SHA-512", "SHA512withRSA", F4_4096_SPEC, "0.9.12")
    EdDSA_SHA512_Ed25519 = (7, 32, 32, 64, 64, SigAlgo.EdDSA, "SHA-512", "SHA512withEdDSA", Ed25519_SHA_512_SPEC, "0.9.17")

    @property
    def code(self):
        return self.value[0]

    @property
    def pubkey_len(self):
        return self.value[1]

    @property
    def privkey_len(self):
        return self.value[2]

    @property
    def hash_len(self):
        return self.value[3]

    @property
    def sig_len(self):
        return self.value[4]

    @property
    def base_algo(self):
        return self.value[5]

    @property
    def digest_name(self):
        return self.value[6]

    @property
    def algo_name(self):
        return self.value[7]

    @property
    def spec(self):
        return self.value[8]

    @property
    def since(self):
        return self.value[9]

    @property
    def is_available(self):
        return self.spec is not None

    @staticmethod
    def get_by_code(code):
        for enc in SigType:
            if enc.code == code:
                return enc
        return None


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

    fd.write(int(key.y).to_bytes(256, 'big'))
    fd.write(int(key.x).to_bytes(256, 'big'))

    if doclose:
        fd.close()


def elgamal_public_key_to_bytes(key):
    return int(key.y).to_bytes(256, 'big')

def elgamal_private_key_to_bytes(key):
    return int(key.x).to_bytes(256, 'big')

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
        data = sha1(data)
        R, S =  key.sign(data, k)
        return int(R).to_bytes(20,'big') + int(S).to_bytes(20,'big')
    else:
        raise I2CPException('No Private Key')

def DSA_SHA1_VERIFY(key, data, sig):
    """
    verify DSA-SHA1 signature
    """

    data = sha1(data)
    R, S = int.from_bytes(sig[:20],'big'), int.from_bytes(sig[20:],'big')
    if not key.verify(data, (R,S)):
        raise I2CPException('DSA_SHA1_VERIFY Failed')

def dsa_public_key_to_bytes(key):
    return int(key.y).to_bytes(128, 'big')

def dsa_private_key_to_bytes(key):
    return int(key.x).to_bytes(20, 'big')

def dsa_public_key_from_bytes(data):
    return DSAKey(int.from_bytes(data,'big'))

def dsa_dump_key(key, fd):
    fd.write(int(key.y).to_bytes(128,'big'))
    fd.write(int(key.x).to_bytes(128,'big'))

def gen_dsa_key(fname=None,fd=None):
    dsakey = DSAGenerate()
    nofname = fd is None
    if nofname:
        fd = open(fname, 'wb')

    y, x = dsakey.y , dsakey.x
    fd.write(int(y).to_bytes(128, 'big'))
    fd.write(int(x).to_bytes(128, 'big'))
    if nofname:
        fd.close()

def load_dsa_key(fname):
    with open(fname, 'rb') as rf:
        return DSAKey(fd=rf)

def gen_keypair(fd):
    gen_elgamal_key(fd)
    gen_dsa_key(fd)

def dump_keypair(enckey, sigkey, fd):
    fd.write(int(enckey.y).to_bytes(256, 'big'))
    fd.write(int(enckey.x).to_bytes(256, 'big'))
    dsa_dump_key(sigkey, fd)

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
