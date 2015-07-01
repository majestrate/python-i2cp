from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
from . import crypto
from .i2cp import util
from enum import Enum
import logging
import struct
import time


#
# Common data types
#

def Date(num=None):
    if isinstance(num, bytes):
        num = struct.unpack(b'>Q', num)[0]
    if num is None:
        num = time.time() * 1000
    num = int(num)
    return struct.pack(b'>Q', num)


class Mapping(object):
    """
    i2p dictionary object
    it sucks
    """

    _log = logging.getLogger('Mapping')

    def __init__(self, opts=None, raw=None):
        if raw:
            self.data = raw
            self.opts = {}
            dlen = struct.unpack(b'>H', raw[:2])
            data = raw[2:2+dlen]
            while dlen > 0:
                key = String.parse(data)
                data = data[len(key)+1:]
                val = String.parse(data)
                data = data[len(val)+1:]
                dlen = len(data)
                self.opts[key] = val
        else:
            self.opts = opts or {}
            data = bytes()
            keys = sorted(self.opts.keys())
            for key in keys:
                val = bytes(opts[key], 'utf-8')
                key = bytes(key, 'utf-8')
                data += String.create(key)
                data += bytes('=', 'utf-8')
                data += String.create(val)
                data += bytes(';', 'utf-8')
            dlen = len(data)
            self._log.debug('len of Mapping is %d bytes' % dlen)
            dlen = struct.pack(b'>H', dlen)
            self.data = dlen + data

    def serialize(self):
        return self.data

    def __str__(self):
        return str([self.opts])


class String(object):

    @staticmethod
    def parse(data):
        dlen = util.get_as_int(data[0])
        return bytearray(data[:dlen])

    @staticmethod
    def create(data):
        if not isinstance(data, bytes):
            data = bytearray(data, 'utf-8')
        dlen = len(data)
        return struct.pack(b'>B', dlen) + data


class SigningKey:
    """
    base class for signing keys
    """

    def __init__(self, raw=None, pub=None, priv=None):
        if raw:
            # load a key from raw bytes
            self.load(raw)
        else:
            # set the keys directly
            self.pub = pub
            self.priv = priv


    def sign(self, data):
        """
        sign data with private key
        :param data: bytearray to sign
        :return: a detached signature
        """

    def verify(self, data, sig):
        """
        verify detached signature for data
        :param data: bytearray for data that was signed
        :param sig: bytearray for detached sig
        :return: True if valid signature otherwise False
        """


class CertificateType(Enum):
    NULL = 0
    HASHCASH = 1
    HIDDEN = 2
    SIGNED = 3
    MULTI = 4
    KEY = 5

class Certificate(object):

    _log = logging.getLogger('Certificate')

    @staticmethod
    def parse(data, b64=True):
        Certificate._log.debug('cert data len=%d' %len(data))
        if b64:
            data = util.i2p_b64decode(data)
        ctype = CertificateType(util.get_as_int(data[0]))
        clen = struct.unpack(b'>H', data[1:3])[0]
        return Certificate(ctype, data[3:3+clen], False)

    def __init__(self, type=CertificateType.NULL, data=bytes(), b64=True):
        if isinstance(type, int) or isinstance(type, CertificateType):
            type = CertificateType(type)
        if isinstance(type, str):
            type = type.encode('ascii')
        if isinstance(type, bytes):
            type = CertificateType(type)
        if b64:
            data = util.i2p_b64decode(data)
        self.data = data
        self.type = type
        self._log.debug('type=%s data=%s raw=%s' % (type.name, util.i2p_b64encode(data), self.serialize()))

    def __str__(self):
        return '[cert type=%s data=%s]' % (self.type.name, self.data)

    def serialize(self, b64=False):
        data = bytearray()
        data += struct.pack(b'>B', self.type.value)
        data += struct.pack(b'>H', len(self.data))
        data += self.data
        if b64:
            data = util.i2p_b64encode(data)
        return data


class KeyCertificate(Certificate):

    _log = logging.getLogger('KeyCertificate')

    @staticmethod
    def parse(data, b64=True):
        cert = Certificate.parse(data, b64)
        if cert.type == CertificateType.KEY:
            cert = KeyCertificate(cert.data, False)
        return cert

    def __init__(self, data=bytes(), b64=True):
        super().__init__(CertificateType.KEY, data, b64)
        if len(self.data) < 4:
            raise ValueError("data too short")

    @property
    def sigtype(self):
        return crypto.SigType.get_by_code(struct.unpack(b'>H', self.data[:2])[0])

    @property
    def enctype(self):
        return crypto.EncType.get_by_code(struct.unpack(b'>H', self.data[2:4])[0])

    @property
    def extra_sigkey_data(self):
        if len(self.data) <= 4:
            return None
        if self.sigtype is None:
            raise ValueError("unknown sig type")
        # XXX Assume no extra crypto key data
        extra = self.sigtype.pubkey_len - 128
        if extra <= 0:
            return None
        return self.data[4:4+extra]

    @property
    def extra_enckey_data(self):
        # XXX Assume no extra crypto key data
        return None


#
# Common data structures
#

class Destination(object):

    _log = logging.getLogger('Destination')

    @staticmethod
    def parse(data, b64=True):
        Destination._log.debug('dest data len=%d' %len(data))
        if b64:
            data = util.i2p_b64decode(data)
        cert = Certificate.parse(data[384:])
        if cert.type == CertificateType.NULL:
            return crypto.ElGamalPublicKey(data[:256]), crypto.DSAPublicKey(data[256:384]), cert, None

    @staticmethod
    def generate_dsa(fname):
        enckey , sigkey = crypto.ElGamalGenerate(), crypto.DSAGenerate()
        with open(fname, 'wb') as wf:
            wf.write(int(CertificateType.NULL.value).to_bytes(1, 'big'))
            crypto.dump_keypair(enckey, sigkey, wf)

    @staticmethod
    def load(fname):
        enckey, sigkey, cert, edkey = None, None, None, None
        with open(fname, 'rb') as rf:
            keytype = CertificateType(int.from_bytes(rf.read(1),'big'))
            if keytype == CertificateType.NULL:
                enckey, sigkey = crypto.load_keypair(rf)
                data = rf.read()
                cert = Certificate()
        if enckey and sigkey:
            return Destination(enckey, sigkey, cert)
        raise I2CPException("failed to load key from {}".format(fname))

    def __str__(self):
        return '[Destination %s %s cert=%s]' % (
            self.base32(), self.base64(),
            self.cert)

    def __init__(self, enckey=None, sigkey=None, cert=None, raw=None, b64=False, edkey=None):
        if raw:
            enckey, sigkey, cert, edkey = self.parse(raw, b64)
        self.enckey = enckey
        self.sigkey = sigkey
        self.cert = cert
        self.edkey = edkey

    def sign(self, data):
        if self.cert.type == CertificateType.NULL:
            return crypto.DSA_SHA1_SIGN(self.sigkey, data)

    def signature_size(self):
        if self.cert.type == CertificateType.NULL:
            return 40


    def dsa_verify(self, data, sig):
        crypto.DSA_SHA1_VERIFY(self.sigkey, data, sig)

    def verify(self, data, sig):
        if self.cert.type == CertificateType.NULL:
            self.dsa_verify(data, sig)
        else:
            raise exceptions.I2CPException('cannot verify data: unknown key type')

    def __len__(self):
        return len(self.serialize())

    def base32(self):
        data = self.serialize()
        return util.i2p_b32encode(crypto.sha256(data)).decode('ascii')

    def dsa_sign(self, data):
        return crypto.DSA_SHA1_SIGN(self.sigkey, data)

    def sign(self, data):
        if self.cert.type == CertificateType.NULL:
            return self.dsa_sign(data)
        else:
            raise exceptions.I2CPException('cannot sign data: unknown key type')

    def serialize(self):
        data = bytes()
        if self.cert.type == CertificateType.NULL:
            data += crypto.elgamal_public_key_to_bytes(self.enckey)
            data += crypto.dsa_public_key_to_bytes(self.sigkey)
            data += self.cert.serialize()
        self._log.debug('serialize len=%d' % len(data))
        return data

    def base64(self):
        return util.i2p_b64encode(self.serialize()).decode('ascii')


class Lease(object):

    _log = logging.getLogger('Lease')

    def __init__(self, ri_hash=None, tid=None, end_date=None):
        self.ri = ri_hash
        self.tid = tid
        self.end_date = end_date
        self._log.debug('ri_hash %d bytes'%len(ri_hash))

    def serialize(self):
        data = bytearray()
        data += self.ri
        data += struct.pack(b'>I', self.tid)
        data += self.end_date
        self._log.debug('Lease is %d bytes' % len(data))
        assert len(data) == 44
        return data

    def __repr__(self):
        return '[Lease ri=%s tid=%d]' % ([self.ri], self.tid)


class LeaseSet(object):

    _log = logging.getLogger('LeaseSet')

    def __init__(self, raw=None, dest=None, ls_enckey=None, ls_sigkey=None, leases=None):
        if raw:
            data = raw
            self.leases = []
            self.dest = Destination.parse(data)
            self._log.debug(self.dest)
            data = data[:len(self.dest)]
            self.enckey = crypto.ElGamalPublicKey(data[:256])
            self._log.debug(self.enckey)
            data = data[256:]
            self.sigkey = crypto.DSAPublicKey(data[:128])
            self._log.debug(self.sigkey)
            data = data[128:]
            numls = data[0]
            while numls > 0:
                _l = data[:44]
                l = Lease(_l[:32], _l[32:36], _l[36:44])
                data = data[44:]
                numls -= 1
                self.leases.append(l)
            self.sig = raw[:-40]
            self.dest.dsa_verify(raw[-40:], self.sig)
        else:
            self.dest = dest
            self.enckey = ls_enckey
            self.sigkey = ls_sigkey
            self.leases = list(leases)

    def __str__(self):
        return '[LeaseSet leases=%s enckey=%s sigkey=%s dest=%s]' % (
            self.leases,
            [crypto.elgamal_public_key_to_bytes(self.enckey)],
            [crypto.dsa_public_key_to_bytes(self.sigkey)],
            self.dest)

    def serialize(self):
        """
        serialize and sign LeaseSet
        only works with DSA-SHA1 right now
        """
        data = bytes()
        data += self.dest.serialize()
        data += crypto.elgamal_public_key_to_bytes(self.enckey)
        data += crypto.dsa_public_key_to_bytes(self.sigkey)
        data += int(len(self.leases)).to_bytes(1,'big')
        for l in self.leases:
            data += l.serialize()
        sig = crypto.DSA_SHA1_SIGN(self.sigkey, data)
        #self.dest.dsa_verify(data, sig, doublehash=False)
        data += sig
        self._log.debug('LS has length %d' % len(data))
        return data



class i2cp_protocol(Enum):

    STREAMING = 6
    DGRAM = 17
    RAW = 18

class datagram(object):

    def __eq__(self, obj):
        if hasattr(self, 'payload') and hasattr(obj, 'payload'):
            return self.payload == obj.payload
        return False

class raw_datagram(object):

    protocol = i2cp_protocol.RAW

    def __init__(self, dest=None, raw=None, payload=None):
        if raw:
            self.data = raw
        else:
            self.data = payload

        self.dest = None

    def serialize(self):
        return self.data

class dsa_datagram(datagram):

    protocol = i2cp_protocol.DGRAM
    _log = logging.getLogger('datagram-dsa')

    def __init__(self, dest=None, raw=None, payload=None):
        if raw:
            self._log.debug('rawlen=%d' % len(raw))
            self.data = raw
            self._log.debug('load dgram data: %s' %[ raw ])
            self.dest = Destination(raw=raw)
            self._log.debug('destlen=%s' % self.dest)
            raw = raw[len(self.dest):]
            self._log.debug('raw=%s' % [raw])
            self.sig = raw[:40]
            raw = raw[40:]
            self._log.debug('payloadlen=%d' % len(raw))
            self.payload = raw
            phash = crypto.sha256(self.payload)
            self._log.debug('verify dgram: sig=%s hash=%s' % ([self.sig], [phash]))
            self.dest.verify(phash, self.sig)
        else:
            self.dest = dest
            self.payload = payload
            self.data = bytearray()
            self.data += self.dest.serialize()
            payload_hash = crypto.sha256(self.payload)
            self.sig = self.dest.sign(payload_hash)
            self._log.debug('signature=%s' % [ self.sig])
            self.data += self.sig
            self.data += payload

    def serialize(self):
        return self.data

    def __str__(self):
        return '[DSADatagram payload=%s sig=%s]' % ( self.payload, self.sig)


class i2cp_payload(object):

    gz_header = b'\x1f\x8b\x08'

    _log = logging.getLogger('i2cp_payload')

    def __init__(self, raw=None, data=None, srcport=0, dstport=0, proto=i2cp_protocol.RAW):
        if raw:
            self.dlen = struct.unpack(b'>I', raw[:4])[0]
            self._log.debug('payload len=%d' %self.dlen)
            data = raw[4:self.dlen]
            self._log.debug('compressed payload len=%d' %len(data))
            assert data[:3] == self.gz_header
            self.flags = data[3]
            self.srcport = struct.unpack(b'>H', data[4:6])[0]
            self.dstport = struct.unpack(b'>H', data[6:8])[0]
            self.xflags = data[8]
            self.proto = i2cp_protocol(util.get_as_int(data[9]))
            self.data = util.i2p_decompress(data[10:])
            self._log.debug('decompressed=%s' % [self.data])
        else:
            if util.check_portnum(srcport) and util.check_portnum(dstport):
                self._log.debug('payload data len=%d' %len(data))
                self.data = util.i2p_compress(data)
                self._log.debug('compressed payload len=%d' % len(self.data))
                self.srcport = srcport
                self.dstport = dstport
                self.proto = i2cp_protocol(proto)
                self.flags = 0
                self.xflags = 2
            else:
                raise ValueError('invalid ports: srcport=%s dstport=%s' % ([srcport], [dstport]))

    def serialize(self):
        data = bytearray()
        data += self.gz_header
        data += struct.pack(b'>B', self.flags)
        data += struct.pack(b'>H', self.srcport)
        data += struct.pack(b'>H', self.dstport)
        data += struct.pack(b'>B', self.xflags)
        data += struct.pack(b'>B', self.proto.value)
        data += self.data
        dlen = len(data)
        self._log.debug('serialize len=%d' % dlen)
        return struct.pack(b'>I', dlen) + data


    def __str__(self):
        return '[Payload flags=%s srcport=%s dstport=%s xflags=%s proto=%s data=%s]' % (
            self.flags,
            self.srcport,
            self.dstport,
            self.xflags,
            self.proto,
            self.data)


def to_b32_bytes(val):
    if isinstance(val, Destination):
        return to_b32_bytes(val.base64())
    if isinstance(val, bytes):
        if val.lower().endswith(b".b32.i2p"):
            return util.i2p_b32decode(val)
        else:
            return crypto.sha256(vale)
    raise TypeError("invalid type", val)
