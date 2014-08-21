from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from future.builtins import bytes
from future.builtins import int
from future.builtins import open
from future.builtins import str
from future import standard_library
standard_library.install_hooks()
from future.builtins import object

from .util import *
from .crypto import *
from enum import Enum
import logging
import struct
import time


class certificate_type(Enum):
    NULL = 0
    HASHCASH = 1
    HIDDEN = 2
    SIGNED = 3
    MULTI = 4
    KEY = 5
    CURVE25519 = 15

class certificate(object):

    _log = logging.getLogger('certificate')

    def __init__(self, type=certificate_type.NULL, data=bytearray(), b64=True):
        
        if isinstance(type, int) or isinstance(type, certificate_type):
            type = certificate_type(type)
        if isinstance(type, str):
            type = type.encode('ascii')
        if isinstance(type, bytes):
            type = certificate_type(type)
        if b64:
            data = i2p_b64decode(data)
        self.data = data
        self.type = type
        self._log.debug('type=%s data=%s raw=%s' % (type.name, i2p_b64encode(data), self.serialize()))


    def __str__(self):
        return '[cert type=%s data=%s]' % (self.type.name, self.data)

    def serialize(self, b64=False):
        data = bytearray()
        data += struct.pack('>B', self.type.value)
        data += struct.pack('>H', len(self.data))
        data += self.data
        if b64:
            data = i2p_b64encode(data)
        return data

class leaseset(object):

    _log = logging.getLogger('leaseset')

    def __init__(self, raw=None, dest=None, ls_enckey=None, ls_sigkey=None, leases=None):
        if raw:
            data = raw
            self.leases = []
            self.dest = destination.parse(data)
            self._log.debug(self.dest)
            data = data[:len(self.dest)]
            self.enckey = ElGamalPublicKey(data[:256])
            self._log.debug(self.enckey)
            data = data[256:]
            self.sigkey = DSAPublicKey(data[:128])
            self._log.debug(self.sigkey)
            data = data[128:]
            numls = data[0]
            while numls > 0:
                l = data[:44]
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
            elgamal_public_key_to_bytes(self.enckey),
            dsa_public_key_to_bytes(self.sigkey),
            self.dest)

    def serialize(self):
        """
        serialize and sign leaseset
        only works with DSA-SHA1 right now
        """
        data = bytearray()
        data += self.dest.serialize()
        data += elgamal_public_key_to_bytes(self.enckey)
        data += dsa_public_key_to_bytes(self.sigkey)
        data += int(len(self.leases)).to_bytes(1,'big')
        for l in self.leases:
            data += l.serialize()
        sig = self.dest.dsa_sign(data)
        self.dest.dsa_verify(data, sig)
        return data + sig

class destination(object):

    _log = logging.getLogger('destination')

    @staticmethod
    def parse(data, b64=True):
        destination._log.debug('dest len=%d' %len(data))
        if b64:
            data = i2p_b64decode(data)
        ctype = certificate_type(data[384])
        clen = struct.unpack('>H', data[385:387])[0]
        cert = certificate(ctype, data[387:387+clen])
        if cert.type == certificate_type.NULL:
            return ElGamalPublicKey(data[:256]), DSAPublicKey(data[256:384]), cert, None
        elif cert.type == certificate_type.CURVE25519:
            return None, DSAPublicKey(data[256:384]), cert, NaclPublicKey(data[:32])

    @staticmethod
    def generate_dsa(fname):
        enckey , sigkey = ElGamalGenerate(), DSAGenerate()
        with open(fname, 'wb') as wf:
            wf.write(certificate_type.NULL.value.to_bytes(1, 'big'))
            dump_keypair(enckey, sigkey, wf)

    @staticmethod
    def generate_curve25519(fname):
        edkey = NaclGenerate()
        sigkey = DSAGenerate()
        with open(fname, 'wb') as wf:
            wf.write(certificate_type.CURVE25519.value.to_bytes(1, 'big'))
            wf.write(edkey.encode())
            dsa_dump_key(sigkey, wf)

    @staticmethod
    def load(fname):
        enckey, sigkey, cert, edkey = None, None, None, None
        with open(fname, 'rb') as rf:
            keytype = certificate_type(int.from_bytes(rf.read(1),'big'))
            if keytype == certificate_type.NULL:
                enckey, sigkey = load_keypair(rf)
                data = rf.read()
                cert = certificate()
            elif keytype == certificate_type.CURVE25519:
                edkey = nacl.SigningKey(rf.read(32))
                sigkey = DSAKey(fd=rf)
                cert = certificate(type=keytype)
        if edkey:
            return destination(enckey, sigkey, cert, edkey=edkey)
        return destination(enckey, sigkey, cert)

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
        sig = None
        if self.cert.type == certificate_type.NULL:
            sig = DSA_SHA1_SIGN(self.sigkey, data)
        elif self.cert.type == certificate_type.CURVE25519:
            sig = self.edkey.sign(data)
        return sig

    def dsa_verify(self, data, sig):
        DSA_SHA1_VERIFY(self.sigkey, data, sig)

    def verify(self, data, sig):
        if self.cert.type == certificate_type.NULL:
            self.dsa_verify(data, sig)
        elif self.cert.type == certificate_type.CURVE25519:
            return self.sigkey.verify_key.verify(data)

    def __len__(self):
        return len(self.serialize())

    def base32(self):
        data = self.serialize()
        return i2p_b32encode(sha256(data)).decode('ascii')

    def dsa_sign(self, data):
        return DSA_SHA1_SIGN(self.sigkey, data)

    def sign(self, data):
        if self.cert.type == certificate_type.NULL:
            return self.dsa_sign(data)
        elif self.cert.type == certificate_type.CURVE25519:
            return self.edkey.sign(bytes(data))
        
    def serialize(self):
        data = bytearray()
        if self.cert.type == certificate_type.NULL:
            data += elgamal_public_key_to_bytes(self.enckey)
            data += dsa_public_key_to_bytes(self.sigkey)
            data += self.cert.serialize()        
        elif self.cert.type == certificate_type.CURVE25519:
            data += nacl_key_to_public_bytes(self.edkey)
            data += b'\x00' * ( 256 - 32 )
            data += dsa_public_key_to_bytes(self.sigkey)
            data += self.cert.serialize()
        self._log.debug('serialize len=%d' % len(data))
        return data

    def base64(self):
        return i2p_b64encode(self.serialize()).decode('ascii')

class i2p_string(object):

    @staticmethod
    def parse(data):
        if isinstance(data, str):
            data = bytearray(data, 'utf-8')
        dlen = data[0]
        return data[:dlen].decode('utf-8')

    @staticmethod
    def create(data):
        if isinstance(data, str):
            data = bytearray(data, 'utf-8')
        dlen = len(data)
        return struct.pack('>B', dlen) + data

class lease(object):

    _log = logging.getLogger('lease')

    def __init__(self, ri_hash=None, tid=None):
        self.ri = ri_hash
        self.tid = tid
        self.data = bytearray()
        self._log.debug('ri_hash %d bytes'%len(ri_hash))
        assert len(ri_hash) == 32
        self.data += ri_hash
        self.data += struct.pack('>I', tid)
        self.data += date()
        self._log.debug('lease is %d bytes' % len(self.data))
        assert len(self.data) == 44

    def serialize(self):
        return self.data

    def __repr__(self):
        return '[Lease ri=%s tid=%d]' % (self.ri, self.tid)



class mapping(object):
    """
    i2p dictionary object
    it sucks
    """

    _log = logging.getLogger('mapping')

    def __init__(self, opts=None, raw=None):
        if raw:
            self.data = raw
            self.opts = {}
            dlen = struct.unpack('>H', raw[:2])
            data = raw[2:2+dlen]
            while dlen > 0:
                key = i2p_string.parse(data)
                data = data[len(key)+1:]
                val = i2p_string.parse(data)
                data = data[len(val)+1:]
                dlen = len(data)
                self.opts[key] = val
        else:
            self.opts = opts or {}
            data = bytearray()
            keys = sorted(self.opts.keys())
            for key in keys:
                val = str(opts[key])
                data += i2p_string.create(key) + b'='
                data += i2p_string.create(val) + b';'
            dlen = len(data)
            self._log.debug('len of mapping is %d bytes' % dlen)
            dlen = struct.pack('>H', dlen)
            self.data = dlen + data

    def serialize(self):
        return self.data

    def __str__(self):
        return str(self.opts)

def date(num=None):
    if isinstance(num, bytes):
        num = struct.unpack('>Q', num)[0]
    if num is None:
        num = time.time() * 1000
    num = int(num)
    return struct.pack('>Q', num)

class i2cp_protocol(Enum):

    STREAMING = 6
    DGRAM = 17
    RAW = 18
    DGRAM_CURVE25519 = 23

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
            self._log.debug('load dgram data: %s' % raw)
            self.dest = destination(raw=raw)
            self._log.debug('destlen=%s' % self.dest)
            raw = raw[len(self.dest):]
            self._log.debug('raw=%s' % raw)
            self.sig = raw[:40]
            raw = raw[40:]
            self._log.debug('payloadlen=%d' % len(raw))
            self.payload = raw
            phash = sha256(self.payload)
            self._log.debug('verify dgram: sig=%s hash=%s' % (self.sig, phash))
            self.dest.verify(phash, self.sig)
        else:
            self.dest = dest
            self.payload = payload
            self.data = bytearray()
            self.data += self.dest.serialize()
            payload_hash = sha256(self.payload)
            self.sig = self.dest.sign(payload_hash)
            self._log.debug('signature=%s' % self.sig)
            self.data += self.sig + self.payload

    def serialize(self):
        return self.data

    def __str__(self):
        return '[DSADatagram payload=%s sig=%s]' % ( self.payload, self.sig) 


class curve25519_datagram(datagram):

    protocol = i2cp_protocol.DGRAM_CURVE25519
    _log = logging.getLogger('datagram-curve25519')
    max_age  = 30 * 1000


    def __init__(self, dest=None, raw=None, payload=None):
        if raw:
            self._log.debug('rawlen=%d' % len(raw))
            self.data = raw
            self._log.debug('load dgram data: %s' % raw)
            self.dest = destination(raw=raw)
            self._log.debug('destlen=%s' % self.dest)
            raw = raw[len(self.dest):]
            if self.dest.cert.type == certificate_type.CURVE25519:
                payload = self.dest.edkey.verify(raw)
                now = int(time.time() * 1000)
                dlt = now - struct.unpack('>Q',payload[:8])[0]
                if abs(dlt) < self.max_age:
                    self.payload = payload[8:]
                else:
                    self._log.error('datagram sage is %d ms, dropping' % dlt)
                    self.payload = bytearray()
            else:
                raise I2CPException('invalid cert: type=%s' % dest.cert.type)
        elif dest.cert.type == certificate_type.CURVE25519:
            self.dest = dest
            self.payload = date()
            self.payload += payload
            self.data = bytearray()
            self.data += self.dest.serialize()
            self.data += self.dest.sign(self.payload)
        else:
            raise I2CPException('cannot construct curve25519 datagram with param: %s %s %s' %(dest, raw, payload))
            

    def serialize(self):
        return self.data

    def __str__(self):
        return '[Curve25519 Datagram payload=%s sig=%s]' % ( self.payload, self.sig)
    

class i2cp_payload(object):

    gz_header = b'\x1f\x8b\x08'

    _log = logging.getLogger('i2cp_payload')

    def __init__(self, raw=None, data=None, srcport=0, dstport=0, proto=i2cp_protocol.RAW):
        if raw:
            self.dlen = struct.unpack('>I', raw[:4])[0]
            self._log.debug('payload len=%d' %self.dlen)
            data = raw[4:self.dlen]
            self._log.debug('compressed payload len=%d' %len(data))
            assert data[:3] == self.gz_header
            self.flags = data[3]
            self.srcport = struct.unpack('>H', data[4:6])[0]
            self.dstport = struct.unpack('>H', data[6:8])[0]
            self.xflags = data[8]
            self.proto = i2cp_protocol(data[9])
            self.data = i2p_decompress(data[10:])
            self._log.debug('decompressed=%s' % self.data)
        else:
            if check_portnum(srcport) and check_portnum(dstport):
                self._log.debug('payload data len=%d' %len(data))
                self.data = i2p_compress(data)
                self._log.debug('compressed payload len=%d' % len(self.data))
                self.srcport = srcport
                self.dstport = dstport
                self.proto = i2cp_protocol(proto)
                self.flags = 0
                self.xflags = 2
            else:
                raise ValueError('invalid ports: srcport=%s dstport=%s' % (srcport, dstport))

    def serialize(self):
        data = bytearray()
        data += self.gz_header
        data += struct.pack('>B', self.flags)
        data += struct.pack('>H', self.srcport)
        data += struct.pack('>H', self.dstport)
        data += struct.pack('>B', self.xflags)
        data += struct.pack('>B', self.proto.value)
        data += self.data
        dlen = len(data)
        self._log.debug('serialize len=%d' % dlen)
        return struct.pack('>I', dlen) + data


    def __str__(self):
        return '[Payload flags=%s srcport=%s dstport=%s xflags=%s proto=%s data=%s]' % (
            self.flags,
            self.srcport,
            self.dstport,
            self.xflags,
            self.proto,
            self.data)

