from .util import *
from .crypto import *
from enum import Enum
import logging
import struct
import time
import zlib



class certificate_type(Enum):
    NULL = 0
    HASHCASH = 1
    HIDDEN = 2
    SIGNED = 3
    MULTI = 4
    KEY = 5

class certificate:

    _log = logging.getLogger('certificate')

    def __init__(self, dlen=0, type=certificate_type.NULL, data=bytearray(), b64=True, raw=None):
        if raw:
            raise NotImplemented()
        else:
            if isinstance(type, int) or isinstance(type, certificate_type):
                type = certificate_type(type)
            if isinstance(type, str):
                type = type.encode('ascii')
            if isinstance(type, bytes):
                type = certificate_type(i2p_b64decode(type))
            if b64:
                data = i2p_b64decode(data)
            self.data = data
            self.type = type
        self._log.debug('type=%s data=%s' % (type.name, i2p_b64encode(data)))

             
    def __str__(self):
        return '[cert type=%s data=%s]' % (self.type.name, self.data)

    def serialize(self, b64=False):
        data = bytearray()
        data += struct.pack('>H', len(self.data))
        data += struct.pack('>B', self.type.value)
        data += self.data
        if b64:
            data = i2p_b64_encode(data)
        return data
        
class leaseset:

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
            self.dest.sigkey.verify(raw[-40:], self.sig)
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
        data += len(self.leases).to_bytes(1,'big')
        for l in self.leases:
            data += l.serialize()
        sig = self.dest.sign(data)
        self.dest.verify(data, sig)
        return data + sig

class destination:

    _log = logging.getLogger('destination')

    @staticmethod
    def parse(data, b64=True):
        if b64:
            data = i2p_b64decode(data)
        ctype = certificate_type(data[384])
        clen = struct.unpack('>H', data[385:368])
        cert = certificate(clen ,ctype, data)
        if cert.type == certificate_type.NULL:
            return ElGamalPublicKey(data[:255]), DSAPublicKey(data[255:383]), cert
        

    @staticmethod
    def generate(fname):
        enckey , sigkey = ElGamalGenerate(), DSAGenerate()
        with open(fname, 'wb') as wf:
            dump_keypair(enckey, sigkey, wf)

    @staticmethod
    def load(fname):
        with open(fname, 'rb') as rf:
            enckey, sigkey = load_keypair(rf)
            data = rf.read()
            cert = certificate()
        return destination(enckey, sigkey, cert)

    def __str__(self):
        return '[Destination %s %s]' % (self.base32(), self.base64())

    def __init__(self, enckey=None, sigkey=None, cert=None, raw=None):
        if raw:
            enckey, sigkey, cert = self.parse(raw, False)
        self.enckey = enckey 
        self.sigkey = sigkey 
        self.cert = cert 

    def sign(self, data):
        sig = DSA_SHA1_SIGN(self.sigkey, data)
        self._log.debug('sign data=%s sig=%s' % (data, sig))
        return sig
        
    def verify(self, data, sig):
        self._log.debug('verify data=%s sig=%s' % (data, sig))
        DSA_SHA1_VERIFY(self.sigkey, data, sig)

    def __len__(self):
        return len(self.serialize())
        
    def base32(self):
        data = bytearray()
        data += elgamal_public_key_to_bytes(self.enckey)
        data += dsa_public_key_to_bytes(self.sigkey)
        data += self.cert.serialize()
        return i2p_b32encode(sha256(data))

    def sign(self, data):
        return DSA_SHA1_SIGN(self.sigkey, data)
        
    def serialize(self):
        data = bytearray()
        if self.cert.type == certificate_type.NULL:
            data += elgamal_public_key_to_bytes(self.enckey)
            data += dsa_public_key_to_bytes(self.sigkey)
            data += self.cert.serialize()        
        self._log.debug('serialize len=%d' % len(data))
        return data

    def base64(self):
        return i2p_b64encode(self.serialize())

class i2p_string:

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

class router_identity:

    def __init__(self, raw=None, enckey=None, sigkey=None, cert=None):
        if raw:
            self.enckey = ElGamalPublicKey(raw[256:])
            self.sigkey = DSAPublicKey(raw[256:384])
            self.cert = certificate(raw[384:])
        else:
            self.enckey = enckey 
            self.sigkey = sigkey 
            self.cert = cert 

    def __len__(self):
        return len(self.serialize())

    def __str__(self):
        return '[RouterIdentity enckey=%s sigkey=%s cert=%s]' % (
            elgamal_public_key_to_bytes(self.enckey),
            dsa_public_key_to_bytes(self.sigkey),
            self.cert)

    def serialize(self):
        data = bytearray()
        data += elgamal_public_key_to_bytes(self.enckey)
        data += dsa_public_key_to_bytes(self.sigkey)
        data += self.cert.serialize()
        return data

class lease:

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



class mapping:
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

class i2cp_payload:

    gz_header = b'\x1f\x8b\x08'

    _log = logging.getLogger('i2cp_payload')

    def __init__(self, raw=None, data=None, srcport=0, dstport=0, proto=i2cp_protocol.RAW):
        if raw:
            self.dlen = struct.unpack('>I', raw[:4])[0]
            data = raw[4:self.dlen]
            self.flags = data[3]
            self.srcport = struct.unpack('>H', data[3:5])[0]
            self.dstport = struct.unpack('>H', data[5:7])[0]
            self.xflags = data[7]
            #self.proto = i2cp_protocol.STREAMING
            self.proto = i2cp_protocol(data[8])
            self.data = inflate(data)
        else:
            self.data = data
            self.srcport = srcport
            self.dstport = dstport
            self.proto = i2cp_protocol(proto)
            self.flags = 0
            self.xflags = 2

    def serialize(self):
        pass


    def __str__(self):
        return '[Payload flags=%s srcport=%s dstport=%s xflags=%s proto=%s dlen=%d]' % (
            self.flags,
            self.srcport,
            self.dstport,
            self.xflags,
            self.proto,
            len(self.data))
