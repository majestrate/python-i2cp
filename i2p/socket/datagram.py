from i2p.i2cp.crypto import *
from i2p.i2cp.datatypes import *
from i2p.i2cp.exceptions import *
from i2p.i2cp.util import *


def parse_datagram(raw):
    """
    given raw data build the appropriate datagram
    :return: a datagram from raw data
    """
    payload = i2cp_payload(raw=raw)
    classes = {
        i2cp_protocol.RAW: datagram,
        i2cp_protocol.DGRAM: dsa_datagram,
        i2cp_protocol.DGRAM_25519: curve25519_dgram
    }
    if payload.proto in classes:
        return classes[payload.proto](raw=raw)

class dsa_datagram(datagram):
    """
    dsa signed datagram
    """

    protocol = i2cp_protocol.DGRAM
    _log = logging.getLogger('datagram-dsa')

    def __init__(self, dest=None, raw=None, payload=None, srcport=0, dstport=0):
        if raw:
            self._log.debug('rawlen=%d' % len(raw))
            self.raw = raw
            self._log.debug('load dgram data: %s' % raw)
            self.dest = destination(raw=raw)
            self._log.debug('destlen=%s' % self.dest)
            raw = raw[len(self.dest):]
            self._log.debug('raw=%s' % raw)
            self.sig = raw[:40]
            raw = raw[40:]
            self._log.debug('payloadlen=%d' % len(raw))
            payload = raw
            phash = sha256(payload)
            self._log.debug('verify dgram: sig=%s hash=%s' % (self.sig, phash))
            self.dest.verify(phash, self.sig)
        else:
            self.dest = dest
            self.payload = payload
            self.raw = bytearray()
            self.raw += self.dest.serialize()
            payload_hash = sha256(self.payload)
            self.sig = self.dest.sign(payload_hash)
            self._log.debug('signature=%s' % self.sig)
            self.raw += self.sig + self.payload

        datagram.__init__(self, payload, srcport, dstport) 

    def serialize(self):
        """
        serialize for sending over i2cp
        """
        return self.raw

    def __str__(self):
        return '[DSADatagram payload=%s sig=%s]' % ( self.data, self.sig) 


class curve25519_datagram(datagram):
    """
    curve25519 signed datagram
    """
    protocol = i2cp_protocol.DGRAM_ED25519
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
            if self.dest.cert.type == certificate_type.ED25519:
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
        elif dest.cert.type == certificate_type.ED25519:
            self.dest = dest
            self.payload = date()
            self.payload += payload
            self.data = bytearray()
            self.data += self.dest.serialize()
            self.data += self.dest.sign(self.payload)
        else:
            raise I2CPException('cannot construct curve25519 datagram with param: %s %s %s' %(dest, raw, payload))
            

    def serialize(self):
        """
        serialize for sending over i2cp
        """
        return self.data

    def __str__(self):
        return '[Curve25519Datagram payload=%s sig=%s]' % ( self.payload, self.sig) 

