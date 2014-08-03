#!/usr/bin/env python3.4

import logging
import struct
import socket
from enum import Enum

from i2cp.util import *
from i2cp.datatypes import *

PROTOCOL_VERSION = b'\x2a'
BUFFER_SIZE = 1024 * 16
NO_SESSION_ID = b'\xff\xff'





class I2CPException(Exception):
    pass

class Message:
    """
    i2cp message
    """
    
    _log = logging.getLogger('I2CP-Message')

    @staticmethod
    def parse(data):
        """
        raw data -> Message
        """
        Message._log.debug('parse raw data %s' % data)
        dlen = len(data)
        if dlen < 5:
            raise I2CPException('data too short, %d bytes' % len(data))
        _len, _type = struct.unpack('>IB', data[:5])
        if _len + 5 != dlen:
            raise I2CPException('incorrect i2cp message, expected %d bytes got %d' % (_len , dlen - 5))
        _data = data[6:dlen]
        return message_type(_type), _data


    def __init__(self, type=None, body=None, raw=None):
        if raw:
            type, body = self.parse(raw)
        self._log.debug('new message: type={} body={}'.format(type, body))
        self._type = type
        self.body = body or bytearray()

    def serialize(self):
        """
        serialize to bytearray
        """
        hdr = struct.pack('>IB', len(self.body), self._type.value)
        hdr += self.body
        return hdr

    def deserialize(self):
        """
        deserialize message
        """

class HostLookupMessage(Message):
    """
    Host Lookup Message
    Send this to initiate a host lookup
    """


    def __init__(self, name=None, sid=None, raw=None, req_timeout=5.0):
        if raw:
            Message.__init__(self, raw=raw)
            self.sid = struct.unpack('>H', self.body[2:])
            self.reqid = struct.unpack('>I', self.body[3:7])
            self.reqtype = self.body[8]
            if self.reqtype == 0:
                self.name = hash_to_b32(body[9:41])
            else:
                self.name = i2cp_string.parse(body[9:])
        else:    
            body = bytearray()
            body += struct.pack('>H', sid or NO_SESSION_ID)
            body += timeout(req_timeout)
            if isdesthash(name):
                body += struct.pack('>I', 0)
                body += b32_to_bytes(name)
            else:
                body += struct.pack('>I', 1)
                body += i2cp_string.create(name)
            Message.__init__(self, message_type.HostLookup, body)
        
class HostLookupReplyMessage(Message):

    def __init__(self, name=None, sid=None, raw=None):
        if raw:
            Message.__init__(self, raw)
            self.sid = struct.unpack('>H', self.body[:2])
            self.reqid = struct.unpack('>I', self.body[3:7])
            code = self.body[8]
            if code == 0:
                self.
        else:
            raise NotImplemented()

class Connection:

    def __init__(self, i2cp_host='127.0.0.1', i2cp_port=7654):
        self._i2cp_addr = (i2cp_host, i2cp_port)
        self._sock = socket.socket()
        self._log = logging.getLogger('I2CP-Connection-%s-%d' % self._i2cp_addr)
        self._sid = None

    def open(self):
        self._log.info('connecting...')
        self._sock.connect(self._i2cp_addr)
        self._send_raw(PROTOCOL_VERSION)
        
    def start_session(self, opts={}):
        msg = Message(message_type.GetDate)
        self._send_raw(msg)
        data = self._recv_raw()
        msg = Message(raw=data)
        if msg.type != message_type.SetDate:
            raise I2CPException('expected SetDate Message but got %s Message' % msg.type.name)
    
    def _recv_raw(self, dlen=BUFFER_SIZE):
        self._log.debug('recv %d...' % dlen)
        data = self._sock.recv(dlen)
        self._log.debug('recv %d bytes' % len(data))
        self._log.debug('<-- %s' % data)
        return data

    def _send_raw(self, data):
        if isinstance(data, str):
            data = bytearray(data, 'utf-8')
        elif isinstance(data, Message):
            data = data.serialize()
        self._log.debug('--> %s' % data)
        try:
            sent = self._sock.send(data)
        except Exception as e:
            self._log.error('cannot send', e)
        else:
            self._log.debug('sent %d bytes' % sent)

    def lookup(self, name):
        msg = HostLookupMessage(name, self._sid)
        self._send_raw(msg)
        data = self._recv_raw()
        msg = Message(raw=data)
        if msg.reply == 0:
            return msg.destination
        

    def close(self):
        self._log.info('closing connection...')
        msg = Message(message_type.Disconnect)
        self._send_raw(msg)
        self._sock.close()


def lookup(name):
    con = Connection()
    con.open()
    result = con.lookup()
    con.close()
    return result

def main():
    logging.basicConfig(level=logging.DEBUG)
    result = lookup('irc.postman.i2p')
    print (result)


if __name__ == '__main__':
    main()
