#!/usr/bin/env python3.4

import logging
import random
import struct

from .util import *
from .datatypes import *


class message_type(Enum):
    CreateSession = 1
    ReconfigSession = 2
    DestroySession = 3
    CreateLS = 4
    SendMessage = 5
    RecvMessageBegin = 6
    RecvMessageEnd = 7
    GetBWLimits = 8
    SessionStatus = 20
    RequestLS = 21
    MessageStatus = 22
    BWLimits = 23
    ReportAbuse = 29
    Disconnect = 30
    MessagePayload = 31
    GetDate = 32
    SetDate = 33
    DestLookup = 34
    DestLookupRely = 35
    SendMessageExpires = 36
    RequestVarLS = 37
    HostLookup = 38
    HostLookupReply = 39



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
        dlen = len(data)
        if dlen < 5:
            raise I2CPException('data too short, %d bytes' % len(data))
        _len, _type = struct.unpack('>IB', data[:5])
        if _len + 5 != dlen:
            raise I2CPException('incorrect i2cp message, expected %d bytes got %d' % (_len , dlen - 5))
        _data = data[5:dlen]
        return message_type(_type), _data


    def __init__(self, type=None, body=None, raw=None):
        if raw:
            type, body = self.parse(raw)
        self.type = type
        self.body = body or bytearray()

    def serialize(self):
        """
        serialize to bytearray
        """
        hdr = struct.pack('>IB', len(self.body), self.type.value)
        hdr += self.body
        return hdr

    def __str__(self):
        return '[I2CPMessage type=%s body=%s]' % (self.type.name, self.body)

class HostLookupMessage(Message):
    """
    Host Lookup Message
    Send this to initiate a host lookup
    """


    def __init__(self, name=None, sid=None, rid=None, raw=None, req_timeout=5.0):
        if raw:
            raise NotImplemented()
        else:    
            self.name = name
            if isinstance(req_timeout, float):
                req_timeout *= 1000
            self.timeout = int(req_timeout)
            self.sid = sid or NO_SESSION_ID
            self.rid = rid or random().randint(1, 2 ** 16)
            body = bytearray()
            body += struct.pack('>H', self.sid)
            body += struct.pack('>I', self.rid)
            body += struct.pack('>I', self.timeout)
            self.req_type = 1
            if isdesthash(name):
                name = b32_to_bytes(name)
            else:
                name = i2p_string.create(name)

            body += struct.pack('>B', self.req_type)
            body += name
            Message.__init__(self, type=message_type.HostLookup, body=body)
        

    def __str__(self):
        return '[HostLookupMessage reqid=%d sid=%d timeout=%dms name=%s reqtype=%d]' % (
            self.rid, self.sid, self.timeout, self.name, self.req_type)

class HostLookupReplyMessage(Message):

    def __init__(self, name=None, sid=None, raw=None):
        if raw:
            Message.__init__(self, raw=raw)
            self.sid = struct.unpack('>H', self.body[:2])[0]
            self.rid = struct.unpack('>I', self.body[2:6])[0]
            self.code = self.body[6]
            self.dest = None
            if self.code == 0:
                self.dest = destination(raw=self.body[7:],b64=False)
        else:
            raise NotImplemented()

    def __str__(self):
        return '[HostLookupReply sid=%d rid=%d code=%d]' % (self.sid, self.rid, self.code)


class CreateSessionMessage(Message):
    
    def __init__(self, opts=None, date=None, dest=None, raw=None):
        if raw:
            Message.__init__(self, raw)
        else:
            self.opts = opts
            data = bytearray()
            _dest = dest.serialize()
            self._log.debug('dest len: %d' % len(_dest))
            opts = mapping(self.opts).serialize()
            self._log.debug('opts: %s' % opts)
            data += _dest
            data += opts
            data += date
            data += dest.sign(data)
            type = message_type.CreateSession
            Message.__init__(self, type, data)

    def __str__(self):
        return '[CreateSession opts=%s]' % self.opts

class RequestLSMessage(Message):

    _log = logging.getLogger(__name__)
    
    def __init__(self, raw):
        Message.__init__(self, raw=raw)
        raw = self.body
        self.leases = []
        self.sid = struct.unpack('>H',raw[:2])
        numtun  = raw[2]
        self._log.debug('got %d leases' % numtun)
        raw = raw[3:]
        while numtun > 0:
            ri = raw[:32]
            raw = raw[32:]
            tid = struct.unpack('>I', raw[:4])[0]
            raw = raw[4:]
            numtun -= 1
            self.leases.append(lease(ri_hash=ri, tid=tid))
        self._log.debug('left over data: %d bytes' % len(raw))
        self.date = date(raw)

    def __str__(self):
        return '[RequestLS sid=%d date=%s leases=%s date=%s]' % (self.sid,
                                                                 self.date, 
                                                                 self.leases, 
                                                                 self.date)

class CreateLSMessage(Message):

    _log = logging.getLogger('CreateLS')

    def __init__(self, raw=None, sid=None, sigkey=None, enckey=None, leaseset=None):
        if raw:
            raise NotImplemented()
        else:
            body = bytearray()
            body += struct.pack('>H', sid)
            body += dsa_private_key_to_bytes(sigkey)
            body += elgamal_private_key_to_bytes(enckey)
            body += leaseset.serialize()
            Message.__init__(self, type=message_type.CreateLS, body=body)
            self.sid = sid
            self.sigkey = sigkey 
            self.enckey = enckey
            self.ls = leaseset
        
    def __str__(self):
        return '[CreateLS sid=%s leasesets=%s]' % (
            self.sid, 
            self.ls)

class DisconnectMessage(Message):

    def __init__(self, raw=None, reason='kthnxbai'):
        if raw:
            Message.__init__(self, raw=raw)
            self.reason = i2p_string.parse(self.body)
        else:
            Message.__init__(self, message_type.Disconnect, i2p_string.create(reason))
            self.reason = reason

    def __str__(self):
        return '[Disconnect %s]' % self.reason

class session_status(Enum):

    DESTROYED = 0
    CREATED = 1
    UPDATED = 2
    INVALID = 3
    REFUSED = 4
    

class SessionStatusMessage(Message):
    
    _log = logging.getLogger('SessionStatus')

    def __init__(self, raw):
        Message.__init__(self, raw=raw)
        self.sid = struct.unpack('>H', self.body[:2])[0]
        self._log.debug('sid=%d' % self.sid)
        status = self.body[2]
        self.status = session_status(status)

    def __str__(self):
        return '[SessionStatus sid=%d status=%s]' % (self.sid, self.status.name)


class MessagePayloadMessage(Message):

    _log = logging.getLogger('MessagePayload')

    def __init__(self, raw):
        Message.__init__(self,raw=raw)
        data = self.body
        self.sid = struct.unpack('>H', data[:2])
        self.mid = struct.unpack('>I', data[2:6])
        self.payload = i2cp_payload(raw=data[7:])

    def __str__(self):
        return '[MessagePayload sid=%d mid=%d payload=%s]' % (self.sid, self.mid, self.payload)

class SendMessageMessage(Message):

    def __init__(self, sid, dest, payload, nonce=None):

        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        if nonce is None:
            nonce = sid
            while nonce == sid:
                nonce = random().randint(0, 2 ** 32)                
        body = bytearray()
        body += struct.unpack('>H', sid)
        body += dest.serialize()
        body += payload
        body += struct.pack('>I', nonce)
        Message.__init__(self, type=message_type.SendMessage, body=body)
        self.sid = sid
        self.dest = dest
        self.payload = payload
        self.nonce = nonce

    def __str__(self):
        return '[SendMessage nonce=%d sid=%s dest=%s payload=%s]' % ( self.nonce, self.sid, self.dest, self.payload)
