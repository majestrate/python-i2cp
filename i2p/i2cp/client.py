from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from future import standard_library
standard_library.install_hooks()

import logging
import os
import socket
import threading
from .exceptions import *
from .messages import *
from .datatypes import *
from .util import *

class Connection(threading.Thread):

    def __init__(self, handlers={}, i2cp_host='127.0.0.1', i2cp_port=7654):
        self._i2cp_addr = (i2cp_host, i2cp_port)
        self._sock = socket.socket()
        self._log = logging.getLogger('I2CP-Connection-%s-%d' % self._i2cp_addr)
        self._sid = None
        self.dest = None
        self._pending_name_lookups = {}
        self._hosts = {}
        self._send_lock = threading.Lock()
        dgram = lambda x, y, z : self._log.info('dgram %d -> %d || %s' % (y, z, x))
        self._got_dgram = 'dgram' in handlers and handlers['dgram'] or dgram
        threading.Thread.__init__(self)

    def open(self):
        self._log.debug('connecting...')
        self._sock.connect(self._i2cp_addr)
        self._send_raw(PROTOCOL_VERSION)

    def generate_dest(self, keyfile):
        if not os.path.exists(keyfile):
            destination.generate(keyfile)
        self.dest = destination.load(keyfile)

    def _recv_msg(self):
        sfd = self._sock.makefile('rb')
        msg, raw = Message.parse(sfd, parts=False)
        sfd.close()
        self._log.debug('got message: %s' %msg)
        return msg, raw


    def start_session(self, opts, keyfile='keys.dat'):
        if self.dest is None:
            self.generate_dest(keyfile)
        self._log.info('out dest is %s' % self.dest.base32())
        msg = Message(message_type.GetDate)
        self._send_raw(msg)
        msg, raw = self._recv_msg()
        if msg.type != message_type.SetDate:
            raise I2CPException('expected SetDate Message but got %s Message' % msg.type.name)
        msg = CreateSessionMessage(dest=self.dest, opts=opts, date=date())
        self._send_raw(msg)
        msg, raw = self._recv_msg()
        if msg.type == message_type.RequestLS:
            self._handle_request_ls(raw)
        elif msg.type == message_type.SessionStatus:
            msg = SessionStatusMessage(raw=raw)
            self._log.debug('session status: %s' % msg)
            self._sid = msg.sid
            if msg.status == session_status.REFUSED:
                self._log.error('session rejected')
            elif msg.status == session_status.DESTROYED:
                self._log.error('session destroyed')
            elif msg.status == session_status.CREATED:
                self._sid = msg.sid
                msg, raw = self._recv_msg()
                self._handle_request_ls(raw)
        else:
            self.close()
        self.start()

    def _handle_request_ls(self, raw):
        msg = RequestLSMessage(raw=raw)
        l = msg.leases[0]
        enckey = ElGamalGenerate()
        sigkey = DSAGenerate()
        ls = leaseset(leases=[l],dest=self.dest, ls_enckey=enckey, ls_sigkey=sigkey)
        msg = CreateLSMessage(
            sid=self._sid,
            sigkey=sigkey,
            enckey=enckey,
            leaseset=ls)
        self._log.debug(msg)
        self._send_raw(msg)

    def run(self):
        while True:
            data = self._recv_raw()
            if data is None:
                break
            msg = Message(raw=data)
            self._handle_message(data, msg)

    def _handle_message(self, raw, msg):
        if msg is None or msg.type is None:
            self._log.warn('bad message')
            return
        self._log.info('client got %s message' % msg.type.name)
        if msg.type == message_type.Disconnect:
            msg = DisconnectMessage(raw=raw)
            self._log.warn('disconnected: %s' % msg.reason)
        if msg.type == message_type.RequestLS:
            self._handle_request_ls(raw)
        if msg.type == message_type.MessagePayload:
            msg = MessagePayloadMessage(raw=raw)
            self._log.debug('handle_message: %s' % msg)
            self._handle_payload(msg.payload)
        if msg.type == message_type.HostLookupReply:
            msg = HostLookupReplyMessage(raw=raw)
            dest = msg.dest
            self._pending_name_lookups.pop(msg.rid)(dest)
        if msg.type == message_type.MessageStatus:
            msg = MessageStatusMessage(raw=raw)
            self._log.debug('message status: %s' % msg.status)

    def _host_not_found(self, rid):
        if rid in self._pending_name_lookups:
            self._pending_name_lookups.pop(rid)(None)


    def _async_lookup(self, name, hook):
        msg = HostLookupMessage(name=name, sid=self._sid)
        self._pending_name_lookups[msg.rid] = hook
        self._send_raw(msg)

    def _handle_payload(self, payload):
        if payload.proto == i2cp_protocol.DGRAM:
            self._log.debug('dgram payload=%s' % payload.data)
            dgram = datagram(raw=payload.data)
            self._got_dgram(dgram, payload.srcport, payload.dstport)


    def send_raw(self, dest, data, srcport=0, dstport=0):
        if isinstance(data, str):
            data = data.encode('utf-8')
        def runit(_dest):
            if _dest is None:
                self._log.warn('no such host: %s' % dest)
                return
            self._log.info('send %d bytes to %s'%(len(data), _dest.base32()))
            p = i2cp_payload(proto=i2cp_protocol.RAW,srcport=srcport,dstport=dstport, data=data)
            self._log.debug('payload=%s' % p)
            msg = SendMessageMessage(sid=self._sid, dest=_dest, payload=p.serialize())
            self._send_raw(msg)

        if isinstance(dest, str):
            self._async_lookup(dest,runit)
        else:
            runit(dest)

    def send_dgram(self, dest, data, srcport=0, dstport=0):
        if isinstance(data, str):
            data = data.encode('utf-8')
        def runit(_dest):
            if _dest is None:
                self._log.warn('no such host: %s' % dest)
                return
            self._log.info('send %d bytes to %s'%(len(data), _dest.base32()))
            dgram = datagram(dest=self.dest, payload=data).serialize()
            self._log.debug('dgram=%s' % dgram)
            p = i2cp_payload(proto=i2cp_protocol.DGRAM,srcport=srcport,dstport=dstport, data=dgram)
            self._log.debug('payload=%s' % p)
            msg = SendMessageMessage(sid=self._sid, dest=_dest, payload=p.serialize())
            self._send_raw(msg)

        if isinstance(dest, str):
            self._async_lookup(dest,runit)
        else:
            runit(dest)

    def _recv_raw(self, dlen=BUFFER_SIZE):
        if self._sock is None:
            return None
        self._log.debug('recv...')
        data = self._sock.recv(dlen)
        dlen = len(data)
        self._log.debug('recv %d bytes' % dlen)
        if dlen == 0:
            self.close()
        else:
            self._log.debug('<-- %s' % data)
            return data

    def _send_raw(self, data):
        if self._sock is None:
            return
        if isinstance(data, str):
            data = bytearray(data, 'utf-8')
        elif isinstance(data, Message):
            self._log.debug('send message: %s' % data)
            data = data.serialize()
        try:
            self._log.debug('--> %s' % data)
        except UnicodeDecodeError:
            # TODO Fix for Python 2
            pass
        self._send_lock.acquire()
        try:
            sent = self._sock.send(data)
        except Exception as e:
            self._log.error('cannot send: %s' % e)
        finally:
            self._send_lock.release()
        self._log.debug('sent %d bytes' % sent)


    def close(self):
        if self._sock is None:
            return
        self._log.debug('closing connection...')
        self._sock.close()
        self._sock = None

def lookup(name, i2cp_host='127.0.0.1', i2cp_port=7654):
    if not name.endswith('.i2p'):
        return destination(name, b64=True)
    c = Connection(i2cp_host=i2cp_host, i2cp_port=i2cp_port)
    c.open()
    msg = HostLookupMessage(name=name, sid=c._sid)
    c._send_raw(msg)
    msg, raw = c._recv_msg()
    dest = None
    if msg.type == message_type.Disconnect:
        msg = DisconnectMessage(raw=raw)
        raise I2CPException(msg.reason)
    elif msg.type == message_type.HostLookupReply:
        msg = HostLookupReplyMessage(raw=raw)
        c._log.debug(msg)
        dest = msg.dest
    c.close()
    return dest

