from future.builtins import bytes
import logging
import os
import queue
import socket
from threading import Thread
import time
from . import exceptions 
from . import messages 
from . import datatypes 
from . import util
from . import crypto

class I2CPHandler(object):

    def got_dgram(self, dest, data, srcport, dstport):
        """
        called every time we get a valid datagram
        """
    
    def session_made(self, conn):
        """
        called after an i2cp session is made successfully with the i2p router
        :param conn: underlying connection
        """

    def session_refused(self):
        """
        called if the i2p router refuses an i2cp session 
        """

    def disconnected(self, reason):
        """
        called if the i2cp session is disconnected abruptly
        """

    def stopped(self):
        """
        session is done executing
        """

class Connection(object):

    def __init__(self, handler, session_options={}, keyfile='i2cp.key', i2cp_host='127.0.0.1', i2cp_port=7654, curve25519=False):
        self._i2cp_addr = (i2cp_host, i2cp_port)
        self._sock = socket.socket()
        self._log = logging.getLogger('I2CP-Connection-%s-%d' % self._i2cp_addr)
        self._sid = None
        self.dest = None
        self._sfd = None
        self._connected = False
        self._pending_name_lookups = {}
        self._sendq = queue.Queue()
        self.handler = handler
        self.keyfile = keyfile
        self.opts = dict(session_options)
        self.opts['i2cp.fastReceive'] = 'true'
        self.send_dgram = self.send_dsa_dgram
        self._threads = list()

    def is_open(self):
        return self._connected

    def open(self):
        self._log.debug('connecting...')
        self._sock.connect(self._i2cp_addr)
        self._sfd = self._sock.makefile('rwb')
        self._connected = True
        self._send_raw(util.PROTOCOL_VERSION)

    def generate_dest(self, keyfile):
        if not os.path.exists(keyfile):
            datatypes.destination.generate_dsa(keyfile)
        self.dest = datatypes.destination.load(keyfile)

    def _recv_msg(self):
        self._log.debug('recv...')
        msg, raw = messages.Message.parse(self._sfd, parts=False)
        self._log.debug('got message: %s' % [ msg ] )
        return msg, raw
        
    def start(self):
        if self.dest is None:
            self.generate_dest(self.keyfile)
        self._log.info('out dest is %s' % self.dest.base32())
        msg = messages.Message(messages.message_type.GetDate)
        self._send_msg(msg)
        self._threads.append(Thread(target=self._run_recv,args=()))
        self._threads.append(Thread(target=self._run_send,args=()))
        for t in self._threads:
            t.start()
        
    def _handle_request_ls(self, raw):
        msg = messages.RequestLSMessage(raw=raw)
        l = msg.leases[0]
        enckey = crypto.ElGamalGenerate()
        sigkey = crypto.DSAGenerate()
        ls = datatypes.leaseset(leases=[l],dest=self.dest, ls_enckey=enckey, ls_sigkey=sigkey)
        msg = messages.CreateLSMessage(
            sid=self._sid,
            sigkey=sigkey,
            enckey=enckey,
            leaseset=ls)
        self._log.debug(msg)
        self._send_msg(msg)
        
    def _flush_sendq(self):
        while not self._sendq.empty():
            msg = self._sendq.get_nowait()
            if msg:
                self._send_raw(msg.serialize())
            else:
                break

    def _run_send(self):
        while self._connected:
            self._flush_sendq()
            time.sleep(0.1)

    def _run_recv(self):
        while self._connected:
            msg, raw = self._recv_msg()
            self._handle_message(raw, msg)
    
    def _handle_message(self, raw, msg):
        if msg is None or msg.type is None:
            self._log.warn('bad message')
            return
        self._log.info('client got %s message' % msg.type.name)
        if msg.type == messages.message_type.Disconnect:
            msg = messages.DisconnectMessage(raw=raw)
            self._log.warn('disconnected: %s' % msg.reason)
            self.handler.disconnected(msg.reason)
            self.close()
        if msg.type == messages.message_type.RequestLS:
            self._handle_request_ls(raw)
        if msg.type == messages.message_type.MessagePayload:
            msg = messages.MessagePayloadMessage(raw=raw)
            self._log.debug('handle_message: %s' % msg)
            self._handle_payload(msg.payload)
        if msg.type == messages.message_type.HostLookupReply:
            msg = messages.HostLookupReplyMessage(raw=raw)
            dest = msg.dest
            self._pending_name_lookups.pop(msg.rid)(dest)
        if msg.type == messages.message_type.MessageStatus:
            msg = messages.MessageStatusMessage(raw=raw)
            self._log.debug('message status: %s' % msg.status)
        if msg.type == messages.message_type.RequestLS:
            self._handle_request_ls(raw)
        if msg.type == messages.message_type.SessionStatus:
            msg = messages.SessionStatusMessage(raw=raw)
            self._log.debug('session status: %s' % msg)
            if msg.status == messages.session_status.REFUSED:
                self._log.error('session rejected')
                self.handler.session_failed(self)
                self.close()
            elif msg.status == messages.session_status.DESTROYED:
                self._log.error('session destroyed')
                self.handler.session_destroyed()
                self.close()
            elif msg.status == messages.session_status.CREATED:
                self._log.info('session created')
                self._sid = msg.sid
                Thread(target=self.handler.session_made, args=(self,)).start()
        if msg.type == messages.message_type.SetDate and self._sid is None:
            msg = messages.CreateSessionMessage(dest=self.dest, opts=self.opts, date=datatypes.date())
            self._send_msg(msg)

    def _host_not_found(self, rid):
        if rid in self._pending_name_lookups:
            self._pending_name_lookups.pop(rid)(None)


    def _async_lookup(self, name, hook):
        msg = messages.HostLookupMessage(name=name, sid=self._sid)
        self._pending_name_lookups[msg.rid] = hook
        self._send_msg(msg)

    def _handle_payload(self, payload):
        if payload.proto == datatypes.i2cp_protocol.DGRAM:
            self._log.debug('dgram payload=%s' % [ payload.data ])
            dgram = datatypes.dsa_datagram(raw=payload.data)
            self.handler.got_dgram(dgram.dest, dgram.payload, payload.srcport, payload.dstport)
        elif payload.proto == datatypes.i2cp_protocol.RAW:
            self._log.debug('dgram-raw paylod=%s' % [ payload.data ])
            self.handler.got_dgram(None, payload.data, payload.srcport, payload.dstport)
        else:
            self._log.debug('streaming payload=%s' % [ payload.data ] )
            self.handler.got_dgram(None, payload.data, payload.srcport, payload.dstport)
        

    def send_raw_dgram(self, dest, data, srcport=0, dstport=0):
        self._send_dgram(datatypes.raw_datagram, dest, data, srcport, dstport)

    def send_dsa_dgram(self, dest, data, srcport=0, dstport=0):
        self._send_dgram(datatypes.dsa_datagram, dest, data, srcport, dstport)

    def _send_dgram(self, dgram_class, dest, data, srcport=0, dstport=0):
        if isinstance(data, str):
            data = bytes(data, 'utf-8')
        def runit(_dest):
            if _dest is None:
                self._log.warn('no such host: %s' % dest)
                return
            self._log.info('send %d bytes to %s'%(len(data), _dest.base32()))
            dgram = dgram_class(dest=self.dest, payload=data).serialize()
            self._log.debug('dgram=%s' % [dgram])
            p = datatypes.i2cp_payload(proto=dgram_class.protocol ,srcport=srcport,dstport=dstport, data=dgram)
            self._log.debug('payload=%s' % [p])
            msg = messages.SendMessageMessage(sid=self._sid, dest=_dest, payload=p.serialize())
            self._send_msg(msg)

        if isinstance(dest, str):
            self._async_lookup(dest,runit)
        else:
            runit(dest)

    def _send_msg(self, msg):
        self._sendq.put(msg)

    def _send_raw(self, data):
        if self._sock is None:
            self._log.error('cannot send data, connection closed')
            return
        try:
            self._log.debug('--> %s' % [data])
        except UnicodeDecodeError:
            # TODO Fix for Python 2
            pass
        try:
            sent = self._sock.send(data)
            self._log.debug('sent %d bytes' % sent)
        except OSError as e:
            self._log.error('cannot send: %s' % e)


    def close(self):
        if self._sfd:
            self._sfd.close()
            self._sfd = None
        self._log.debug('closing connection...')
        if self._sock:
            self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()
            self._sock = None
            self._connected = False
            for t in self._threads:
                t.join()

def lookup(name, i2cp_host='127.0.0.1', i2cp_port=7654):
    if not name.endswith('.i2p'):
        return datatypes.destination(name, b64=True)
    c = Connection(I2CPHandler(), i2cp_host=i2cp_host, i2cp_port=i2cp_port)
    dest = None
    try:
        c.open()
        msg = messages.HostLookupMessage(name=name, sid=c._sid)
        c._send_raw(msg.serialize())
        msg, raw = c._recv_msg()
        if msg.type == messages.message_type.HostLookupReply:
            msg = messages.HostLookupReplyMessage(raw=raw)
            c._log.debug(msg)
            dest = msg.dest
    except KeyboardInterrupt:
        pass
    finally:
        c.close()
    return dest

