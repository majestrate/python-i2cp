import socket
import logging
from .exceptions import *
from .messages import *
from .datatypes import *
from .util import *

class Connection:

    def __init__(self, i2cp_host='127.0.0.1', i2cp_port=7654):
        self._i2cp_addr = (i2cp_host, i2cp_port)
        self._sock = socket.socket()
        self._log = logging.getLogger('I2CP-Connection-%s-%d' % self._i2cp_addr)
        self._sid = None
        self.dest = None

    def open(self):
        self._log.info('connecting...')
        self._sock.connect(self._i2cp_addr)
        self._send_raw(PROTOCOL_VERSION)
        
    def generate_dest(self, keyfile):
        destination.generate(keyfile)
        self.dest = destination.load(keyfile)
    
    def recv_msg(self):
        raw = self._recv_raw()
        msg = Message(raw=raw)
        self._log.debug('got message: %s' %msg)
        return msg, raw

        
    def start_session(self, opts, keyfile='keys.dat'):
        if self.dest is None:
            self.generate_dest(keyfile)
        msg = Message(message_type.GetDate)
        self._send_raw(msg)
        msg, raw = self.recv_msg()
        if msg.type != message_type.SetDate:
            raise I2CPException('expected SetDate Message but got %s Message' % msg.type.name)
        msg = CreateSessionMessage(dest=self.dest, opts=opts, date=date())
        self._send_raw(msg)
        msg, raw = self.recv_msg()
        if msg.type == message_type.RequestLS:
            self._handle_request_ls(raw)
        elif msg.type == message_type.SessionStatus:
            msg = SessionStatusMessage(raw=raw)
            self.sid = msg.sid
            if msg.status == session_status.REFUSED:
                self._log.error('session rejected')
            elif msg.status == session_status.DESTROYED:
                self._log.error('session destroyed')
            elif msg.status == session_status.CREATED:
                self.sid = msg.sid
                msg, raw = self.recv_msg()
                self._handle_request_ls(raw)
        else:
            self.close()
        
    def _handle_request_ls(self, raw):
        msg = RequestLSMessage(raw=raw)
        l = msg.leases[0]
        ls = leaseset(leases=[l],dest=self.dest, ls_enckey=self.dest.enckey, ls_sigkey=self.dest.sigkey)
        msg = CreateLSMessage(
            sid=self.sid,
            sigkey=self.dest.sigkey,
            enckey=self.dest.enckey,
            leaseset=ls)
        self._log.debug(msg)
        self._send_raw(msg)
        
    def run(self):
        while True:
            data = self._recv_raw()
            if data is None: 
                break
            msg = Message(raw=data)
            self.handle_message(data, msg)
    
    def handle_message(self, raw, msg):
        self._log.debug('client got message: %s' % msg)
        if msg.type == message_type.RequestLS:
            self._handle_request_ls(raw)


    def _recv_raw(self, dlen=BUFFER_SIZE):
        if self._sock is None:
            return None
        self._log.debug('recv...')
        data = self._sock.recv(dlen)
        dlen = len(data)
        self._log.debug('recv %d bytes' % dlen)
        if dlen == 0:
            return None
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
        if msg.type == message_type.Disconnect:
            raise I2CPException(msg.body.decode('utf-8'))
        elif msg.type == message_type.HostLookupReply:
            return HostLookupReplyMessage(raw=data).dest
            
        

    def close(self):
        if self._sock is None:
            return
        self._log.info('closing connection...')
        msg = Message(message_type.Disconnect)
        self._send_raw(msg)
        self._sock.close()
        self._sock = None


def lookup(name):
    con = Connection()
    con.open()
    con.start_session()
    result = con.lookup(name)
    con.close()
    return result

