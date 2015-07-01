from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
import logging
import os
import queue
import socket
import struct
import time
from i2p import crypto, datatypes
from . import exceptions
from . import messages
from . import util

import trollius as asyncio
from trollius import From, Return

class I2CPHandler(object):

    @asyncio.coroutine
    def got_dgram(self, dest, data, srcport, dstport):
        """
        called every time we get a valid datagram
        """
        raise Return()

    @asyncio.coroutine
    def got_packet(self, pkt, srcport, dstport):
        """
        called every time we get a valid streaming packet
        """
        raise Return()

    @asyncio.coroutine
    def session_made(self, conn):
        """
        called after an i2cp session is made successfully with the i2p router
        :param conn: underlying connection
        """
        raise Return()

    @asyncio.coroutine
    def session_refused(self):
        """
        called when the i2p router refuses a session
        """

    @asyncio.coroutine
    def disconnected(self, reason):
        """
        called if the i2cp session is disconnected abruptly
        """
        raise Return()

    @asyncio.coroutine
    def session_done(self):
        """
        called when the session is done and the i2cp connection has gracefully disconnected
        """
        raise Return()
        
class PrintDestinationHandler(I2CPHandler):
    """
    a handler that prints our destination and then closes the connection
    """

    def __init__(self, printfunc=None, b32=True):
        """
        :param printfunc: function to use to print our destination
        """
        if printfunc:
            self._print = printfunc
        else:
            self._print = self._stdout_print
        self._b32 = b32 is True

    def _stdout_print(self, *args):
        print (*args)

    @asyncio.coroutine
    def session_made(self, conn):
        dest = conn.dest
        if self._b32:
            self._print(dest.base32())
        else:
            self._print(dest.base64())
        conn.close()

class Connection(object):

    _log = logging.getLogger('I2CP-Connection')


    def __init__(self, handler, session_options={}, keyfile='i2cp.key', i2cp_host='127.0.0.1', i2cp_port=7654, evloop=None):
        self._i2cp_host, self._i2cp_port = i2cp_host, i2cp_port
        self._sid = None
        # unused
        self._lookup = None
        self._done = False
        # our destination
        self.dest = None
        self._connected = False
        self._created = False
        self.handler = handler or I2CPHandler()
        self.keyfile = keyfile
        self.opts = dict(session_options)
        self.opts['i2cp.fastReceive'] = 'true'
        self.send_dgram = self.send_dsa_dgram
        self._host_lookups = dict()
        # create encryption key for LS per session
        self._enckey = crypto.ElGamalGenerate()
        self._msg_handlers = {
            messages.message_type.SessionStatus : self._msg_handle_session_status,
            messages.message_type.RequestLS : self._msg_handle_request_ls,
            messages.message_type.SetDate : self._msg_handle_set_date,
            messages.message_type.Disconnect : self._msg_handle_disconnect,
            messages.message_type.RequestVarLS : self._msg_handle_request_var_ls,
            messages.message_type.HostLookupReply : self._msg_handle_host_lookup_reply,
            messages.message_type.MessagePayload : self._msg_handle_message_payload,
        }
        self._dest_cache = dict()
        if evloop is None:
            self._loop = asyncio.get_event_loop()
        else:
            self._loop = evloop
        self._done_future = asyncio.Future(loop=self._loop)
        self.generate_dest(self.keyfile)

    def is_connected(self):
        return self._connected

    def is_done(self):
        """
        :return: true if our connection has finished and ended the session
        """
        return self._done

    def open(self):
        """
        open session to i2p router
        :return: a future that completes after connected
        """
        self._log.debug('connecting...')
        tsk = self._async(asyncio.open_connection(self._i2cp_host, self._i2cp_port, loop=self._loop))
        tsk.add_done_callback(self._cb_connected)
        return tsk

    def generate_dest(self, keyfile):
        if not os.path.exists(keyfile):
            datatypes.Destination.generate_dsa(keyfile)
        self.dest = datatypes.Destination.load(keyfile)

    def lookup_async(self, name, ftr):
        """
        lookup name asynchronously
        """
        self._log.info('async lookup {}'.format(name))
        msg = messages.HostLookupMessage(name=name, sid=self._sid)
        self._host_lookups[msg.rid] = ftr, name
        self._log.debug('put rid {}'.format(msg.rid))
        self._loop.call_soon_threadsafe(self._async, self._send_msg(msg))


    def _async(self, coro):
        """
        do stuff thread safe async
        """
        return self._loop.create_task(coro)


    def _put_dest_cache(self, name, dest):
        self._log.debug('put dest cache for {}'.format(name))
        self._dest_cache[name] = dest


    def _cb_recv_msg_hdr(self, ftr):
        """
        called when we read a message header
        """
        data = ftr.result()
        if data is None:
            return
        else:
            _len, _type = struct.unpack(b'>IB', data)
            _type = messages.message_type(_type)
            self._loop.call_soon(self._read_msg, _len, _type, data)


    def _got_message(self, msgtype, msgbody, msgraw):
        """
        we got a message of tpye with body
        """
        if msgtype in self._msg_handlers:
            handler_coro = self._msg_handlers[msgtype]
            self._log.debug(handler_coro)
            msg = messages.messages[msgtype](raw=msgraw)
            self._async(handler_coro(msg))
        else:
            self._log.warn('unhandled message of type: {}'.format(msgtype))
        self._loop.call_soon(self._recv_msg_hdr)

    def _read_msg(self, msglen, msgtype, msghdr):
        """
        read a message of a certain type
        execute coroutine to handle message once read
        """
        self._log.debug('read_msg()')
        self._log.info('recv %d bytes' % msglen)
        if self._reader:
            self._log.debug('read message of size {}'.format(msglen))
            tsk = self._async(self._reader.readexactly(msglen))
            tsk.add_done_callback(lambda ftr : self._got_message(msgtype, ftr.result(), msghdr + ftr.result()))

    def _recv_msg_hdr(self):
        """
        read message header
        """
        if self._reader:
            self._log.debug('recv header...')
            tsk = self._async(self._reader.readexactly(5))
            tsk.add_done_callback(self._cb_recv_msg_hdr)

    def _begin_session(self):
        """
        begin i2cp session after sending protocol byte
        """
        self._log.debug('begin_session()')
        msg = messages.GetDateMessage()
        self._async(self._send_msg(msg))
        self._loop.call_soon(self._recv_msg_hdr)

    def _cb_connected(self, ftr):
        """
        we connected, send protocol byte
        """
        self._reader, self._writer = ftr.result()
        self._connected = None not in (self._reader, self._writer)
        if self.is_connected():
            self._async(self._send_raw(util.PROTOCOL_VERSION))
            self._loop.call_soon(self._begin_session)
        else:
            self._log.error('could not connect to i2p router')

    @asyncio.coroutine
    def lookup(self, name):
        """
        lookup a name
        :param name: the name
        yields none on error otherwise the destination as a datatype.Destination
        """
        ftr = asyncio.Future(loop=self._loop)
        self._async(self.lookup_async(name, ftr))
        yield From(ftr)

    @asyncio.coroutine
    def _send_raw(self, data):
        """
        send raw bytes
        """
        self._writer.write(data)
        yield From(self._writer.drain())
        self._log.info('send %d bytes' % len(data))
        self._log.debug('--> {}'.format( [data]))

    @asyncio.coroutine
    def _send_msg(self, msg):
        if msg:
            yield From(self._send_raw(msg.serialize()))
        else:
            self._log.error("_send_msg given None?")

    @asyncio.coroutine
    def _msg_handle_set_date(self, msg):
        """
        handle disconnect message
        """
        if not self._created:
            self._log.info('creating session...')
            msg = messages.CreateSessionMessage(opts=self.opts, dest=self.dest, session_date=datatypes.Date())
            self._async(self._send_msg(msg))

    @asyncio.coroutine
    def _msg_handle_disconnect(self, msg):
        """
        handle disconnect message
        """
        reason = msg.reason
        self._log.warn('session disconnected from i2p router: {}'.format(reason))
        self._async(self.handler.disconnected(reason))
        self.close()
        raise Return()

    @asyncio.coroutine
    def _msg_handle_request_var_ls(self, msg):
        """
        handle variable lease set request message
        """
        self._log.debug('handle vls message')
        dummy_sigkey = crypto.DSAGenerate()
        #enckey = self.dest.enckey
        sigkey = self.dest.sigkey
        leases = list()
        for l in msg.leases:
            l.end_date = datatypes.Date((time.time() * 1000) + 600000)
            leases.append(l)
        ls = datatypes.LeaseSet(leases=leases, dest=self.dest, ls_enckey=self._enckey, ls_sigkey=sigkey)
        self._log.debug('made LeaseSet: {}'.format(ls))
        msg = messages.CreateLSMessage(
            sid=self._sid,
            sigkey=dummy_sigkey,
            enckey=self._enckey,
            leaseset=ls)
        self._log.debug('made message')
        yield From(self._send_msg(msg))


    @asyncio.coroutine
    def _msg_handle_request_ls(self, msg):
        """
        handle lease set request message
        """
        l = msg.leases[0]
        #TODO: should we regen keys?
        enckey = crypto.ElGamalGenerate()
        sigkey = crypto.DSAGenerate()
        ls = datatypes.LeaseSet(leases=[l],dest=self.dest, ls_enckey=enckey, ls_sigkey=sigkey)
        msg = messages.CreateLSMessage(
            sid=self._sid,
            sigkey=sigkey,
            enckey=enckey,
            leaseset=ls)
        yield From(self._send_msg(msg))


    @asyncio.coroutine
    def _msg_handle_message_payload(self, msg):
        """
        handle message payload message
        """
        payload = msg.payload
        if payload.proto == datatypes.i2cp_protocol.DGRAM:
            self._log.debug('dgram payload=%s' % [ payload.data ])
            dgram = datatypes.dsa_datagram(raw=payload.data)
            yield From(self.handler.got_dgram(dgram.dest, dgram.payload, payload.srcport, payload.dstport))
        elif payload.proto == datatypes.i2cp_protocol.RAW:
            self._log.debug('dgram-raw paylod=%s' % [ payload.data ])
            yield From(self.handler.got_dgram(None, payload.data, payload.srcport, payload.dstport))
        elif payload.proto == datatypes.i2cp_protocol.STREAMING:
            self._log.debug('streaming payload=%s' % [ payload.data ] )
            yield From(self.handler.got_packet(payload.data, payload.srcport, payload.dstport))
        else:
            self._log.warn('bad message payload')
            raise Return()


    @asyncio.coroutine
    def _msg_handle_host_lookup_reply(self, msg):
        """
        handle host message reply
        """
        self._log.debug('hlr rid={}'.format(msg.rid))
        if msg.rid in self._host_lookups:
            ftr, name = self._host_lookups[msg.rid]
            if msg.dest is not None:
                self._put_dest_cache(name, msg.dest)
                self._log.debug('got dest: {}'.format(msg.dest))
                if not ftr.done():
                    ftr.set_result(msg.dest)
            else:
                ftr.set_result(None)
            self._host_lookups.pop(msg.rid)
        raise Return()

    @asyncio.coroutine
    def _msg_handle_session_status(self, msg):
        """
        handle session status message
        """
        self._log.info('session status: {}'.format(msg.status))
        if msg.status == messages.session_status.CREATED:
            self._log.debug('session created')
            self._created = True
            self._sid = msg.sid
            self._async(self.handler.session_made(self))
        else:
            self._async(self.handler.session_refused())
        raise Return()

    def send_packet(self, dest, packet, srcport=0, dstport=0):
        """
        send a streaming packet to a destination
        """
        self._log.debug('send packet to {}: {}'.format(dest.base32(), packet))
        pkt_data = packet.serialize()
        p = datatypes.i2cp_payload(proto=datatypes.i2cp_protocol.STREAMING, srcport=srcport, dstport=dstport, data=pkt_data).serialize()
        dest = self._check_dest_cache(dest)
        msg = messages.SendMessageMessage(sid=self._sid, dest=dest, payload=p)
        self._loop.call_soon_threadsafe(self._async, self._send_msg(msg))

    def send_raw_dgram(self, dest, data, srcport=0, dstport=0):
        self._async(self._send_dgram(datatypes.raw_datagram, dest, data, srcport, dstport))

    def send_dsa_dgram(self, dest, data, srcport=0, dstport=0):
        self._async(self._send_dgram(datatypes.dsa_datagram, dest, data, srcport, dstport))

    @asyncio.coroutine
    def _send_dgram(self, dgram_class, dest, data, srcport=0, dstport=0):
        dest = self._check_dest_cache(dest)
        if not isinstance(data, bytes):
            data = bytearray(data, 'utf-8')

        ftr = asyncio.Future(loop=self._loop)

        if not isinstance(dest, datatypes.Destination):
            self._loop.call_soon(self.lookup_async, dest, ftr)
        else:
            self._log.debug('sending dgram to {}'.format(dest.base32()))
            dgram = dgram_class(dest=self.dest, payload=data)
            p = datatypes.i2cp_payload(data=dgram.serialize(), srcport=srcport, dstport=dstport, proto=dgram_class.protocol)
            msg = messages.SendMessageMessage(sid=self._sid, dest=dest, payload=p.serialize())
            yield From(self._async(self._send_msg(msg)))

    def _check_dest_cache(self, dest):
        if dest in self._dest_cache:
            return self._dest_cache[dest]
        return dest

    def close(self):
        self._log.debug('closing connection...')
        if self._writer:
            self._writer.close()
        self._connected = False
        self._reader = None
        self._writer = None
        # we are now done
        self._async(self.handler.session_done())
        self._done = True
        self._done_future.set_result(True)

    def done(self):
        """
        :return: a future that ends when this connection is done
        """
        return self._done_future
        
    def __del__(self):
        self.close()
