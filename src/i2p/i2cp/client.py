from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
import logging
import os
import queue
import socket
import struct
import time
import functools
from i2p import crypto, datatypes
from . import exceptions
from . import messages
from . import util

import trollius as asyncio
from trollius import From, Return

class I2CPHandler(object):

    def got_dgram(self, dest, data, srcport, dstport):
        """
        called every time we get a valid datagram
        """

    def got_packet(self, pkt, srcport, dstport):
        """
        called every time we get a valid streaming packet
        """

    def session_made(self, conn):
        """
        called after an i2cp session is made successfully with the i2p router
        :param conn: underlying connection
        """

    def session_refused(self):
        """
        called when the i2p router refuses a session
        """

    def disconnected(self, reason):
        """
        called if the i2cp session is disconnected abruptly
        """

    def session_done(self):
        """
        called when the session is done and the i2cp connection has gracefully disconnected
        """

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

    def session_made(self, conn):
        dest = conn.dest
        if self._b32:
            self._print(dest.base32())
        else:
            self._print(dest.base64())
        conn.close()

class Connection(object):

    _log = logging.getLogger('I2CP-Connection')


    def __init__(self, handler=None, session_options={}, keyfile='i2cp.key', i2cp_host='127.0.0.1', i2cp_port=7654, loop=None):
        # host, port of i2cp interface
        self._i2cp_host, self._i2cp_port = i2cp_host, i2cp_port
        # i2cp session id
        self._sid = None
        # unused
        self._lookup = None
        self._done = False
        # Our destination. Contains our private keys.
        self.dest = None
        # state stuff
        self._connected = False
        self._created = False
        # session handler
        self.handler = handler or I2CPHandler()
        # keyfile
        self.keyfile = keyfile
        # options
        self.opts = dict(session_options)
        self.opts['i2cp.fastReceive'] = 'true'
        # send_* functions
        self.send_dgram = self.send_dsa_dgram
        # host lookups
        self._host_lookups = dict()
        # create encryption key for LS per session
        self._enckey = crypto.ElGamalKey()
        # session handlers
        self._msg_handlers = {
            messages.MessageType.SessionStatus : self._msg_handle_session_status,
            messages.MessageType.RequestLS : self._msg_handle_request_ls,
            messages.MessageType.SetDate : self._msg_handle_set_date,
            messages.MessageType.Disconnect : self._msg_handle_disconnect,
            messages.MessageType.RequestVarLS : self._msg_handle_request_var_ls,
            messages.MessageType.HostLookupReply : self._msg_handle_host_lookup_reply,
            messages.MessageType.MessagePayload : self._msg_handle_message_payload,
        }
        # destination cache
        self._dest_cache = dict()
        # get and set loop
        if loop is None:
            self._loop = asyncio.get_event_loop()
        else:
            self._loop = loop
        # create the future to use to indicate that we are done
        self._done_future = asyncio.Future(loop=self._loop)
        # generate private keys
        self.generate_dest(self.keyfile)

    def is_connected(self):
        return None not in [self._reader, self._writer]

    def is_done(self):
        """
        :return: true if our connection has finished and ended the session
        """
        return self._done

    @asyncio.coroutine
    def open(self):
        """
        open session to i2p router
        this is a coroutine
        """
        self._log.debug('connecting...')
        tsk = self._async(asyncio.open_connection(self._i2cp_host, self._i2cp_port, loop=self._loop))
        ftr = asyncio.Future(loop=self._loop)
        def _done_connecting(f):
            try:
                self._reader, self._writer =  f.result()
            except Exception as e:
                self._log.error("cannot connect to i2p router at {}:{}".format(self._i2cp_host, self._i2cp_port))
                ftr.set_exception(e)
            else:
                self._log.info("connected")
                self._loop.call_soon_threadsafe(self._async, self._send_raw(util.PROTOCOL_VERSION))
                self._loop.call_soon_threadsafe(self._begin_session)
                ftr.set_result(None)
        tsk.add_done_callback(_done_connecting)
        yield From(ftr)

    def generate_dest(self, keyfile):
        if not os.path.exists(keyfile):
            with open(keyfile, 'wb') as wf:
                wf.write(datatypes.Destination().serialize(priv=True))
        with open(keyfile, 'rb') as rf:
            self.dest = datatypes.Destination(raw=rf)

    def lookup_async(self, name, ftr):
        """
        lookup name asynchronously
        """
        self._log.info('async lookup {}'.format(name))
        msg = messages.HostLookupMessage(name=name, sid=self._sid)
        self._host_lookups[msg.rid] = ftr, name
        self._log.debug('put rid {}'.format(msg.rid))
        self._loop.call_soon_threadsafe(self._async, self._send_msg(msg))

    def _has_lookup_job(self, name):
        """
        :return: true if we are currently looking up a name
        """
        for _, _name in self._host_lookups.values():
            if name == _name:
                return True
        return False

    def _async(self, coro):
        """
        do stuff thread safe async
        """
        return self._loop.create_task(coro)


    def _put_dest_cache(self, name, dest):
        self._log.debug('put dest cache for {}'.format(name))
        self._dest_cache[name] = dest

    @asyncio.coroutine
    def _recv_message(self):
        """
        recv and process a message
        """
        # read header
        self._log.debug('recv header...')
        hdrdata = yield From(self._reader.readexactly(5))
        msglen, _type = struct.unpack(b'>IB', hdrdata)
        msgtype = messages.MessageType(_type)
        # read body
        self._log.debug('recv %d bytes' % msglen)
        self._log.debug('read message of size {}'.format(msglen))
        msgbody = yield From(self._reader.readexactly(msglen))
        msgraw = hdrdata + msgbody
        raise Return(msgtype, hdrdata, msgraw)


    @asyncio.coroutine
    def _recv_process(self):
        """
        process recv'd message
        """
        if self.is_connected():
            msgtype, hdrdata, msgraw = yield From(self._recv_message())
            # handle message data
            if msgtype in self._msg_handlers:
                handler = self._msg_handlers[msgtype]
                msg = messages.messages[msgtype](raw=msgraw)
                # call handler
                self._loop.call_soon_threadsafe(handler, msg)
            else:
                self._log.warn('unhandled message of type: {}'.format(msgtype))
            # call again
            self._async(self._recv_process())
        raise Return()

    def _begin_session(self):
        """
        begin i2cp session after sending protocol byte
        """
        self._log.debug('begin_session()')
        # fire off get date message
        msg = messages.GetDateMessage()
        self._async(self._send_msg(msg))
        # start recving messages
        self._async(self._recv_process())


    @asyncio.coroutine
    def lookup(self, name):
        """
        lookup a name
        this is a coroutine
        :param name: the name
        """
        ftr = asyncio.Future(loop=self._loop)
        self._async(self.lookup_async(name, ftr))
        dest = yield From(ftr)
        raise Return(dest)

    @asyncio.coroutine
    def _send_raw(self, data):
        """
        send raw bytes
        """
        self._writer.write(data)
        self._log.debug('send %d bytes' % len(data))
        self._log.debug('--> {}'.format( [data]))
        raise Return(self._writer.drain())

    @asyncio.coroutine
    def _send_msg(self, msg):
        if msg:
            yield From(self._send_raw(msg.serialize()))
        else:
            self._log.error("_send_msg given None?")
        raise Return()

    def _msg_handle_set_date(self, msg):
        """
        handle disconnect message
        """
        if not self._created:
            self._log.info('creating session...')
            msg = messages.CreateSessionMessage(opts=self.opts, dest=self.dest, session_date=datatypes.Date())
            self._async(self._send_msg(msg))

    def _msg_handle_disconnect(self, msg):
        """
        handle disconnect message
        """
        reason = msg.reason
        self._log.warn('session disconnected from i2p router: {}'.format(reason))
        self._async(self.handler.disconnected(reason))
        self.close()
        raise Return()

    def _msg_handle_request_var_ls(self, msg):
        """
        handle variable lease set request message
        """
        self._log.debug('handle vls message')
        dummy_sigkey = crypto.DSAKey()
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


    def _msg_handle_request_ls(self, msg):
        """
        handle lease set request message
        """
        l = msg.leases[0]
        enckey = self._enckey
        sigkey = self.dest.sigkey
        ls = datatypes.LeaseSet(leases=[l],dest=self.dest, ls_enckey=enckey, ls_sigkey=sigkey)
        msg = messages.CreateLSMessage(
            sid=self._sid,
            sigkey=sigkey,
            enckey=enckey,
            leaseset=ls)
        yield From(self._send_msg(msg))

    def _msg_handle_message_payload(self, msg):
        """
        handle message payload message
        """
        payload = msg.payload
        if payload.proto == datatypes.I2CPProtocol.DGRAM:
            self._log.debug('dgram payload=%s' % [ payload.data ])
            dgram = datatypes.dsa_datagram(raw=payload.data)
            self.handler.got_dgram(dgram.dest, dgram.payload, payload.srcport, payload.dstport)
        elif payload.proto == datatypes.I2CPProtocol.RAW:
            self._log.debug('dgram-raw paylod=%s' % [ payload.data ])
            self.handler.got_dgram(None, payload.data, payload.srcport, payload.dstport)
        elif payload.proto == datatypes.I2CPProtocol.STREAMING:
            self._log.debug('streaming payload=%s' % [ payload.data ] )
            self.handler.got_packet(payload.data, payload.srcport, payload.dstport)
        else:
            self._log.warn('bad message payload')

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

    def _msg_handle_session_status(self, msg):
        """
        handle session status message
        """
        try:
            self._log.info('session status: {}'.format(msg.status))
            if msg.status == messages.SessionStatus.CREATED:
                self._log.debug('session created')
                self._created = True
                self._sid = msg.sid
                self.handler.session_made(self)
            else:
                self.handler.session_refused()
        except Exception as e:
            self._log.error("failed to handle session status message")

    def send_packet(self, name, packet, srcport=0, dstport=0):
        """
        send a streaming packet to a destination
        packets will drop until the name is resolved
        """
        dest = self._check_dest_cache(name)
        if dest:
            self._log.debug('send packet to {}: {}'.format(dest.base32(), packet))
            pkt_data = packet.serialize()
            p = datatypes.i2cp_payload(proto=datatypes.I2CPProtocol.STREAMING, srcport=srcport, dstport=dstport, data=pkt_data).serialize()
            msg = messages.SendMessageMessage(sid=self._sid, dest=dest, payload=p)
            # send the packet safely
            self._loop.call_soon_threadsafe(self._async, self._send_msg(msg))
        else:
            # look up the destination
            self._issue_lookup()


    def send_raw_dgram(self, dest, data, srcport=0, dstport=0):
        """
        send a "raw" datagram
        """
        self._loop.call_soon_threadsafe(self._send_dgram, datatypes.raw_datagram, dest, data, srcport, dstport)

    def send_dsa_dgram(self, dest, data, srcport=0, dstport=0):
        """
        send a dsa signed datagram
        """
        self._loop.call_soon_threadsafe(self._send_dgram, datatypes.dsa_datagram, dest, data, srcport, dstport)

    def _send_dgram(self, dgram_class, name, data, srcport=0, dstport=0):
        # check out destination cache
        dest = self._check_dest_cache(name)
        # ensure the data is bytes
        if not isinstance(data, bytes):
            data = bytearray(data, 'utf-8')

        # if we don't have the destination in our cache
        # look it up
        # drop packets until we find it
        if dest:
            # make the payload
            self._log.debug('sending dgram to {}'.format(dest.base32()))
            dgram = dgram_class(dest=self.dest, payload=data)
            p = datatypes.i2cp_payload(data=dgram.serialize(), srcport=srcport, dstport=dstport, proto=dgram_class.protocol)
            msg = messages.SendMessageMessage(sid=self._sid, dest=dest, payload=p.serialize())
            # send it safely
            self._loop.call_soon_threadsafe(self._async, self._send_msg(msg))
        else:
            # look up the name
            self._issue_lookup(name)

    def _issue_lookup(self, name):
        # don't call lookup async many times if we are already pending
        if not self._has_lookup_job(name):
            # this will put the resolved destination in our dest_cache on success
            ftr = asyncio.Future(loop=self._loop)
            self._loop.call_soon(self.lookup_async, name, ftr)


    def _check_dest_cache(self, name):
        """
        :param dest:
        :return: the destination of this name if we know it otherwise None
        """
        if name in self._dest_cache:
            return self._dest_cache[name]

    def close(self):
        """
        close this connection
        """
        self._log.debug("initiate close")
        if self._writer:
            self._log.debug("close writer")
            self._writer.transport.close()
            self._log.debug("writer closed")
        self._log.debug('closing connection...')
        self._connected = False
        self._reader = None
        self._writer = None
        self._done = True
        self._done_future.set_result(True)
        self._log.debug("inform handler done")
        try:
            self.handler.session_done()
        except Exception as e:
            self._log.error("failed to call self.handler.session_done(): {}".format(e))

    def done(self):
        """
        :return: a future that ends when this connection is done
        """
        return self._done_future

    def __del__(self):
        self.close()
