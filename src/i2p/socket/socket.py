from i2p.i2cp import client
from i2p.i2cp import crypto
from i2p.i2cp import datatypes
from i2p.i2cp import util

from . import defaults
from . import exceptions
from . import firewall
from . import streaming


import functools
import logging
import queue
import threading
import time
import os

import trollius as asyncio
from trollius import Return, From
from enum import Enum


_log = logging.getLogger("i2p.socket.socket")

SOCK_STREAM = datatypes.i2cp_protocol.STREAMING
SOCK_DGRAM = datatypes.i2cp_protocol.DGRAM
SOCK_RAW = datatypes.i2cp_protocol.RAW

class _SocketFamily(Enum):
    # unused for now
    SAM = 9000
    # it's over 9000!
    I2CP = 9001

AF_SAM = _SocketFamily.SAM
AF_I2CP = _SocketFamily.I2CP

class _SocketEndpoint(client.I2CPHandler):

    _log = logging.getLogger("i2p.socket.SocketEndpoint")

    def __init__(self, rules=None, loop=None, streaming_opts=defaults.streaming_options()):
        """
        :param rules: firewall rules
        :param connection_handler_class: class to use for handling connections
        """
        self._streaming_opts = streaming_opts
        self._handlers = dict()
        self._rules = rules or firewall.DefaultRule()
        self._i2cp = None
        if loop is None:
            loop = asyncio.new_event_loop()
            # just run it
            threading.Thread(target=loop.run_forever).start()
            self._log.info("using new event loop")
        self._loop = loop
        # sid -> pipe send fd
        self._send_to_user_fds = dict()

    def lookup(self, name, tries=1):
        """
        try to look up a name, will block until session is made
        :param name: the name to look up
        :param tries: the number of times to try
        """
        self._log.info("lookup {} try {}".format(name, tries))
        # wait until we are connected
        while not self.is_connected():
            self._log.info("wait for connection")
            time.sleep(1)
        while True:
            if tries > 0:
                self._log.debug("try lookup")
                ftr = asyncio.Future(loop=self._i2cp._loop)
                self._i2cp.lookup_async(name, ftr)
                while not ftr.done():
                    self._log.debug("wait for reply")
                    time.sleep(1)
                dest = ftr.result()
                if dest is None:
                    tries -= 1
                else:
                    return dest
            else:
                raise exceptions.gaierror()

    def is_connected(self):
        """
        :return: true if we are connected to teh remote destination
        """
        return self._i2cp is not None

    def _get_opts(self):
        """
        get i2cp session options
        """
        if self._i2cp is not None:
            return self._i2cp.opts

    def up(self):
        """
        put the interface up
        wait for the session to be ready
        """
        while self._i2cp is None:
            time.sleep(1)
        self.dest = self._i2cp.dest

    @asyncio.coroutine
    def session_made(self, con):
        self._i2cp = con

    @asyncio.coroutine
    def session_refused(self):
        # TODO: handle
        pass

    @asyncio.coroutine
    def got_dgram(self, dest, data, srcport, dstport):
        """
        don't call me
        """
        _log.info("got {} bytes datagram from {} srcport={} dstport={}".format(len(data), dest, srcport, dstport))

    @asyncio.coroutine
    def got_packet(self, data, srcport, dstport):
        """
        don't call me
        """
        pkt = streaming.packet(raw=data)
        # check packet signatures as needed
        if not pkt.verify():
            self._log.error("packet verify failed. pkt={} srcport={} dstport={}".format(pkt, srcport, dstport))
            raise Return()
        # if this is a sync packet add a connection handler for it if it's allowed by firewall
        if pkt.is_syn():
            if not self.rules.allow_ib():
                self._log.warn("drop unwarrened inbound connection attempt")
                raise Return()
            fromdest = pkt.get_from()
            if fromdest is None:
                self._log.error("got malformed streaming packet: {}".format(pkt))
                raise Return()
            self._log.info("incoming connection from {}".format(pkt.get_from()))
            # check if firewall rules permit this
            if self.rules.should_drop(fromdest, srcport, dstport):
                self._log.warn("packet dropped by firewall fromdest={} srcport={} dstport={}".format(fromdest, srcport, dstport))
                raise Return()
            self._new_ib_stream_handler(pkt, dstport, srcport)
        if self._has_stream(pkt):
            stream_handler = self._get_stream_handler(pkt)
            # handle the packet we got
            stream_handler.got_packet(pkt)
        else:
            self._log.warn("got packet for unknown stream. pkt={} srcport={} dstport={}".format(pkt, srcport, dstport))

    def _has_stream(self, pkt):
        """
        return true if we have a stream for this packet
        """
        return pkt.recv_sid in self._stream_handlers

    def _async(self, coro):
        """
        run coroutine async
        """
        return self._loop.create_task(coro)

    def _new_ib_stream_handler(self, pkt, ourport, theirport):
        """
        create a new stream handler given a syn packet
        does not return it
        use _get_stream_handler to get it
        """
        pkt_from_dest = pkt.get_from()
        if pkt_from_dest is None:
            self._log.error("anonymous syn packet, pkt={} srcport={} dstport={}".format(pkt, theirport, ourtport))
        else:
            self._handlers[pkt.recv_sid] = _SocketState(self._loop,
                                                        pkt_from_dest,
                                                        functools.partial(self._stream_recv, pkt.recv_sid),
                                                        self._i2cp,
                                                        self._new_sid, self._streaming_opts)

    def _new_sid(self):
        """
        create a new stream id that we don't have
        """
        sid = None
        while sid is None or sid in self._handlers:
            sid = crypto.random().randint(1, 2 ** 32)
        return sid


    def _get_stream_handler(self, pkt):
        """
        get a stream handler given an existing connection given a packet
        will throw if it does not exist
        """
        return self._handlers[pkt.recv_sid]


    def _stream_recv(self, sid, data):
        """
        :param sid: stream id
        :param data: the data to recv or None if this is eof
        """
        if data:
            # get the pipe fd
            fd = self._send_to_user_fds[sid]
            # write to pipe
            self._log.debug("os.write({}) -> {}".format(fd, sid))
            # probably dangerous
            os.write(fd, data)
        else:
            # this is the end of stream
            # deregister everything
            self._log.debug("close stream {}".format(sid))
            self.close_socket(sid)


    def close_socket(self, sid):
        """
        deregister/close all resources for a stream
        :param sid: the stream's id
        """
        fd = self._send_to_user_fds.pop(sid)
        self._log.debug("os.close({}) -> {}".format(fd, sid))
        # TODO: does this work right? will existing data be recv'd right?
        os.close(fd)
        handler = self._handlers.pop(sid)

    def _register_socket_stream(self, sid, write_fd):
        """
        register a stream id to write to a file descriptor
        :param sid: stream id
        :param write_fd: a fileno that can be written to with os.write for sending results to user
        """
        if sid in self._send_to_user_fds:
            raise Exception("cannot register socket because it already is registered")
        self._send_to_user_fds[sid] = write_fd

    def stream_socket(self):
        """
        create a new streaming socket over i2p that is not bound or connected to anyone
        """
        sid = self._new_sid()
        # create the socket state
        handler = _SocketState(self._loop,
                               None,
                               functools.partial(self._stream_recv, sid),
                               self._i2cp,
                               lambda : sid,
                               self._streaming_opts)
        # new pipe for recv-ing data
        r, w = os.pipe()
        # give write fd to socket state
        self._register_socket_stream(sid, w)
        # give read fd to socket wraper
        return _StreamSocket(self, handler, r)

    def close(self):
        """
        close this endpoint, call when we're done using sockets from this guy
        """
        if self._i2cp:
            # if we are connected then close the i2cp session
            self._log.info("closing interface")
            # close connection
            self._i2cp.close()
            # we no longer have an i2cp session
            self._i2cp = None
        # if the event loop is already closed we're gud
        if self._loop.is_closed():
            return
        # stop the event loop
        self._loop.stop()
        # wait for it to end
        while self._loop.is_running():
            time.sleep(0.1)
        # close it
        self._loop.close()

    def socket(self, af=AF_I2CP, type=SOCK_STREAM, flags=None):
        """
        create a new socket object that uses i2cp
        :param af: address family, must be AF_I2CP
        """
        if af != AF_I2CP:
            raise Exception("cannot use address family {}".format(af))
        if type == SOCK_STREAM:
            return self.stream_socket()
        elif type == SOCK_DGRAM:
            return self.dgram_socket()
        elif type == SOCK_RAW:
            return self.raw_socket()

    def __del__(self):
        self.close()

class _SocketState:
    """
    state of a single connection between destinations
    """

    _log = logging.getLogger("i2p.socket.SocketState")

    def __init__(self, loop, dest, recv_func, i2cp_conn, new_sid, opts):
        """
        :param recv_func: a function that takes 1 bytearray, sends received data to user, must not block
        :param dest: i2p.i2cp.datatypes.destination object of who we are talking to
        :param i2cp_conn: the underlying i2cp session connection
        :param new_sid: generate an new unused sid for this socket to use when replying to syn
        :param opts: streaming options
        """
        # sequence number for sending
        self._seqno = 0
        self._loop = loop
        # callbacks
        self._recv = recv_func
        self._i2cp = i2cp_conn
        # stream ids
        self._send_sid = 0
        self._recv_sid = 0
        self._new_sid = new_sid

        # seqno -> job
        self._pending_send = dict()
        self._pending_acks = dict()

        # tcp backoff
        self._backoff = 0.1

        self._remote_connected = False
        self._opts = opts
        # default mtu
        self._mtu = self._opt_int("maxMessageSize")
        # XXX: this isn't right
        self._ack_timeout = 6

        self._segments = list()
        self.remote_dest = dest

        # times
        self._started_at = util.now()
        self._connected_at = 0

    def _opt_int(self, shortname):
        """
        :param shortname: the name of the option, it will be prefixed with 'i2p.streaming'
        :return: int or None if it's not defined
        """
        name = 'i2p.streaming.{}'.format(shortname)
        if name in self._opts:
            return int(self._opts[name])

    def got_packet(self, pkt):
        """
        recvieve a packet
        this changes the state of the socket
        queues any packets to be sent in reply if needed
        don't call externally
        """
        self._log.debug("got a packet {}".format(pkt))
        # check packet signatures if they exist
        if not pkt.verify(self.remote_dest):
            # report error and return if invalid
            self._log.error("packet signature invalid: {}".format(pkt))
            return
        # record that we got a packet
        self._last_recv = util.now()
        if pkt.is_syn():
            # this is a syn packet
            # handle it
            self._got_syn(pkt)
        elif pkt.is_ack():
            # this is a plain ack
            self._got_ack(pkt)
            return
        if pkt.empty():
            # this packet is emtpy?
            self._log.info("empty packet {}".format(pkt))
        else:
            # recv segment
            self._recv_pkt(pkt)

    def send(self, data):
        """
        send data to endpoint in order
        may block
        :return: how much was sent
        """
        sent = 0
        self._log.debug("send {} bytes".format(len(data)))
        while len(data) > self._mtu:
            sent += self._queue_segment(data[self._mtu:])
            data = data[:self._mtu]
        sent += self._queue_segment(data)
        if self._remote_connected:
            # backoff if we are connected
            self._log.debug("backoff {}".format(self._backoff))
            time.sleep(self._backoff)
        if self.remote_timeout():
            # if we timed out raise exception
            raise exceptions.timeout()
        return sent

    def _queue_segment(self, data):
        """
        queue an entire segment for sending
        :param data: the data in the segment
        """
        self._log.debug("queue {} bytes".format(len(data)))
        self._segments.append(data)
        return len(data)


    def _send_segment(self, sign=False):
        """
        send the next queued segment
        :param sign: do we sign this packet
        :return: how much we sent
        """
        # get the latest segment
        data = self._segments.pop(0)
        # sanity
        assert len(data) <= self._mtu
        self._log.debug("send segment. data={}".format(data))
        pkt = streaming.packet(self._send_sid, self._recv_sid, self._seqno, payload=data)
        if sign:
            pkt.sign(self._i2cp.dest)
        tsk = self._loop.call_later(self._ack_timeout, self._packet_not_acked, pkt)
        self._pending_send[self._seqno] = tsk
        self._seqno += 1
        self._loop.call_soon_threadsafe(self._send_pkt, pkt)
        return len(data)

    def _packet_not_acked(self, pkt):
        """
        called when a packet was not acked in time
        :param pkt: the packet itself
        """
        self._log.warn("packet took too long to be acknowledged: pkt={}".format(pkt))
        #TODO: packet not acked in time, now what?

    def begin_connect(self, dest, port):
        """
        initiate an outbound connection
        :param dest: i2p.i2cp.datatypes.destination object
        :param port: port number
        """
        # set remote dest
        self.remote_dest = dest
        # set ports
        self.remote_port = port
        self.local_port = crypto.random().randint(1, 2 ** 16)
        # start syn sender
        delay = self._opt_int("connectDelay")
        if delay > 0:
            delay /= 1000.
            self._log.debug("buffering for {} before initial send".format(delay))
        else:
            delay = 0
        self._loop.call_soon_threadsafe(self._send_syn, delay)

    def block_until_connected(self):
        """
        block on this function until we are connected to the remote destination
        on timeout will raise
        """
        if self._opt_int("connectDelay") > 0:
            self._log.debug("will not block connect because we are delaying syn")
            return
        while True:
            # wait for a bit
            self._log.debug("blocking for connect")
            time.sleep(0.1)
            if self.remote_connected():
                # we gud yay
                break
            elif self.remote_timeout():
                self._log.warn("connect to {}:{} timed out".format(self.remote_dest.base32(), port))
                # we timed out
                raise exceptions.timeout()

    def _send_syn(self, delay=0, pkt=None):
        """
        send our initial syn packet
        """
        if self.remote_connected():
            self._log.debug("we are connected, not sending syn")
        else:
            if delay == 0:
                self._log.debug("sending syn")
                if pkt is None:
                    pkt = self._make_syn()
                self._loop.call_soon_threadsafe(self._send_pkt, pkt)
                # TODO: make resend interval configurable
                self._loop.call_later(4, self._send_syn, 0, pkt)
            else:
                # delay this
                self._loop.call_later(delay, self._send_syn, 0)

    def _make_syn(self):
        """
        make our initial syn packet
        :return: the syn packet we'll send
        """
        # new sid
        self._recv_sid = self._new_sid()
        # syn flags
        flags = [streaming.packet_flag.SYNC, streaming.packet_flag.SIG_INC, streaming.packet_flag.FROM_INC]
        pkt = streaming.packet(recv_sid=self._recv_sid, flags=flags)
        pkt.set_mtu(self._mtu)
        # add initial payload stuff
        pkt.payload = bytearray()
        # if we have initial data add that in our packet
        while len(pkt.payload) < self._mtu and len(self._segments) > 0:
            seg = self._segments.pop(0)
            # if we add this segment will it be bigger than our mtu?
            if len(seg) + len(pkt.payload) > self._mtu:
                # ya let's not add it, break out
                break
            # add this segment to the syn
            pkt.payload += seg
        pkt.sign(self._i2cp.dest)
        self._log.debug("our syn packet has {} bytes payload".format(len(pkt.payload)))
        return pkt

    def remote_connected(self):
        """
        :return: True if we have a fully established handshake with the remote destination
        """
        return self._remote_connected

    def remote_timeout(self):
        """
        :return: True if the communication with the remote destination has timed out
        """
        if self._remote_connected:
            # we are connected use inactivity timeout
            return util.now() - self._last_recv > self._opt_int("inactivityTimeout")
        # we are not connected, use connect timeout
        return util.now() - self._started_at > self._opt_int("connectTimeout")

    def _send_pkt(self, pkt):
        """
        send a packet to whoever we're talking to
        """
        self._log.debug("sending packet {}".format(pkt))
        # send the packet along its way
        self._i2cp.send_packet(self.remote_dest, pkt, self.local_port, self.remote_port)

    def _send_expired(self, pkt):
        """
        called when we don't get an ack for this packet in time
        """
        self._log.info("packet ack timeout. pkt={}".format(pkt))
        # XXX: is this right? prolly not
        self._backoff += 0.1

    def _recv_pkt(self, pkt):
        """
        handle a packet that isn't a syn or ack
        """
        #TODO: handle this and deliver it to the user in order

    def _got_ack(self, pkt):
        """
        we got an ack from the other
        """
        if pkt.seqno in self._pending_send:
            tsk = self._pending_send[pkt.seqno]
            tsk.cancel()
            del self._pending_send[pkt.seqno]
            self._backoff = 0.1
        else:
            self._log.info("got ack for non pending packet. pkt={}".format(pkt))

    def _got_syn(self, pkt):
        """
        we got an incoming connection
        """

        # is this a oneshot messsage?
        if pkt.is_close():
            self._recv(pkt.payload)
            # end of stream
            self._recv(None)

        self._recv_sid = pkt.recv_sid
        self._send_sid = self._new_sid()
        # set our connection's mtu
        self._mtu = pkt.get_mtu()

class _StreamSocket:
    """
    socket that implements python native tcp socket
    """

    _log = logging.getLogger("i2p.socket.StreamSocket")

    def __init__(self, endpoint, state, fd):
        """
        :param endpoint: the parent endpoint
        :param state: SocketState
        :param fd: the fileno to poll/select for read
        """
        self._fd = fd
        self._endpoint = endpoint
        self._state = state
        self.send = state.send

    def connect(self, addr):
        """
        blocking connect
        :param addr: (host, port) tuple
        """
        self._log.info("resolve address {}".format(addr[0]))
        dest = self._endpoint.lookup(addr[0], tries=10)
        self._log.info("connecting to {}:{}".format(dest, addr[1]))
        self._state.begin_connect(dest, addr[1])
        self._log.info("waiting for reply from {}".format(addr[0]))
        self._state.block_until_connected()
        self._log.info("we are connected to {}:{}".format(addr[0], addr[1]))

    def recv(self, n):
        """
        recv data from remote host, blocks until we read n bytes
        :param n: the number of bytes to recv
        """
        self._log.debug("os.read({}) -> {}".format(self._fd, n))
        return os.read(self._fd, n)

    def close(self):
        """
        close this socket
        """
        self._log.debug("close()")
        self.shutdown()
        # close file descriptor
        self._log.debug("os.close({})".format(self._fd))
        os.close(self._fd)

    def shutdown(self, *args):
        """
        shut down stream
        """
        self._log.debug("shutdown({})".format(self._sid))
        # remove from endpoint
        self._endpont.close_socket(sid)

    def fileno(self):
        """
        :return: the fileno for this socket
        """
        return self._fd

def create_interface(keyfile=defaults.keyfile, i2cp_options=defaults.i2cp_options(), i2cp_host=defaults.i2cp_host, i2cp_port=defaults.i2cp_port):
    """
    create an i2p network interface via i2cp
    :param keyfile: file for private keys
    :param i2cp_options: i2cp session options
    :param i2cp_host: i2cp interface address
    :param i2cp_port: i2cp interface port
    :return: a new socket endpoint used for creating i2p sockets
    """
    i2cp_port = int(i2cp_port)
    loop = asyncio.new_event_loop()
    endpoint_handler = _SocketEndpoint()
    i2cp_con = client.Connection(endpoint_handler, i2cp_options, keyfile, i2cp_host, i2cp_port, loop)
    _log.info("connecting to router at {}:{}".format(i2cp_host, i2cp_port))
    loop.run_until_complete(i2cp_con.open())
    if i2cp_con.is_connected():
        _log.info("we connected, forking event loop")
        # fork event loop off into the background
        # XXX: bad idea?
        threading.Thread(target=loop.run_forever).start()
        return endpoint_handler
    raise Exception("failed to initialize i2p network interface, not connected")

