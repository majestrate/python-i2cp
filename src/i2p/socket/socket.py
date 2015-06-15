from i2p.i2cp import client
from i2p.i2cp import crypto 
from i2p.i2cp import datatypes 
from i2p.i2cp import exceptions  
from i2p.i2cp import util 
from i2p.socket import streaming 

import logging
import queue
import threading

import trollius as asyncio
from trollius import Return, From

from i2p.socket import firewall


SOCK_STREAM = datatypes.i2cp_protocol.STREAMING
SOCK_DGRAM = datatypes.i2cp_protocol.DGRAM
SOCK_RAW = datatypes.i2cp_protocol.RAW

class SocketEndpoint(client.I2CPHandler):

    _log = logging.getLogger("i2p.socket.SocketEndpoint")
    
    def __init__(self, rules=None, loop=None):
        """
        :param rules: firewall rules
        :param connection_handler_class: class to use for handling connections
        """
        self._handlers = dict()
        self._rules = rules or firewall.DefaultRule()
        self._i2cp = None
        if loop is None:
            loop = asyncio.new_event_loop()
        self._loop = loop
        # sid -> pipe send fd
        self._send_to_user_fds = dict()

        
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
    def got_packet(self, pkt, srcport, dstport):
        """
        don't call me
        """
        # check packet signatures as needed
        if not pkt.verify():
            self._log.error("packet verify failed. pkt={} srcport={} dstport={}".format(pkt, srcport, dstport))
            raise Return()
        # if this is a sync packet add a connection handler for it if it's allowed by firewall
        if pkt.is_syn():
            if not self.rules.allow_ib():
                self._log.error("drop unwarrened inbound connection attempt")
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
            self._handlers[pkt.recv_sid] = SocketState(self.get_loop(),
                                                       functools.partial(self._stream_recv, pkt.recv_sid),
                                                       lambda packet : self._i2cp.send_packet(pkt_from_dest, packet, thierport, ourport)
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


    def _stream_recv(self, recv_sid, data):
        fd = self._send_to_user_fd[recv_sid]
        # write to pipe
        # probably dangerous
        os.write(fd, data)


    def _register_socket_stream(self, sid, write_fd):
        """
        register a stream id to write to a file descriptor
        :param sid: stream id
        :param write_fd: a fileno that can be written to with os.write for sending results to user
        """
        if sid in self._send_to_user_fd:
            raise Exception("cannot register socket because it already is registered")
        self._send_to_user_fd[sid] = write_fd
        
    def connect(self, dest, port):
        """
        create a new outbound connection to destination
        """
        sid = self._new_sid()
        handler = SocketState(self.get_loop(),
                              functools.partial(self._stream_recv, sid),
                              lambda packet : self._i2cp.send_packet(dest, packet, port, our_port),
                              lambda : sid,
                              self._streaming_opts)
        r, w = os.pipe()
        self._register_socket_stream(sid, w)
        return _OutboundSocket(self, sid, r, handler.send)
        
    def get_loop(self):
        """
        get event loop belonging to this endpoint
        don't call
        """
        return self._loop

    def close(self):
        """
        close this endpoint, call when we're done using sockets from this guy
        """
        if self._i2cp:
            self._log.info("closing interface")
            # close connection
            self._i2cp.close()
            # close event loop
            # XXX: should we?
            self._loop.close()

class SocketState:
    """
    state of a single connection between destinations
    """

    _log = logging.getLogger("i2p.socket.SocketState")

    def __init__(self, loop, recv_func, send_func, new_sid, opts):
        """
        :param recv_func: a function that takes 1 bytearray, sends received data to user, must not block
        :param send_func: a function that sends a streaming packet to the correct endpoint, takes 1 parameter, the packet
        :param new_sid: generate an new unused sid for this socket to use when replying to syn
        :param opts: streaming options
        """
        # sequence number for sending
        self._seqno = 0
        self._loop = loop
        # callbacks
        self._recv = recv_func
        self._send = send_func
        # stream ids
        self._send_sid = 0
        self._recv_sid = 0
        self._new_sid = new_sid
                                          
        # seqno -> job
        self._pending_send = dict()
        self._pending_acks = dict()

        self._backoff = 0.1
        
        
    # TODO: coroutine?
    def got_packet(self, pkt):
        """
        recvieve a packet
        this changes the state of the socket
        queues any packets to be sent in reply if needed
        don't call externally
        """
        self._log.debug("got a packet {}".format(pkt))
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
            self._recv_pkt(pkt)

    def _make_packet(self, data, ack_thru=0):
        """
        create a new packet to be sent, ease of use function
        """
        return streaming.packet(self._send_sid, self._recv_sid, self._seqno, ack_thru, payload=data)

    
    def send(self, data):
        """
        send data to endpoint in order
        may block
        :return: how much was sent
        """
        sent = 0
        self._log.debug("send {} bytes".foramt(len(data)))
        while len(data) > self.mtu:
            sent += self._queue_send(data[:self.mtu])
            data = data[:self.mtu]
        sent += self._queue_send(data)
        return sent

    def _queue_send(self, data):
        """
        queue segment data less than or equal to the mtu to be sent
        add timeout callbacks
        :return: how much we sent
        """
        # backoff
        self._log.debug("backoff {}".format(self._backoff))
        time.sleep(self._backoff)        
        self._log.debug("queue send. data={}".format(data))
        # regular tcp data segment
        pkt = self._make_packet(data)
        tsk = self._loop.call_later(self.send_timeout, self._send_expired, pkt)
        self._pending_send[self._seqno] = tsk
        self._seqno += 1
        self._loop.call_soon_threadsafe(self._send, pkt)
        return len(data)
        
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
        self._recv_sid = pkt.recv_sid
        self._send_sid = self._new_sid()
        
class _BaseSocket:
    """
    base socket for i2p
    """

    def __init__(self, i2p_router, endpoint):
        self._router_addr = i2p_router
        self._endpoint = endpoint

    def connect(self, addr):
        """
        connect to a remote address on i2p
        :param addr: a (hostname, port) tuple
        """
        raise NotImplemented()
        
    def bind(self, keyfile):
        """
        bind a server socket given destination private keys
        :param keyfile: path to private key file
        """
        raise NotImplemented()

    def shutdown(self, *param):
        """
        shut down communication
        :param param: unused
        """
        raise NotImplemented()
    
    def close(self):
        """
        close this connection
        """
        raise NotImplemented()

    def send(self, data):
        """
        send data to endpoint
        :param data: bytearray
        """
        raise NotImplemented()
    def recv(self, n):
        """
        recv N bytes from endpoint
        blocks
        :param n: the number of bytes max to recv
        """
        raise NotImplemented()


class _OutboundSocket(_BaseSocket):

    def __init__(self, endpoint, sid, fd, send_func):
        """
        :param endpoint: the parent endpoint
        :param sid: the stream id we are using
        :param fd: the fileno to poll/select for read
        :param send_func: the function that sends data to the remote host
        """
        self._fd = fd
        self._endpoint = endpoint
        self.send = send_func
        self._sid = sid

    def recv(self, n):
        """
        recv data from remote host, blocks until we read n bytes
        :param n: the number of bytes to recv
        """
        self._log.debug("sid={} os.read({}) -> {}".format(self._sid, self._fd, n))
        return os.read(self._fd, n)

    def close(self):
        """
        close this socket
        """
        self._log.debug("close({})".format(self._sid))
        self.shutdown()
        # close file descriptor
        self._log.debug("fd {} close".format(self._fd))
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

_log = logging.getLogger("i2p.socket.socket")

def create_interface(keyfile, i2cp_options={}, i2cp_host='127.0.0.1', i2cp_port=7654):
    """
    create an i2p network interface via i2cp
    """
    loop = asyncio.new_event_loop()
    handler = SocketEndpoint(loop=loop)
    i2cp_con = client.Connection(handler, session_options, keyfile, i2cp_host, i2cp_port, loop)
    _log.info("connecting to router at {}:{}".format(i2cp_host, i2cp_port))
    loop.run_until_complete(i2cp_con.open())
    if i2cp_con.is_connected():
        # fork event loop off into the background
        # XXX: bad idea?
        threading.Thread(target=loop.run_forever).start()
        return handler
    raise Exception("failed to initialize i2p network interface, not connected")
    
