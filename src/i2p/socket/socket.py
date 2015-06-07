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

from . import firewall


SOCK_STREAM = datatypes.i2cp_protocol.STREAMING
SOCK_DGRAM = datatypes.i2cp_protocol.DGRAM
SOCK_RAW = datatypes.i2cp_protocol.RAW

class SocketEndpoint(client.I2CPHandler):

    _log = logging.getLogger("i2p.socket.SocketEndpoint")
    
    def __init__(self, rules=None):
        """
        :param rules: firewall rules
        :param connection_handler_class: class to use for handling connections
        """
        self._handlers = dict()
        self._rules = rules or firewall.DefaultRule()
        self._remote_connected = False
        self._loop = asyncio.new_event_loop()
        
    def is_connected(self):
        """
        :return: true if we are connected to teh remote destination
        """
        return self._i2cp is not None and self._remote_connected
        
    @asyncio.coroutine
    def session_made(self, con):
        self._i2cp = con

    @asyncio.coroutine
    def session_refused(self):
        # TODO: handle
        pass
        
    @asyncio.coroutine
    def got_dgram(self, dest, data, srcport, dstport):
        _log.info("got {} bytes datagram from {} srcport={} dstport={}".format(len(data), dest, srcport, dstport))

    @asyncio.coroutine
    def got_packet(self, pkt, srcport, dstport):
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
            self._new_stream_handler(pkt.recv_id, dstport, srcport)
        stream_handler = self._get_stream_handler(pkt.recv_id, dstport, srcport)
        # handle the packet we got
        stream_handler.got_packet(pkt)

    def _async(self, coro):
        """
        run coroutine async
        """
        return self._loop.create_task(coro)
    
    def _new_stream_handler(self, stream_id, ourport, theirport):
        t = (stream_id, ourport, theirport)
        self._handlers[t] = SocketState()
    
    def _get_stream_handler(self, stream_id, ourport, theirport):
        """
        get a stream handler given an existing connection
        will throw if it does not exist
        """
        t = (stream_id, ourport, theirport)
        return self._handlers[t]

    def get_loop(self):
        """
        get event loop belonging to this endpoint
        """
        return self._loop

class SocketState:
    """
    state of a single connection between destinations
    """

    _log = logging.getLogger("i2p.socket.SocketState")

    def __init__(self, loop, recv_func, inbound=False):
        """
        :param recv_func: a function that takes 1 bytearray, sends received data to user, must not block
        :param inbound: true if this is an inbound connection otherwise false
        """
        self.seqno = None
        self._loop = loop
        self._recv = recv_func
        
    def got_packet(self, pkt):
        """
        recvieve a packet
        this changes the state
        """
        self._log.debug("got a packet {}".format(pkt))
        if pkt.is_syn():
            # this is a syn packet
            # set the sequence number to 0
            self.seqno = 0
        elif pkt.is_ack():
            # this is a plain ack
            # the sender got our data
            # just increment the sequence number
            self.seqno += 1
            return
        if pkt.empty():
            # this packet is emtpy?
            self._log.info("empty packet {}".format(pkt))
            return
        # have the user recv the payload
        self._recv(pkt.payload)


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
        
            
class _StreamSocket(_BaseSocket):
    """
    socket.socket equiv class for streaming
    """

    def __init__(self, i2p_router, endpoint):
        _BaseSocket.__init__(self, i2p_router, endpoint)

    def _is_server(self):
        """
        :return: true if this is a server socket
        """
        return self._outbound is False

    def _is_client(self):
        """
        :return: true if this a client socket
        """
        return self._outbound is True


    def _got_remote(self, data):
        """
        called when we got remote data
        """
        self._recv_buffer += data
        
    def connect(self, addr):
        """
        connect to a remote destination 
        :param addr: (destination, port)
        """
        self._outbound = True
        rules = firewall.DefaultRule()
        self._state = SocketState(self._loop, self._got_remote)
        self._endpoint = SocketEndpoint(rules, None)
        self._i2cp = client.Connection(self._endpoint)
        self._i2cp.open()
        
        
    def send(self, data):
        """
        send data to endpoint after connected
        :param data: data to send
        """
        self._state.queue_send(data)
        
class _DgramSocket(_BaseSocket):
    """
    socket.socket equiv class for datagrams (both replyable and non replyable)
    """


def socket(name=None, type=SOCK_STREAM, i2cp_interface=("127.0.0.1",7657)):
    """
    create an i2p socket that uses i2cp
    
    :param name: the name of the tunnel or None for a random one
    :param type: SOCK_STREAM for tcp, SOCK_DGRAM for udp, SOCK_RAW for raw datagrams
    :param i2cp_interface: the address of the i2p router's i2cp interface
    :return: a socket like object that goes over i2p
    """
    endpoint = SocketEndpoint()
    if type == SOCK_STREAM:
        return _Socket
    raise Exception("cannot make socket of unknown type {}".format(type))

