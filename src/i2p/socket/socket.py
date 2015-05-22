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

_ev_loop = asyncio.new_event_loop()


class SocketEndpoint(client.I2CPHandler):

    _log = logging.getLogger("i2p.socket.SocketEndpoint")
    
    def __init__(self, rules, connection_handler_class):
        """
        :param rules: firewall rules
        :param connection_handler_class: class to use for handling connections
        """
        self._handlers = dict()
        self._rules = rules
        self._handler_class = connection_handler_class
        self._remote_connected = False
        
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
        raise Return()

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
        

class SocketState:
    """
    state of a single connection between destinations
    """

    _log = logging.getLogger("i2p.socket.SocketState")

    def __init__(self, recv_func):
        """
        :param recv_func: a function that takes 1 bytearray, sends received data to user, must not block
        """
        self.seqno = None
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

class SocketFactory:
    """
    handles socket creation
    """

    
    def create_inbound(self, keys):
        """
        create a new server socket
        """

    def create_outbound(self, addr, use_new_connection=False):
        """
        connect to a remote address
        """

class _BaseSocket(threading.Thread):
    """
    base socket for i2p
    """

    def __init__(self, i2p_router):
        self._router_addr = i2p_router
        threading.Thread.__init__(self)

            
class _StreamSocket(_BaseSocket):
    """
    socket.socket equiv class for streaming
    """


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
        self._state = SocketState(self._got_remote)
        self._endpoint = SocketEndpoint(rules, None)
        self._i2cp = client.Connection(self._endpoint)
        self._i2cp.open()
        while not self._state.is_connected():
            time.sleep(0.1)
        
    def send(self, data):
        """
        send data to endpoint after connected
        :param data: data to send
        """
        
        
    def run(self):
        self._i2cp.open()
        
class _DgramSocket:
    """
    socket.socket equiv class for datagrams (both replyable and non replyable)
    """
    
def socket(name=None, type=SOCK_STREAM, i2p_router=("127.0.0.1",7657)):
    """
    create an i2p socket that uses i2cp
    
    :param name: the name of the tunnel or None for a random one
    :param type: SOCK_STREAM for tcp, SOCK_DGRAM for udp, SOCK_RAW for raw datagrams
    :param flags: unused
    :return: a socket like object that goes over i2p
    """
    if type == SOCK_STREAM:
        # make a streaming socket
        return _StreamSocket(i2p_router)
    raise Exception("cannot make socket of unknown type {}".format(type))


# start event loop
t = threading.Thread(target=_ev_loop.run_forever)
t.start()
    
