import i2p.i2cp.client as i2cp
from i2p.i2cp.crypto import *
from i2p.i2cp.datatypes import *
from i2p.i2cp.exceptions import *
from i2p.i2cp.util import *
from i2p.socket.streaming import *

import logging
import queue



class _i2p_socket(i2cp.I2CPHandler):
    """
    socket like object for 1 destination
    utilizes 1 i2cp connection
    """

    def __init__(self, i2cp_host, i2cp_port, session_opts):
        self._log = logging.getLogger(self.__class__.__name__)
        self._i2cp_host , self._i2cp_port = i2cp_host, i2cp_port
        self._i2cp = None
        self._dest = None
        self._port = None
        self._keyfd = None
        self._handler = socket_handler(self)
        self._session_opts = dict(session_opts)

    def __del__(self):
        # explicitly close tempkey fd
        if self._keyfd is not None:
            self._keyfd.close()

        
    def _proto(self):
        return self._handler.protocol

    def _port_okay(self, dstport):
        return self._port is not None and dstport == self._port or True

    def got_dgram(self, dest, data, srcport, dstport):
        if self._port_okay(dstport):
            msg = self._handler.create_message(data)
            if msg is not None:
                msg.srcport = srcport
                msg.dstport = dstport
                self._handler.new_incoming(msg)
            else:
                self._log.error('malformed message')
        else:
            self._log.info('dropping packet with dstport=%d' % dstport)

    def _flush_send(self):
        """
        flush send queue
        """
        while True:
            msg = self._handler.poll_outgoing()
            if msg is None:
                break
            self._send_msg(msg)

    def _send_msg(self, msg):
        self._i2cp.send_message(msg.dest, msg.serialize(), 
                            msg.srcport, msg.dstport,
                            msg.message_class, msg.opts)


    def session_made(self, conn):
        """
        called after an i2cp session is made successfully with the i2p router
        :param conn: underlying connection
        """
        self._flush_send()


    def session_refused(self):
        """
        called if the i2p router refuses an i2cp session 
        """
        self.close()

    def disconnected(self, reason):
        """
        called if the i2cp session is disconnected abruptly
        """
        self.close()



    def connect(self, addr, keyfile=None):
        """
        connect to an i2p destination + port
        """
        if self._i2cp is not None:
            raise I2CPException('socket already in use')
            
        if keyfile is None:
            self._keyfd, keyfile = tmpkeyfile()

        self._i2cp = i2cp.Connection(self, keyfile=keyfile, i2cp_host='127.0.0.1', i2cp_port=7654, curve25519=False)
        self._start_i2cp()


    def _start_i2cp(self):
        """
        start i2cp session
        """
        self._i2cp.open()
        self._i2cp.start()

    def bind(self, addr):
        """
        craete a new i2p destination with key file
        """
        if self._i2cp is not None:
            raise I2CPException('socket already in use')

        if not isinstance(addr, tuple) or len(addr) != 2:
            raise I2CPException('bind() requires a tuple (keyfile, portno)')
        keyfile = addr[0]
        self._port = addr[1]
        self._i2cp = i2cp.Connection(self, keyfile=keyfile, i2cp_host=self._i2cp_host, i2cp_port=self._i2cp_port, curve25519=False)
        self._start_i2cp()
        

    def close(self):
        """
        close socket and underlying session
        """
        self._i2cp.close()


    def accept(self):
        """
        accept incoming connection
        """
        


def socket(name=None, type=None, i2cp_host='127.0.0.1', i2cp_port=7654, **kwargs):
    """
    create an i2p socket that uses i2cp
    
    :param name: the name of the tunnel or None for a random one
    :param type: SOCK_STREAM for tcp, SOCK_DGRAM for udp, SOCK_RAW for raw datagrams
    :param i2cp_host: the ip or hostname of an i2p router's i2cp interface
    :param i2cp_port: the port for an i2p router's i2cp interface
    :param kwargs: i2cp session options
    :return: a socket like object that goes over i2p
    """
    return _i2p_socket(i2cp_host, i2cp_port, kwargs)
