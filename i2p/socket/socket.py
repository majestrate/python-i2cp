from i2p.i2cp import client
from i2p.i2cp import crypto 
from i2p.i2cp import datatypes 
from i2p.i2cp import exceptions  
from i2p.i2cp import util 
from i2p.socket import streaming 

import logging
import queue

import trollius as asyncio
from trollius import Return, From

class _i2p_base_socket(client.I2CPHandler):

    def __init__(self, i2cp_host, i2cp_port, keyfile, session_opts):
        """
        base socket object
        provides reliable streaming over i2p
        """
        self._log = logging.getLogger(self.__class__.__name__)
        self._i2cp_host , self._i2cp_port = i2cp_host, i2cp_port
        self._dest = None
        self._port = None
        self._keyfile = keyfile or util.tmpkeyfile()
        self._keyfd = open(self._keyfile, 'rb')
        self._session_opts = dict(session_opts)
        self.i2cp = client.Connection(self, keyfile=self._keyfile, i2cp_host=self._i2cp_host, i2cp_port=self._i2cp_port)

    @asyncio.coroutine
    def handle_packet(self, pkt, srcport, dstport):
        
        
    def __del__(self):
        # explicitly close tempkey fd
        if self._keyfd is not None:
            self._keyfd.close()


class _i2p_socket(object):

    def __init__(self, factory):
        self._factory = factory

    def connect(self, addr, keyfile=None):
        """
        connect to an i2p destination + port
        """
        if self._i2cp is not None:
            raise I2CPException('socket already in use')
            
        #if keyfile is None:
        #    self._keyfd, keyfile = 

        self._i2cp = i2cp.Connection(self, keyfile=keyfile, i2cp_host='127.0.0.1', i2cp_port=7654)
        self._start_i2cp()



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
        #self._i2cp = i2cp.Connection)
        #self._start_i2cp()
        

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
    
    sock = _i2p_socket(i2cp_host, i2cp_port, kwargs)
    return sock
