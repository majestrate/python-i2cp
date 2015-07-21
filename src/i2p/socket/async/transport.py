#
#
#
__doc__ = """
implements i2p transport objects
"""

import logging

from i2p.i2cp import client

import trollius as asyncio
from trollius import From, Return


class BaseI2PTransport(asyncio.BaseTransport):
    """
    base i2p transport interface
    """

    _log = logging.getLogger("i2p.async.BaseI2PTransport")
    
    def __init__(self, i2cp):
        """
        initialize this transport 
        :param i2cp: an already established i2cp session
        """
        assert i2cp is not None
        self._i2cp = i2cp

    def close(self):
        """
        close this transport
        """
        self._closeSession()

    def _closeSession(self):
        """
        close the underlying i2cp connection
        """
        if self._i2cp:
            self._log.debug("closing i2cp session")
            self._i2cp.close()
            self._i2cp = None
        else:
            self._log.warn("i2cp session already closed")
        
    def abort(self):
        """
        abort all activity
        """
        self._closeSession()
            
class RWTransportMixIn(asyncio.ReadTransport, asyncio.WriteTransport):
    """
    mix in to make a transport do both read and write
    """

class TCPTransport(BaseI2PTransport, RWTransportMixIn):
    """
    tcp over i2p transport type
    """

    _log = logging.getLogger("i2p.async.TCPTransport")


@asyncio.coroutine
def createI2PTransportFactory(i2cp_host, i2cp_port):
    """
    create a new transport Factory used to create more transports
    uses one i2cp connection for all transports
    this is a coroutine
    """
    trans = TCPTransport()
    i2cp = client.Connection(trans, i2cp_host=i2cp_host, i2cp_port=i2cp_port)
