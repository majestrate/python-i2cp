from i2p import socket

from unittest import TestCase

class TestSocket(TestCase):

    def setUp(self):
        # set up i2p socket module
        socket.setup(("10.0.3.1", 7654))
        
    def test_connect(self):
        """
        test socket connections
        """
        sock = socket.socket()
        assert not sock.isConnected()
        sock.connect(("psi.i2p", 80))
        assert sock.isConnected()
        sock.close()
        assert not sock.isConnected()

    def test_bind(self):
        """
        TODO: implement
        """
        assert False
        
