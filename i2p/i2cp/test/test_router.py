from unittest import TestCase
import socket

class TestI2PRouter(TestCase):

    def test_router_i2cp_enabled(self):
        sock = socket.socket()
        try:
            sock.connect(('127.0.0.1', 7654))
            sock.close()
        except OSError:
            enabled = False
        else:
            enabled = True
        assert enabled
