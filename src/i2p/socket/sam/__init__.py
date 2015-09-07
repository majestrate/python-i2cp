__doc__ = """
sam3 backend to i2p.socket
"""

from i2p.socket.sam import simple
import socket as pysocket

SOCK_STREAM = simple.SAM.SOCK_STREAM
SOCK_DGRAM = simple.SAM.SOCK_DGRAM
SOCK_RAW = simple.SAM.SOCK_RAW

# socket flags for shutdown()
SHUT_RD = pysocket.SHUT_RD
SHUT_WR = pysocket.SHUT_WR
SHUT_RDWR = pysocket.SHUT_RDWR

# Address family for SAM
# what! 9000?!
AF_SAM = 9002

def socket(family=None, type=SOCK_STREAM, proto=0, fileno=None, samaddr=('127.0.0.1', 7656)):
    """
    create a socket
    :param family: always set to AF_SAM, any other value will be ignored
    :param type: the type of connection, SOCK_STREAM / SOCK_DGRAM etc
    :param proto: unused at the moment
    :param samaddr: address of sam interface
    """
    if type in [SOCK_DGRAM, SOCK_RAW, SOCK_STREAM]:
        return simple.Socket(samaddr, type)
    else:
        raise ValueError("invalid socket type: {}".format(type))
