import base64
import struct

BUFFER_SIZE = 1024 * 16
NO_SESSION_ID = 65535
PROTOCOL_VERSION = b'\x2a'


def timeout(sec):
    sec *= 1000
    ms = int(sec)
    return struct.pack('>I', ms)

def isdesthash(name):
    return name.endswith('.b32.i2p')

def i2p_b64encode(data):
    return base64.b64encode(data, b'-~')

def i2p_b64decode(data):
    return base64.b64decode(data, b'-~')

def i2p_b32encode(data):
    return base64.b32encode(data).replace(b'=',b'').lower() + b'.b32.i2p'
