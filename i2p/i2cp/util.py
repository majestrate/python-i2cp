from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *
import base64
import struct
import zlib
import sys

# Py2 struct.pack() must take a native string as its format argument
# http://python-future.org/stdlib_incompatibilities.html#struct-pack
if sys.version_info[0] < 3:
    from future.utils import native as native_str
else:
    # No-op wrapper
    native_str = str

BUFFER_SIZE = 1024
NO_SESSION_ID = 65535
PROTOCOL_VERSION = b'\x2a'
_desthash_valid = '1234567890qwertyuiopasdfghjklzxcvbnm'

def struct_pack(fmt, *args):
    return struct.pack(native_str(fmt), *args)

def struct_unpack(fmt, *args):
    return struct.unpack(native_str(fmt), *args)

def get_as_int(data):
    if isinstance(data, int):
        return data
    else:
        return ord(data)

def timeout(sec):
    sec *= 1000
    ms = int(sec)
    return struct_pack('>I', ms)

def isdesthash(name):
    if isinstance(name, bytes):
        name = name.decode('utf-8')
    parts = name.split('.')
    if len(parts) != 3:
        return False
    for c in parts[0]:
        if c not in _desthash_valid:
            return False
    return len(name) == 60 and name.endswith('.b32.i2p')

def i2p_b64encode(data):
    if isinstance(data, str):
        data = bytes(data, 'ascii')
    return base64.b64encode(data, b'-~')

def i2p_b64decode(data):
    return base64.b64decode(data, b'-~')

def i2p_b32encode(data):
    return base64.b32encode(data).replace(b'=',b'').lower() + b'.b32.i2p'

def i2p_compress(data):
    if isinstance(data, str):
        data = bytes(data, 'utf-8')
    return zlib.compress(data)[2:]

def i2p_decompress(data):
    decompress = zlib.decompressobj(
            -zlib.MAX_WBITS
    )
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated


def check_portnum(num):
    return isinstance(num, int) and num < 2 ** 16 and num >= 0
