from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from future.builtins import int
from future import standard_library
standard_library.install_hooks()

import base64
import struct
import zlib

BUFFER_SIZE = 1024
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


def b32_to_bytes(data):
    print (data)
    data = data.split('.b32.i2p')[0].upper() + '===='
    print (data)
    return base64.b32decode(data)

def i2p_compress(data):
    #_compress = zlib.compressobj(
    #        2,
    #        zlib.DEFLATED,
    #        -zlib.MAX_WBITS,
    #        zlib.DEF_MEM_LEVEL,
    #        0)
    return zlib.compress(data)[2:]
    #deflated += _compress.flush()
    #return deflated

def i2p_decompress(data):
    decompress = zlib.decompressobj(
            -zlib.MAX_WBITS
    )
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated
