import base64
import struct
import zlib

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

def deflate(data, compresslevel=2):
    compress = zlib.compressobj(
            compresslevel,
            zlib.DEFLATED,        
            -zlib.MAX_WBITS,      
            zlib.DEF_MEM_LEVEL,  
            0)
    deflated = compress.compress(data)
    deflated += compress.flush()
    return deflated
 
def inflate(data):
    data = data
    decompress = zlib.decompressobj(
            -zlib.MAX_WBITS
    )
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated
