#
# dht related functions
#

from future.builtins import *
from i2p.tun import bencode
from i2p.i2cp.datatypes import to_b32_bytes

from enum import Enum

__doc__ = """
dht provides a dht implementation that is used to resolve the destination of an ipv6 address


"""

class PacketType(Enum):

    CAPS = 1
    RESOLVE = 2
    ACQUIRE = 3
    RELEASE = 4

def build_data_packet(raw, version=6):
    """
    build a data packet for ip from raw ip packet
    """
    version = int(version)
    assert version in (4,6)
    return bencode.encode({"a":0, "x": raw, "z": version})

def build_dht_packet(type, **kwargs):
    """
    build a dht control packet
    """
    kwargs["a"] = int(type)
    return bencode.encode(kwargs)

def decode_packet(raw):
    """
    decode a packet from a buffer
    """
    pkt = bencode.decode(raw)
    if isinstance(pkt, dict):
        return pkt
    raise Exception("invalid dht packet, not of type dict")

def packet_is_repl(pkt):
    """
    :return: true if this packet is a reply packet
    """
    return "r" in pkt and pkt["r"] != '0'
    
def packet_is_ip(pkt, version=6):
    """
    :return: true if this packet is an ip packet of the given version
    """
    return "z" in pkt and pkt["z"] == version

def packet_is_control(pkt):
    """
    :return: true if this is a control packet
    """
    assert "a" in pkt
    return pkt["a"] != 0

def distance(x, y, short=False):
    """
    :param x: key as bytearray
    :param y: key as bytearray
    :return: the distance between key x and key y as an integer
    """
    assert len(x) == len(y)
    x , y = bytearray(x), bytearray(y)
    d = bytearray()
    for idx in range(len(x)):
        c = x[idx] ^ y[idx]
        d.append(c)
    d = int.from_bytes(d, 'big')
    if short:
        d %= len(x) * 8
    return d
    

def b32_distance(dest_x, dest_y, short=False):
    """
    :param dest_x: i2p destination x
    :param dest_y: i2p destination y
    :return: distance between x and y destinations
    """
    x, y = to_b32_bytes(dest_x), to_b32_bytes(dest_y)
    print(x,y)
    return distance(x, y, short)
    
    
def test_distance(k1, k2, short, b32=False):
    if b32:
        distance_func = b32_distance
    else:
        distance_func = distance
    if short:
        dist = lambda x,y: distance_func(x,y,True)
    else:
        dist = distance_func
    print ("test distance() short={}".format(short))
    print ("")
    print ("distance between {} and {}".format([k1], [k2]))
    print (dist(k1, k2))
    print ("")
    print ("distance between {} and {}".format([k2], [k1]))
    print (dist(k2, k1))
    print ("")
    print ("distance between {} and {}".format([k2], [k2]))
    print (dist(k2, k2))
    print ("")
    print ("distance between {} and {}".format([k1], [k1]))
    print (dist(k1, k1))
    print ("")
    
    assert dist(k1, k1) == dist(k2, k2)
    assert dist(k1, k2) == dist(k2, k1)
    assert dist(k1, k1) == 0
    assert dist(k2, k2) == 0

    assert distance(k1, k2, False) % (len(k1) * 8) == distance(k1, k2, True)

def test_packet(version):
    print ("test packet ip%d" % version)
    print ("")
    data = "asdf" * 32
    vers = version
    pktdata = build_data_packet(data, version=vers)
    print (pktdata)
    print ("")
    pkt = decode_packet(pktdata)
    print (pkt)
    print ("")
    assert packet_is_ip(pkt, version=vers)

def main():
    """
    dht test main
    """
    import os
    k1 = b'\x00' * 32
    k2 = b'\xff' * 32
    test_distance(k1, k2, True)
    test_distance(k1, k2, False)
    k1 = ('a' * 52 + '.b32.i2p').upper().encode('ascii')
    k2 = ('7' * 52 + '.b32.i2p').upper().encode('ascii')
    test_distance(k1, k2, True, True)
    test_distance(k1, k2, False, True)
    test_packet(4)
    test_packet(6)
    
if __name__ == "__main__":
    main()
