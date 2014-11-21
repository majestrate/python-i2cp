from i2p.i2cp.crypto import *
from i2p.i2cp.datatypes import *
from i2p.i2cp.exceptions import *
from i2p.i2cp.util import *


def parse_datagram(raw):
    """
    given raw data build the appropriate datagram
    :return: a datagram from raw data
    """
    payload = i2cp_payload(raw=raw)
    classes = {
        i2cp_protocol.RAW: datagram,
        i2cp_protocol.DGRAM: dsa_datagram,
        i2cp_protocol.DGRAM_25519: curve25519_dgram
    }
    if payload.proto in classes:
        return classes[payload.proto](raw=raw)
