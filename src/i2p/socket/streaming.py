import struct
import logging
from enum import Enum
from i2p.i2cp import datatypes

class packet_flag(Enum):
    SYNC = 1 << 0
    CLOSE = 1 << 1
    RESET = 1 << 2
    SIG_INC = 1 << 3
    SIG_REQ = 1 << 4
    FROM_INC = 1 << 5
    DELAY = 1 << 6
    MAX_PACKET_SIZE = 1 << 7
    PROFILE_INTERACTIVE = 1 << 8
    ECHO = 1 << 9
    NO_ACK = 1 << 10
    

def get_flags(flags):
    """
    get a list of flags set given integer
    """
    ret = []
    for flag in packet_flag.__members__:
        flag = getattr(packet_flag, flag)
        if flags & flag.value == flag.value:
            ret.append(flag)
    return ret


class packet:

    _size_table = {
        4 : '>I',
        2 : '>H',
        1 : 'B'
    }

    _packet_first = (
        (4, 'send_sid'),
        (4, 'recv_sid'),
        (4, 'seqno'),
        (4, 'ack_thru'),
        (1, '_nack_count')
    )
    
    _packet_second = (
        (1, 'resend_delay'),
        (2, 'flags'),
        (2, '_opts_len')
    )

    
    _log = logging.getLogger("streaming-packet")

    def __init__(self, raw=None, 
                 send_sid=0, recv_sid=0, seqno=0, 
                 ack_thru=0, nacks=[], resend_delay=0, 
                 flags=[], opts=None, payload=None):
        """
        streaming packet

        from raw=<data> or with parameters
        """
        if raw is None:
            self.send_sid = send_sid
            self.recv_sid = recv_sid
            self.seqno = seqno
            self.ack_thru = ack_thru
            self.nacks = list(nacks)
            self.resend_delay = resend_delay
            self.flags = flags
            self.opts = opts or bytes()
            self.payload = payload            
        else:
            for size, name in self._packet_first:
                _str = self._size_table[size]
                part = raw[:size]
                val = struct.unpack(_str,part)[0]
                raw = raw[size:]
                setattr(self, name, val)

            self.nacks = []
            for n in range(self._nack_count):
                part = raw[:4]
                val = struct.unpack('>I', part)[0]
                raw = raw[4:]
                self.nacks.append(val)

            for size, name in self._packet_second:
                unpstr = self._size_table[size]
                part = raw[:size]
                val = struct.unpack(unpstr,part)[0]
                raw = raw[size:]
                setattr(self, name, val)
            
            self.opts = raw[:self._opts_len]
            self.payload = raw[self._opts_len:]
            self.flags = get_flags(self.flags)
    
    def serialize(self):
        """
        serialize to bytearray
        """
        data = bytearray()
        for name, size in self._packet_first[:-1]:
            _str = self._size_table[size]
            val = getattr(self, name)
            data += struct.pack(_str, val)

        data += struct.pack('B', len(self.nacks))

        for nack in self.nacks:
            data += struct.pack('>I', nack)

        for name, size in self._packet_second[:-1]:
            _str = self._size_table[size]
            val = getattr(self, name)
            data += struct.pack(_str, val)
        
        data += struct.pack('>H', len(self.opts))
        data += self.opts
        data += bytearray(self.payload)
        return data
 
    def __repr__(self): 
        attrs = ('flags', 'send_sid', 'recv_sid', 'seqno', 'ack_thru', 'nacks', 'opts', 'payload')
        _str = '[Streaming Packet '
        for attr in attrs:
            _str += '%s=%s ' % ( attr, getattr(self, attr))
        return _str + ']'

    def verify(self):
        """
        verify the signature on this streaming packet if it has one
        :return: true if valid otherwise false
        """
        if packet_flags.SIG_INC in self.flags:
            self._log.debug("verify packet signature")
            # TODO: implement
            self._log.warn("packet not verified, not implemented")
            return True
        else:
            return True

    def is_syn(self):
        """
        :return: if this is an initial incoming syn packet
        """
        return self.has_flags(packet_flags.FROM_INC, packet_flags.SYNC, packet_flags.SIG_INC)

    def get_from(self):
        """
        :return: the destination of who sent this packet
        """
        offset = 0
        if packet_flags.DELAY in self.flags:
            offset += 2
        if packet_flags.FROM_INC in self.flags:
            return datatypes.destination(raw=self.options[offset:])
        return None
        
    def is_rst(self):
        """
        :return: true if this is a valid rst packet
        """
        return self.has_flags(packet_flags.FROM_INC, packet_flags.RESET, packet_flags.SIG_INC)
        
    def has_flags(self, *args):
        """
        check if all the given flags are set in this packet
        :return: true if all flags are set, otherwise false
        """
        for arg in args:
            if arg not in self.flags:
                return False
        return True


    def is_ack(self):
        """
        :return: true if this is a regular ack
        """
        return self.seqno == 0 and packet_flags.SYNC not in self.flags
