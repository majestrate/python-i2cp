from enum import Enum
import collections
import struct

ClumpingPacket = collections.namedtuple("ClumpingPacket", ["type", "data"])

class ClumpingFrameType(Enum):
    """
    frame types for clumping frames
    """
    KeepAlive = 1 << 0
    IP = 1 << 1
    Control = 1 << 2


    
class Clumping:
    """
    clumping frame protocol
    clumps ip packets into a single link level message
    """

    FrameType = ClumpingFrameType
    Packet = ClumpingPacket
    # 4 byte overhead per frame
    _frame_overhead = 4
    # 2 byte overhead per packet
    _packet_overhead = 2
    
    def __init__(self, mtu):
        self.mtu = int(mtu)
    
    def parseFrame(self, data):
        """
        :param data: bytearray
        :returns a generator of all packets:
        """
        type, packets = struct.unpack('>HH', data[:4])
        data = data[4:]
        if packets > 0:
            for _ in range(packets):
                l = struct.unpack('>H', data[:2])[0]
                yield self.Packet(self.FrameType(type), data[2:2+l])
                data = data[2+l:]

    def _create_frame(self, packets, type):
        """
        create 1 frame
        the total size of the frame must fit the link mtu
        """
        fr = bytearray()
        fr += struct.pack('>H', type.value)
        fr += struct.pack('>H', len(packets))
        for pkt in packets:
            fr += struct.pack('>H', len(pkt))
            fr += pkt
        return ClumpingPacket(type, fr)

    def createFrames(self, packets, type):
        """
        :param packets: a list of Packet instances
        :param type: link level frame type
        :returns a generator yielding each frame created:
        """
        if len(packets) > 0:
            current_frame_packets = list()
            current_frame_size = self._frame_overhead
            for pkt in packets:
                if current_frame_size + len(pkt) < self.mtu:
                    current_frame_packets.append(pkt)
                    current_frame_size += len(pkt) + self._packet_overhead
                else:
                    yield self._create_frame(current_frame_packets, type)
                    current_frame_packets = list()
            yield self._create_frame(current_frame_packets, type)

            


class Flat(Clumping):
    """
    subset of the clumping protocol that doesn't actually clump
    """

    def createFrames(self, packets, type):
        for pkt in packets:
            yield self._create_frame([pkt], type)
    
            
class BencodeRPC:
    """
    bencoded rpc protocol
    """

    
