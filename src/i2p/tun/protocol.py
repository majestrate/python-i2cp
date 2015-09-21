from enum import Enum
import collections

CumpingPacket = namedtuple("ClumpingPacket", ["type", "data"])

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
        self._mtu = int(mtu)
    
    def parseFrame(self, data):
        """
        :param data: bytearray
        :returns a list of Packet instances:
        """

    def _create_frame(self, packets, type):
        """
        create 1 frame
        the total size of the frame must fit the link mtu
        """
        fr = bytearray()
        fr += struct.pack('>H', type.value)
        fr += struct.pack('>H', len(packets))
        for pkt in packets:
            

    def createFrames(self, packets, type):
        """
        :param packets: a list of Packet instances
        :param type: link level frame type
        :returns a generator yielding each frame created:
        """
        current_frame_packets = list()
        current_frame_size = self._frame_overhead
        for pkt in packets:
            if current_frame_size + len(pkt.data) < self._mtu:
                current_frame_packets.append(pkt)
                current_frame_size += len(pkt.data) + self._packet_overhead
            else:
                yield self._create_frame(current_frame_packets, type)
                current_frame_packets = list()
        yield self._create_frame(current_frame_packets, type)

            


class BencodeRPC:
    """
    bencoded rpc protocol
    """

    
