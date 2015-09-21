
from i2p import socket
import asyncio
import collections

class SAMLink:

    _log = logging.getLogger("i2p.tun.Handler")

    _pump_interval = 0.01

    def __init__(self, switch, link_protocol, keyfile, loop=None):
        """
        """
        self._switch = switch
        self._protocol = protocol
        self._write_buff = collections.deque() 
        self._read_buff = collections.deque()
        self.loop = loop or asyncio.get_event_loop()
        self._bw = 0
        self._pps = 0
        self._conn = socket.socket(type=socket.SOCK_DGRAM)
        self._conn.bind(keyfile)
        
        
    def _tun_up(self, localaddr, remoteaddr, netmask):
        self._switch.setTunAddr(localaddr, remoteaddr, netmask)
        self._switch.tunIfaceUp()
        self._log.info("tun interface up")
            
    def got_dgram(self, dest, data):
        dlen = len(data)
        if dlen > self._mtu:
            self._log.warn("drop packet too big: {} > {} (mtu)".format(dlen, self._mtu))
        else:
            self._recv_packet(dest, data)

    def _recv_packet(self, dest, data):
        """
        we got a packet
        """
        self._write_buff.append((dest,data))
        self._log.info("recv q: {}".format('#' * len(self._write_buff)))

    def get_status(self):
        """
        :return: r, w
        """
        return len(self._read_buff), len(self._write_buff)
    
    def _pump_tun(self):
        # pump rpc
        if len(self._rpc_buff) > 0:
            frames = self._protocol.createFrames(self._rpc_buff, self._protocol.FrameType.Control)
            for frame in frames:
                self._send_packet(dest, frame.data)
            self._rpc_buff = collections.deque()

        # create frame to send to remote
        if len(self._read_buff) > 0:
            # group packets 
            pkts = dict()
            while len(self._read_buff) > 0:
                ip, buff = self._read_buff.pop()
                if ip not in pkts:
                    pkts[ip] = collections.deque()
                pkts[ip].append(buff)
            
            # make frames
            for ip, buff, in pkts.iteritems():
                # create frames
                frames = self._protocol.createFrames(buff, self._protocol.FrameType.IP)
                # get dest for ip
                dest = self._get_dest_for_ip(ip)
                if dest is None:
                    self._log.warn("unknown dest for ip: {}".format(ip))
                else:
                    # send frames
                    for f in frames:
                        self._send_packet(dest, f.data)

        # get all frames from remote
        while len(self._write_buff) > 0:
            # read frame from remote
            dest, data = self._write_buff.pop()
            # make packets from frame
            pkts = self._protocol.parseFrame(data)
            if pkts:
                for pkt in pkts:
                    if pkt.type == self._protocol.FrameType.IP:
                        self._write_ip(dest, pkt.data)
                    elif pkt.type == self._protocol.FrameType.Control:
                        # handle a control message
                        self._handle_control(dest, pkt.data)
                    elif pkt.type == self._protocol.FrameType.KeepAlive:
                        # keep this guy alive
                        self._keep_alive(dest)
        # call again
        self.loop.call_later(self._pump_interval, self._pump_tun)


    def _handle_control(self, dest, data):
        """
        handle control packet
        :param dest: source destination
        :param data: bencoded data
        """
        method = None
        params = None
                    
    def _write_ip(self, dest, pktdata):
        """
        write an ip packet from a destination to the interface
        :param dest: the remote destination
        :param pktdata: bytearray of packet data
        """
        
        
    def _read_tun(self, dev):
        """
        read from tun interface
        queue packets to remote endpoint sender
        """
        # read from interface
        self._log.debug("read tun")
        buff = dev.read(self._mtu)
        self._read_buff.append(buff)

    def _send_packet(self,dest, data):
        """
        send a packet of data
        """
        self._pps += 1
        self._bw += len(data)
        self._log.debug("write {} to {}".format(len(data), dest))        
        # send to endpoint
        self._conn.sendto(dest, data)
