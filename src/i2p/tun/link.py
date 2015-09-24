
from i2p import socket
from i2p.datatypes import Destination
import trollius as asyncio
import collections
import logging

class SAMLink:

    _log = logging.getLogger("i2p.tun.Handler")

    _pump_interval = 0.075

    def __init__(self, remote, tundev, switch, protocol, keyfile, samcfg=None, loop=None):
        """
        """
        self._switch = switch
        self._remote_dest = remote
        self._tundev = tundev
        self._protocol = protocol
        self._write_buff = collections.deque() 
        self._read_buff = collections.deque()
        self.loop = loop or asyncio.get_event_loop()
        self._bw = 0
        self._pps = 0
        self._log.debug("creating sam")
        if samcfg:
            samaddr = (samcfg["controlHost"], samcfg["controlPort"])
            dgramaddr = (samcfg["dgramHost"], samcfg["dgramPort"])
            dgrambind = (samcfg["dgramBind"], 0)
            self._conn = socket.socket(type=socket.SOCK_DGRAM, samaddr=samaddr, dgramaddr=dgramaddr, dgrambind=dgrambind)
        else:
            self._conn = socket.socket(type=socket.SOCK_DGRAM)
        self._conn.bind(keyfile)
        self._log.debug("sam bound")
        self.dest = Destination(raw=self._conn.getsocketinfo(), b64=True)
        self.loop.add_reader(self._tundev, self._read_tun)
        self.loop.add_reader(self._conn, self._read_sock)
        self.loop.call_soon(self._pump)
        
    def got_dgram(self, dest, data):
        """
        we got a packet
        """
        self._log.debug('got dgram')
        self._write_buff.append((dest,data))

    def get_status(self):
        """
        :return: r, w
        """
        return len(self._read_buff), len(self._write_buff)
    
    def _pump(self):
        # pump rpc
        #if len(self._rpc_buff) > 0:
        #    frames = self._protocol.createFrames(self._rpc_buff, self._protocol.FrameType.Control)
        #    for frame in frames:
        #        self._send_packet(dest, frame.data)
        #    self._rpc_buff = collections.deque()

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
            for ip, buff, in pkts.items():
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
                    else:
                        self._log.warn('invalid packet type in frame: {}'.format(pkt.type))
            else:
                self._log.warn('no data in frame')
        # call again
        self.loop.call_later(self._pump_interval, self._pump)


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
        # TODO: filter packets
        # schedule it
        self._log.debug('write ip')
        self.loop.call_soon(self._tundev.write, pktdata)
        
        
    def _read_tun(self):
        """
        read from tun interface
        queue packets to remote endpoint sender
        """
        # read packet + overhead
        self._log.debug('readtun')
        buff = self._tundev.read(self._protocol.mtu + 64)
        self._read_buff.append((None, buff))

    def _read_sock(self):
        self._log.debug('read sock')
        result = self._conn.recvfrom(self._protocol.mtu + 64)
        if result:
            dest, pkt = result
            self.got_dgram(dest, pkt)
            
    def _send_packet(self, dest, data):
        """
        send a packet of data
        """
        self._pps += 1
        self._bw += len(data)
        self._log.debug("write {} to {}".format(len(data), dest))        
        # send to endpoint
        self._conn.sendto(data, (dest,0))

    def _get_dest_for_ip(self, ip):
        return self._switch.destForIP(ip)


Handler = SAMLink
