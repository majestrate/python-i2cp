#
# i2p.tun -- ipv6 compatability layer for i2p
#
from future.builtins import *


from i2p.i2cp import client as i2cp
from i2p.tun import tundev

# for ipv6 later
from i2p.tun import dht
# link protocol
from i2p.tun import link

import trollius as asyncio
from trollius import Return, From

import collections
import logging
import struct
import threading

import curses


class Handler(i2cp.I2CPHandler):

    _log = logging.getLogger("i2p.tun.Handler")

    _pump_interval = 0.01

    def __init__(self, tun, protocol, loop=None, noui=False, addr=None):
        """
        :param tun: a i2p.tun.tundev.Interface instance, must already be down
        ;ara
        """
        self._tundev = tun
        # include ip header + packet headers
        self._mtu = tun.mtu + 80
        self._protocol = protocol
        self._write_buff = collections.deque() 
        self._read_buff = collections.deque()
        # ip -> dest
        self._switch = dict()
        self.loop = loop or asyncio.get_event_loop()
        self._bw = 0
        self._pps = 0
        if noui:
            self._scr = None
        else:
            self._scr = curses.initscr()

    def update_ui(self):
        if self._scr:
            self._scr.clear()
            self._scr.box()
            self._scr.addstr(1, 1, "src: {}".format(self._conn.dest.base32()))
            self._scr.addstr(2, 1, "dst: {}".format(self._dest))
            self._scr.addstr(4, 1, "write buff: {}".format('#' * len(self._write_buff)))
            self._scr.addstr(5, 1, "read buff:  {}".format('#' * len(self._read_buff)))
            self._scr.addstr(7, 1, "link speed: {} Bps".format(self._bw))
            self._scr.addstr(8, 1, "pkt/sec:    {} pps".format(self._pps))
            self._scr.refresh()
        self._bw = 0
        self._pps = 0
        self.loop.call_later(1, self.update_ui)
        
    def session_made(self, conn):
        """
        we made a session with the i2p router
        set tun interface up, watch io on it
        """
        self._conn = conn

    def _tun_up(self, localaddr, remoteaddr, netmask):
        self._tundev.addr = localaddr
        self._tundev.dstaddr = remoteaddr
        self._tundev.netmask = netmask
        self._tundev.up()
        self._log.info("tun interface up")

        

    def session_ready(self, conn):
        self.loop.add_reader(self._tundev, self._read_tun, self._tundev)
        self.loop.call_soon(self._pump_tun)
        self.update_ui()
        
    def _run_loop(self):
        try:
            self.loop.run_forever()
        finally:
            self.loop.close()

    def __del__(self):
        curses.endwin()
            
    def got_dgram(self, dest, data, srcport, dstport):
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
        
    def _get_dest_for_ip(self, ip):
        """
        get the destination for this ip address
        :param ip: ip address to look for
        :return: None when not found or a desthash
        """
        if ip in self._switch:
            return self._switch[ip]
    
    def _pump_tun(self):
        # pump rpc
        if len(self._rpc_buff) > 0:
            frames = self._protocol.createFrames(self._rpc_buff, self._mtu, link.FrameType.Control)
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
                frames = self._protocol.createFrames(buff, self._mtu, link.FrameType.IP)
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
                    if pkt.type == link.FrameType.IP:
                        self._write_ip(dest, pkt.data)
                    elif pkt.type == link.FrameType.Control:
                        # handle a control message
                        self._handle_control(dest, pkt.data)
                    elif pkt.type == link.FrameType.KeepAlive:
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
        pkt = bencode.decode(data)
        # type check
        if isinstance(pkt, dict):
            # method
            if 'a' in pkt:
                method = pkt['a']
            if 'b' in pkt:
                params = list(pkt['b'])
        if method is None or params is None:
            # invalid packet
            return
        # handle rpc
        if 'c' in pkt:
            self._handle_rpc_resp(dest, pkt['c'], method, *params)
        else:
            self._handle_rpc_req(dest, method, *params)

    def _rpc_req_register(self, dest, method, *param):
        """
        handle a register request
        """
        resp = dict()
        resp["a"] = "register"
        # register ip address
        if len(params) == 1:
            ip = util.ip2bytes(param[0])
            if self._has_ip(ip):
                resp["b"] = "0.0.0.0"
                resp["c"] = 1
            else:
                self._register_ip(dest, ip)
                resp["b"] = param[0]
                resp["c"] = 0
        else:
            resp["b"] = "invalid parameters"
            resp["c"] = 2
        
    def _handle_rpc_req(self, dest, method, *params):
        """
        handle control rpc request
        :param dest: source destination
        :param method: rpc method
        :param params: rpc params for method
        """
        name = "_rpc_req_{}".format(method)

        # make error
        resp = {"c" :  2 , "b" : "no such method", "a" : method}

        if hasattr(self, name):
            resp = getattr(self, name)(dest, method, *params)
        data = bencode.encode(resp)

    def _register_ip(self, dest, ip):
        """
        register a dest to have an ip address
        :param dest: destination object
        :param ip: ip bytestring
        """
        self._switch[ip] = dest
                    
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
        self._conn.send_dsa_dgram(dest, data)

def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--hops", type=int, default=2, help="inbound/outbound tunnel length")
    ap.add_argument("--remote", type=str, default=None, help="remote destination to exchange ip packets with")
    ap.add_argument("--i2cp", type=str, default="127.0.0.1:7654", help="i2cp interface")
    ap.add_argument("--mtu", type=int, default=4096, help="interface mtu")
    ap.add_argument("--local-addr", type=str, default=None, help="our ip on our interface")
    ap.add_argument("--remote-addr", type=str, default=None, help="remote peer's ip")
    ap.add_argument("--netmask", type=str, default=None, help="interface's network mask")
    ap.add_argument("--iface", type=str, default="i2p0", help="what we want to call the new network interface")
    ap.add_argument("--keyfile", type=str, default="i2p.tun.key", help="i2cp destination keys")
    ap.add_argument("--debug", action="store_const", const=True, default=False, help="toggle debug mode")
    ap.add_argument("--tap", action="store_const", const=True, default=False, help="use tap instead of tun")
    ap.add_argument("--noui", action="store_const", const=True, default=False, help="do we disable the ui?")
    ap.add_argument("--ob", type=int, default=4 help="outbound tunnel quantity")
    ap.add_argument("--ib", type=int, default=4, help="inbound tunnel quantity")
    args = ap.parse_args()

    log = logging.getLogger("i2p.tun")

    if args.debug:
        lvl = logging.DEBUG
    else:
        lvl = logging.WARN

    i2cp_host = args.i2cp.split(":")[0]
    i2cp_port = int(args.i2cp.split(":")[-1])
        
    logging.basicConfig(level=lvl)
    loop = asyncio.new_event_loop()
    ftr = asyncio.Future(loop=loop)
    tun = None
    
    if args.remote is None:
        handler = i2cp.PrintDestinationHandler()
    else:
        tun = tundev.opentun(args.iface, args.tap)
        # set network interface properties
        tun.mtu = args.mtu

        # set parameters for exit if specified
        if args.netmask:
            tun.netmask = args.netmask
        if args.remote_addr:
            tun.dstaddr = args.remote_addr
        if args.local_addr:
            tun.addr = args.local_addr
            
        proto = link.FrameV0
        # make handler
        handler = Handler(args.remote, tun, proto, loop, args.noui, args.local_addr)

    opts = {'inbound.length':'%d' % args.hops, 'outbound.length' :'%d' % args.hops}
    opts['outbound.quantity'] = str(args.ob)
    opts['inbound.quantity'] = str(args.ib)
    conn = i2cp.Connection(handler, i2cp_host=i2cp_host, i2cp_port=i2cp_port, keyfile=args.keyfile, loop=loop, session_options=opts)
    loop.run_until_complete(conn.open())
    try:
        loop.run_forever()
    finally:
        if hasattr(handler, 'close'):
            handler.close()
    

if __name__ == "__main__":
    main()
