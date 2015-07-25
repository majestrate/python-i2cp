#
# i2p.tun -- ipv6 compatability layer for i2p
#
from future.builtins import *


from i2p.i2cp import client as i2cp
from i2p.tun import tundev

# for ipv6 later
from i2p.tun import dht


import trollius as asyncio
from trollius import Return, From

import collections
import logging
import threading

import curses

class Handler(i2cp.I2CPHandler):

    _log = logging.getLogger("i2p.tun.Handler")
    
    def __init__(self, remote_dest, tun, packet_factory, loop=None):
        """
        :param tun: a i2p.tun.tundev.Interface instance, must already be configured and down
        """
        self._dest = remote_dest
        self._tundev = tun
        # include ip header
        self._mtu = tun.mtu + 60
        self._packet_factory = packet_factory
        self._write_buff = collections.deque() 
        self._read_buff = collections.deque()
        self.loop = loop or asyncio.get_event_loop()
        self._scr = curses.initscr()

    def update_ui(self):
        self._scr.clear()
        self._scr.box()
        self._scr.addstr(1, 1, "src: {}".format(self._conn.dest.base32()))
        self._scr.addstr(2, 1, "dst: {}".format(self._dest))
        self._scr.addstr(4, 1, "write buff: {}".format('#' * len(self._write_buff)))
        self._scr.addstr(5, 1, "read buff:  {}".format('#' * len(self._read_buff)))
        self.loop.call_later(0.1, self.update_ui)
        
    def session_made(self, conn):
        """
        we made a session with the i2p router
        set tun interface up, watch io on it
        """
        self._conn = conn
        self._tundev.up()
        self._log.info("tun interface up")
        

    def session_ready(self, conn):
        self.loop.add_reader(self._tundev, self._read_tun, self._tundev)
        self.loop.call_soon(self._pump_tun, self._tundev)
        self.update_ui()
        
    def _run_loop(self):
        try:
            self.loop.run_forever()
        finally:
            self.loop.close()

    def __del__(self):
        curses.endwin()
            
    def got_dgram(self, dest, data, srcport, dstport):
        #TODO: resolve self._dest to b32
        if dest.base32() == self._dest:
            dlen = len(data)
            if dlen > self._mtu:
                self._log.warn("drop packet too big: {} > {} (mtu)".format(dlen, self._mtu))
            else:
                self._recv_packet(data)

        else:
            self._log.warn("got unwarrented packets from {}".format(dest))

    def _recv_packet(self, data):
        """
        we got a packet
        """
        self._write_buff.append(data)
        self._log.info("recv q: {}".format('#' * len(self._write_buff)))

    def get_status(self):
        """
        :return: r, w
        """
        return len(self._read_buff), len(self._write_buff)
        
    def _pump_tun(self, dev):
        while len(self._write_buff) > 0:
            d = self._write_buff.pop()
            dev.write(d)
        while len(self._read_buff) > 0:
            d = self._read_buff.pop()
            self._send_packet(d)
        self.loop.call_later(0.0005, self._pump_tun, dev)
            
    def _read_tun(self, dev):
        """
        read from tun interface
        queue packets to remote endpoint sender
        """
        # read from interface
        self._log.debug("read tun")
        buff = dev.read(self._mtu)
        # make a packet
        data = self._packet_factory(buff)
        # serialize packet to bytes
        self._read_buff.append(data)
        self._log.info("send q: {}".format('#' * len(self._read_buff)))
        
    def _send_packet(self, data):
        """
        send a packet of data
        """
        self._log.debug("write {} to {}".format(len(data), self._dest))        
        # send to endpoint
        self._conn.send_dsa_dgram(self._dest, data)

def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--hops", type=int, default=2, help="inbound/outbound tunnel length")
    ap.add_argument("--remote", type=str, default=None, help="remote destination to exchange ip packets with")
    ap.add_argument("--i2cp", type=str, default="127.0.0.1:7654", help="i2cp interface")
    ap.add_argument("--mtu", type=int, default=4096, help="interface mtu")
    ap.add_argument("--local-addr", type=str, default=None, help="our ip on our interface")
    ap.add_argument("--remote-addr", type=str, default=None, help="remote peer's ip")
    ap.add_argument("--netmask", type=str, default="255.255.255.0", help="interface's network mask")
    ap.add_argument("--iface", type=str, default="i2ptun0", help="what we want to call the new network interface")
    ap.add_argument("--keyfile", type=str, default="i2p.tun.key", help="i2cp destination keys")
    ap.add_argument("--debug", action="store_const", const=True, default=False, help="toggle debug mode")
    ap.add_argument("--tap", action="store_const", const=True, default=False, help="use tap instead of tun")
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
        if args.local_addr is None:
            log.error("no local ip address specified")
            return
        if args.remote_addr is None:
            log.error("no remote ip address specified")
            return
        tun.addr = args.local_addr
        tun.dstaddr = args.remote_addr
        tun.mtu = args.mtu
        tun.netmask = args.netmask
        # make handler
        handler = Handler(args.remote, tun, lambda x : x, loop)

    opts = {'inbound.length':'%d' % args.hops, 'outbound.length' :'%d' % args.hops}
    opts['outbound.quantity'] = '4'
    opts['inbound.quntity'] = '2'
    conn = i2cp.Connection(handler, i2cp_host=i2cp_host, i2cp_port=i2cp_port, keyfile=args.keyfile, loop=loop, session_options=opts)
    loop.run_until_complete(conn.open())
    try:
        loop.run_forever()
    finally:
        if hasattr(handler, 'close'):
            handler.close()
    

if __name__ == "__main__":
    main()
