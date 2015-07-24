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

import logging

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
        self._write_buff = list()
        if loop:
            self.loop = loop
        else:
            self.loop = asyncio.get_event_loop()

    def session_made(self, conn):
        """
        we made a session with the i2p router
        set tun interface up, watch io on it
        """
        self._conn = conn
        print("tun interace going up...")
        self._tundev.up()
        self._log.info("tun interface up")

    def session_ready(self, conn):
        self.loop.add_reader(self._tundev, self._read_tun, self._tundev)
        print ("interface ready")
        print ("we are {} talking to {}".format(self._conn.dest.base32(), self._dest))

    def got_dgram(self, dest, data, srcport, dstport):
        #TODO: resolve self._dest to b32
        if dest.base32() == self._dest:
            dlen = len(data)
            if dlen > self._mtu:
                self._log.warn("drop packet too big: {} > {} (mtu)".format(dlen, self._mtu))
            else:
                self._log.debug("write {} to tun".format(dlen))
                self._tundev.write(data)

        else:
            self._log.warn("got unwarrented packets from {}".format(dest))
        
    def _read_tun(self, dev):
        """
        read from tun interface
        sends packets to remote endpoint
        """
        # read from interface
        self._log.debug("read tun")
        buff = dev.read(self._mtu)
        # make a packet
        data = self._packet_factory(buff)
        # serialize packet to bytes
        self._log.debug("write {} to {}".format(len(data), self._dest))
        # send to endpoint
        self._conn.send_dsa_dgram(self._dest, data)

def main():
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--hops", type=str, default=2, help="inbound/outbound tunnel length")
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
    # wait sleeptime seconds for our connection to be done or retry
    def _wait_for_done(conn, sleeptime):
        if conn.is_done():
            ftr.set_result(True)
            if tun:
                tun.down()
                tun.close()
        else:
            loop.call_later(sleeptime, _wait_for_done, conn, sleeptime)
            
    
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
    conn = i2cp.Connection(handler, i2cp_host=i2cp_host, i2cp_port=i2cp_port, keyfile=args.keyfile, loop=loop, session_options=opts)
    loop.run_until_complete(conn.open())
    loop.call_soon(_wait_for_done, conn, 1.0)
    loop.run_until_complete(ftr)
    

if __name__ == "__main__":
    main()
