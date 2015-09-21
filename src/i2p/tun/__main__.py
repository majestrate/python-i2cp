#
# i2p.tun -- ipv6 compatability layer for i2p
#
from future.builtins import *


from i2p.i2cp import client as i2cp
from i2p.tun import tundev
# link protocol
from i2p.tun import protocol
from i2p.tun import link


import trollius as asyncio
from trollius import Return, From

import collections
import logging
import struct
import threading

import curses


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
    ap.add_argument("--ob", type=int, default=4, help="outbound tunnel quantity")
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
            
        proto = protocol.Clumping(args.mtu)
        # make handler
        handler = link.Handler(args.remote, tun, proto, loop, args.local_addr)

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
