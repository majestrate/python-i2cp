#!/usr/bin/env python3.4
#
# i2p network stress tool 
# test how many messages we can send to a destination
#
# handle with care, may cause explosions
#
__doc__ = """
i2p network stress tool

usage: python3.4 -m i2p.tools.stress [--keyfile keys|--dest remote]

This script is going to be abused I just know it.

To skiddies who abuse this tool:
you can set the banner string at the variable _banner

"""

from i2p.i2cp import client as i2cp
from argparse import ArgumentParser as AP
import logging
import os
import threading
import time


_banner = """
sending packets to %%target%%
"""

now = time.ctime

_data = 0

def data():
    return int(_data)

def print_banner(target):
    print ( _banner.replace('%%target%%', target) )
        

def log(msg):
    print ('%s | %s' % (now(), msg))


def inc(amount):
    global _data
    _data += amount

def got_dgram(dgram, srcport, dstport):
    inc(len(dgram.data))

def main():
    logging.basicConfig(level=logging.INFO)
    ap = AP()

    ap.add_argument('--dest', type=str, default=None)
    ap.add_argument('--keyfile', type=str, default=None)
    ap.add_argument('--count', type=int, default=5)
    ap.add_argument('--host', type=str, default='127.0.0.1')
    ap.add_argument('--port', type=int, default=7654)
    ap.add_argument('--mtu', type=int, default=2 ** 12)
    
    args = ap.parse_args()

    opts = {
        'inbound.quantity' : '3',
        'outbound.quantity' : '10',
        'i2cp.fastReceive':'true'
    }


    if args.keyfile:
        cl = i2cp.Connection(i2cp_host=args.host, i2cp_port=args.port, handlers={'dgram':got_dgram})
        cl.open()
        cl.start_session(opts=opts,keyfile=args.keyfile)
        log(cl.dest.base32())
        while True:
            time.sleep(1)
            log('got %d bytes' % data())
    elif args.dest:
        payload = lambda : os.urandom(args.mtu)
        clients = []
        for n in range(args.count):
            cl = i2cp.Connection(None, i2cp_host=args.host, i2cp_port=args.port, session_options=opts,keyfile='%d.key'% n)
            cl.open()
            clients.append(cl)
            log('opened session %d' % n)
        
        def monitor():
            while True:
                time.sleep(1)
                log('sent %d bytes' % data())
        threading.Thread(target=monitor).start()
        while True:
            for cl in clients:
                raw = payload()
                cl.send_dgram(args.dest, raw)
                inc(len(raw))
                time.sleep(0.1)
    else:
        ap.print_help()

if __name__ == '__main__':
    main()
