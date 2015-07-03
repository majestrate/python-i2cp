from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *

from argparse import ArgumentParser as AP
import logging
import time
import os
from threading import Thread
from i2p.datatypes import Destination
from .client import Connection, I2CPHandler
import trollius as asyncio
from trollius import Return

class Handler(I2CPHandler):

    _log = logging.getLogger('handler')

    def __init__(self, dest, data, delay=1.5):
        self.dest = dest
        self.data = data
        self._delay = delay * 1.0

    def got_dgram(self, dest, data, srcport, dstport):
        self._log.info('got dgram from {}:{} to port {} : {}'.format (
            dest, srcport, dstport, [data]))

    def _send(self):
        if self.dest is not None:
            self.conn.send_dgram(self.dest, self.data)
            asyncio.get_event_loop().call_later(self._delay, self._send)


    def session_made(self, conn):
        self.conn = conn
        self._log.info('session made we are {}'.format(conn.dest))
        asyncio.get_event_loop().call_later(self._delay, self._send)

def main():
    ap = AP()
    ap.add_argument('--host', type=str, default='127.0.0.1')
    ap.add_argument('--port', type=int, default=7654)
    ap.add_argument('--debug', action='store_const', const=True, default=False)
    ap.add_argument('--keyfile', type=str, default='i2cp.key')
    ap.add_argument('--dgram', type=str, default='A'*4000)
    ap.add_argument('--dest', type=str)

    args = ap.parse_args()

    loglvl = args.debug and logging.DEBUG or logging.INFO
    format='%(levelname)s [%(asctime)s] | %(name)s | %(message)s'
    logging.basicConfig(format=format, level=loglvl)
    log = logging.getLogger('i2cp')
    dest = args.dest
    dgram = args.dgram
    opts = {
        'inbound.quantity' : '3',
        'outbound.quantity' : '3',
    }
    handler = Handler(dest, dgram)
    c1 = Connection(keyfile=args.keyfile, handler=handler, session_options=opts, i2cp_host=args.host, i2cp_port=args.port)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(c1.open())
    try:
        loop.run_forever()
    finally:
        loop.close()

if __name__ == '__main__':
    main()
