from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *

from argparse import ArgumentParser as AP
import logging
import time
import os
from threading import Thread
from .client import Connection, I2CPHandler
from .datatypes import destination
import trollius as asyncio
from trollius import Return

class Handler(I2CPHandler):

    _log = logging.getLogger('handler')

    def __init__(self, dest, data):
        self.dest = dest
        self.data = data

    @asyncio.coroutine
    def got_dgram(self, dest, data, srcport, dstport):
        self._log.info('got dgram from {}:{} to port {} : {}'.format (
            dest, srcport, dstport, [data]))
        raise Return()
    
    def _send(self):
        if self.dest is not None:
            self.conn.send_dgram(self.dest, os.urandom(len(self.data)))
            asyncio.get_event_loop().call_later(1.0, self._send)
        
        
    @asyncio.coroutine
    def session_made(self, conn):
        self.conn = conn
        self._log.info('session made')
        asyncio.get_event_loop().call_later(1.0, self._send)
        raise Return()
        
def main():
    ap = AP()
    ap.add_argument('--host', type=str, default='127.0.0.1')
    ap.add_argument('--port', type=int, default=7654)
    ap.add_argument('--debug', action='store_const', const=True, default=False)
    ap.add_argument('--keyfile', type=str, default='i2cp.key')
    ap.add_argument('--dgram', type=str, default='A'*1000)
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
    c1.open()
    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    finally:
        loop.close()
        
if __name__ == '__main__':
    main()
