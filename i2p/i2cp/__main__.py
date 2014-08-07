from argparse import ArgumentParser as AP
import logging
import time
import os
from threading import Thread
from .client import Connection, lookup, I2CPHandler
from .datatypes import destination


class Handler(I2CPHandler):

    _log = logging.getLogger('handler')

    def __init__(self, dest, data):
        self.dest = dest
        self.data = data
        self.process = None

    def send_loop(self, conn):
        while conn.is_open():
            if self.dest is not None:
                conn.send_ed25519_dgram(self.dest, self.data)
            time.sleep(1)

    def got_dgram(self, dest, data, srcport, dstport):
        self._log.info('got dgram from %s:%d to port %d : %s' % (
            dest, srcport, dstport, data))
        
    def session_made(self, conn):
        self.process = Thread(target=self.send_loop, args=(conn,))
        self.process.start()

    def end(self):
        if self.process is not None:
            self.process.join()

def main():
    ap = AP()
    ap.add_argument('--host', type=str, default='127.0.0.1')
    ap.add_argument('--port', type=int, default=7654)
    ap.add_argument('--debug', action='store_const', const=True, default=False)
    ap.add_argument('--keyfile', type=str, default='i2cp.key')
    ap.add_argument('--dgram', type=str, default='A'*100)
    ap.add_argument('--dest', type=str)

    args = ap.parse_args()
    
    loglvl = args.debug and logging.DEBUG or logging.INFO
    format='%(levelname)s [%(asctime)s] || %(message)s'
    logging.basicConfig(format=format, level=loglvl)
    log = logging.getLogger('i2cp')
    dest = args.dest
    dgram = args.dgram
    opts = {
        'inbound.quantity' : '16',
        'outbound.quantity' : '16',
        'i2cp.fastReceive':'true'
    }
    handler = Handler(dest, dgram)
    c1 = Connection(keyfile=args.keyfile, handler=handler, session_options=opts, i2cp_host=args.host, i2cp_port=args.port)
    c1.open()

    c1.start()
    
if __name__ == '__main__':
    main()
