from argparse import ArgumentParser as AP
import logging
import time
import os
from .client import Connection, lookup
from .datatypes import destination

def main():
    ap = AP()
    ap.add_argument('--host', type=str, default='127.0.0.1')
    ap.add_argument('--port', type=int, default=7654)
    ap.add_argument('--debug', action='store_const', const=True, default=False)
    ap.add_argument('--keyfile', type=str, required=True)
    ap.add_argument('--dgram', type=str, default='A'*100)
    ap.add_argument('--dest', type=str)

    args = ap.parse_args()
    
    loglvl = args.debug and logging.DEBUG or logging.INFO
    format='%(levelname)s [%(asctime)s] || %(message)s'
    logging.basicConfig(level=loglvl)
    log = logging.getLogger('i2cp')
    dest = args.dest
    dgram = args.dgram

    c1 = Connection(i2cp_host=args.host, i2cp_port=args.port)
    c1.open()
    opts = {
        'inbound.quantity' : '16',
        'outbound.quantity' : '16',
        'i2cp.fastReceive':'true'
    }
    c1.start_session(opts, keyfile=args.keyfile)
    while args.dest:
        c1.send_dgram(dest, dgram)
        time.sleep(1)
    
    
if __name__ == '__main__':
    main()
