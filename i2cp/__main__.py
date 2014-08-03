from argparse import ArgumentParser as AP
import logging
from .client import Connection
from .datatypes import destination

def main():
    ap = AP()
    ap.add_argument('--lookup', type=str)
    ap.add_argument('--tob32', type=str)
    ap.add_argument('--host', type=str, default='127.0.0.1')
    ap.add_argument('--port', type=int, default=7654)
    ap.add_argument('--debug', action='store_const', const=True, default=False)

    args = ap.parse_args()
    
    loglvl = args.debug and logging.DEBUG or logging.INFO
    logging.basicConfig(format='%(levelname)s [%(asctime)s] || %(message)s',level=loglvl)
    log = logging.getLogger('i2cp')
    
    if args.tob32:
        dest = destination(raw=args.tob32, b64=True)
        print(dest.base32())
        exit(0)

    c = Connection(i2cp_host=args.host, i2cp_port=args.port)
    c.open()

    if args.lookup:
        name = args.lookup
        log.debug('lookup name %s' % name)
        dest = c.lookup(name)
        c.close()
        print (dest.base32())
        print (dest.base64())
        exit(0)
    opts = {
        'inbound.quantity' : '16',
        'outbound.quantity' : '16',
        'inbound.nickname' : 'i2cpy',
        'i2cp.fastReceive':'true'
    }
    c.start_session(opts)


if __name__ == '__main__':
    main()
