#!/usr/bin/env python3.4
#
#
import traceback
import logging
import time
from i2p import socket

__doc__ = '''
tcp over i2p main tester
'''



def main():
    """
    main driver
    """
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--listen', action='store_const', const=True, default=False)
    ap.add_argument('--debug', action='store_const', const=True, default=False)
    ap.add_argument('--host', default='psi.i2p')
    ap.add_argument('--port', default=80, type=int)

    args = ap.parse_args()

    lvl = logging.INFO
    
    if args.debug:
        lvl = logging.DEBUG
    
    logging.basicConfig(level=lvl)
    log = logging.getLogger("i2p.socket")
    log.debug("wait for interface to be up")
    # wait for the interface to go up
    socket.get_default_interface().up()
    log.debug(socket.get_default_interface().dest)
    if args.listen:
        while args.listen:
            time.sleep(1)
    try:
        log.debug("create socket")
        # make the socket
        sock = socket.socket()
        # run it
        log.debug("connect")
        sock.connect((args.host, args.port))
        log.debug("send")
        data = 'GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(args.host).encode("utf-8")
        sock.send(data)
        log.debug("sent")
        sock.recv(1024)
        log.debug("recv'd")
        sock.close()
        log.debug("closed")
    except Exception as e:
        log.error(e)
        traceback.print_exc(e)
    finally:
        socket.get_default_interface().close()

    


if __name__ == '__main__':
    main()
