#!/usr/bin/env python3.4
#
#

from . import socket as i2psocket

__doc__ = '''
tcp over i2p main tester
'''



def main():
    """
    main driver
    """
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='psi.i2p')
    ap.add_argument('--port', default=80, type=int)

    args = ap.parse_args()

    sock = i2psocket()

    sock.connect((args.host, args.port))
    data = bytes('GET / HTTP/1.0\r\n\r\n')
    sock.send(data)
    data = sock.recv(1024)
    sock.close()
    print (data)



if __name__ == '__main__':
    main()
