from __future__ import absolute_import, division, print_function, unicode_literals
from builtins import *

__doc__ = """
example for i2p.i2cp
"""

from argparse import ArgumentParser as AP
import logging
import time
import os

# i2cp 
from i2p.i2cp.client import Connection, I2CPHandler
# asyncio comapt library
import trollius as asyncio
from trollius import Return

class Handler(I2CPHandler):
    """
    this is a high level i2cp session handler
    """

    
    _log = logging.getLogger('handler')

    def __init__(self, name, data, delay=1.5):
        """
        :param name: the name/b32 of the destination we want to send data to
        :param data: the data we want to send
        :param delay: how many seconds to delay in between sending of messages
        """
        self.name = name
        self.data = data
        self._delay = delay * 1.0
        self._dest = None
        self._ready = False
        
    def got_dgram(self, dest, data, srcport, dstport):
        """
        callback for when we got a datagram from the void
        :param dest: None if non repliable or a Destination of the sender
        :param srcport: the source port of this datagram
        :param dstport: the destination port of this datagram
        """
        # log it
        self._log.info('got dgram from {}:{} to port {} : {}'.format (
            dest, srcport, dstport, [data]))

    def _lookup_reply(self, dest):
        """
        called when we resolve the name of our destination we want to send to
        :param dest: None if the lookup failed otherwise the Destination for the name/b32 we want to send to
        """
        # was this a success?
        if dest:
            # yah
            self._log.info("we resolved our name to a destination")
            self._dest = dest
    
    def _send(self):
        """
        send our packet or lookup the destination of our remote host we want to send to
        """
        # are we going to send?
        if self.name:
            # yah
            if self._dest is None: # have we resolved the destination for this guy?
                # nah
                # look it up in the background
                self.conn.lookup_async(self.name, hook=self._lookup_reply)
            elif self._ready: # are we ready to send packets to other destinations?
                # yah
                self._log.info("send datagram")
                # send a signed datagram from us to them
                self.conn.send_dgram(self._dest, self.data)
            # call the function again in the background
            asyncio.get_event_loop().call_later(self._delay, self._send)

    def session_ready(self, conn):
        """
        called when we are ready to send messages to other destinations
        :param conn: our i2cp connection that we are using
        """
        self._log.info("we are ready")
        self._ready = True
            
    def session_made(self, conn):
        """
        called when we established a session to the router
        we can look up names/b32 but can't send messages to others yet
        :param conn: our i2cp connection that we are using
        """
        self.conn = conn
        self._log.info('session made we are {}'.format(conn.dest))
        asyncio.get_event_loop().call_later(self._delay, self._send)

def main():
    """
    main function
    """
    # set up arguments
    ap = AP()
    ap.add_argument('--i2cp-addr', type=str, default='127.0.0.1', help="The address of the i2cp interface we want to use")
    ap.add_argument('--i2cp-port', type=int, default=7654, help="The port of the i2cp interface we want to use")
    ap.add_argument('--debug', action='store_const', const=True, default=False, help="enable very very verbose debug")
    ap.add_argument('--keyfile', type=str, default='i2cp.key', help="the private key file for our destination")
    ap.add_argument('--dgram', type=str, default='A' * 1024, help="the message to send to a remote destination")
    ap.add_argument('--delay', type=float, default=1.0, help="how long should we wait between sending messages")
    ap.add_argument('--dest', type=str, help="the destination to send packets to if we are going to")

    # parse args
    args = ap.parse_args()

    # logging stuff
    loglvl = args.debug and logging.DEBUG or logging.INFO
    format='%(levelname)s [%(asctime)s] | %(name)s | %(message)s'
    logging.basicConfig(format=format, level=loglvl)
    log = logging.getLogger('i2cp')

    # i2cp options
    opts = {
        'inbound.quantity' : '3',
        'outbound.quantity' : '3',
    }
    # create our session handler
    handler = Handler(args.dest, args.dgram, args.delay)
    # create our I2CP Connection
    # pass the session handler to the connection in the constructor
    c1 = Connection(keyfile=args.keyfile, handler=handler, session_options=opts, i2cp_host=args.i2cp_addr, i2cp_port=args.i2cp_port)
    
    # you could also use None as a handler ...
    #
    # c2 = Connection(keyfile=args.keyfile+".other")
    # ...
    #
    # and then add a handler before calling open() ...
    #
    # c2.handler = SomeHandler()
    # loop.run_until_complete(c2.open())
    # ...
    #
    
    # get the event loop
    loop = asyncio.get_event_loop()
    # open the i2cp session to the i2p router
    loop.run_until_complete(c1.open())
    # run it
    try:
        loop.run_forever()
    finally:
        loop.close()

if __name__ == '__main__':
    main()
