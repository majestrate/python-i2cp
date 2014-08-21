__author__ = 'jeff'
#!/usr/bin/env python
from i2p.i2cp import client as i2cp
import sys
import time

class EchoHandler(i2cp.I2CPHandler):
    """
    example i2cp session handler
    this echos back datagrams, but not streaming messages (tcp over i2p)
    """
    def __init__(self, remote):
        """
        construct
        """
        self.connection = None
        self.our_dest = None
        self.remote_dest = remote

    def session_made(self, conn):
        """
        we have connected to the i2p router and established a session
        """
        print ("session made")
        self.connection = conn
        self.our_dest = conn.dest
        print ("are address is %s" % self.our_dest.base32())

    def ping_loop(self):
        """
        send pings forever to remote destination
        """
        if self.remote_dest:
            while True:
                self.conn.send_dsa_dgram(self.remote_dest, "hello")
                time.sleep(1)

    def got_dgram(self, dest, data, srcport, dstport):
        """
        called when we got a datagram from someone
        if it is repliable reply with the standard DSA datagram
        """
        if dest is None:
            print ("we can't reply to a raw message, got: %s" % data)
        else:
            print ("we got a signed message from %s: %s" % (dest, data))
            self.connection.send_dsa_dgram(dest, data)


def main():
    remote = None
    if len(sys.argv) == 2:
        name = sys.argv[1]
        while remote is None:
            print ('looking up %s ...' % name)
            remote = i2cp.lookup(name)
            time.sleep(1)
        print ('found: %s' % remote.base32())

    handler = EchoHandler(remote)
    conn = i2cp.Connection(handler)
    conn.open()
    conn.start()


if __name__ == '__main__':
    main()
