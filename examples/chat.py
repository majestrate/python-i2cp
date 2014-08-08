#!/usr/bin/env python3.4
#
# simple distributed chat client
#
from i2p.i2cp import client as i2cp
import curses
import json
import threading
from argparse import ArgumentParser as AP

class ChatHandler(i2cp.I2CPHandler):
    
    def __init__(self, peers, protocol):
        self.peers = peers
        self.dests = dict()
        self.connection = None
        self.protocol = protocol


    def got_dgram(self, dest, data, srcport, dstport):
        chat = self.protocol.parse_message(dest, data)
        if self.ui:
            self.ui.message(chat)

    def session_made(self, conn):
        """
        we have successfully created a session
        """
        self.connection = conn
        if self.ui:
            self.ui.message('we have connected')
            self.ui.message('we are %s' % conn.dest.base32())
        for peer in self.peers:
            dest = None
            while dest is None:
                dest = i2cp.lookup(peer)
            self.dests[peer] = dest
            self.ui.message('found %s' % dest.base32())

    def send_alive(self):
        msg = self.protocol.alive_message()
        self.send_raw(msg)

    def send_chat(self, chat):
        """
        send a chat message
        """
        if self.connection is None:
            if self.ui:
                self.ui.message('cannot send, not connected yet')
        else:
            msg = self.protocol.gen_message(chat)
            # send message to all remote peer
            self.send_raw(msg)

    def send_raw(self, raw):
        for peer in self.dests:
            dest = self.dests[peer]
            self.connection.send_ed25519_dgram(dest, raw)


class json_protocol:

    def gen_message(self, msg, channel="#public"):
        return json.dumps({
            'msg':msg.decode('utf-8'),
            'chan':channel,
            })

    def parse_message(self,dest, msg):
        try:
            j = json.loads(msg.decode('utf-8'))
            assert 'msg' in j
            assert 'chan' in j
        except Exception as e:
            return 'Error: %s' % e
        return '<%s@%s> %s' % (dest.base32()[:8], j['chan'], j['msg'])

class console_ui:

    def message(self, line):
        self.chat.append(line)
        while len(self.chat) > 20:
            self.chat.pop(0)
        self.draw()

    def run(self):
        self.win = curses.initscr()
        self.chat = []
        self.message('started')
        while True:
            self.win.move(1,1)
            chat = self.win.getstr()
            self.send(chat)
            self.message('<you> %s' % chat.decode('utf-8'))

    def draw(self):
        self.win.clear()
        self.win.box()
        col, row = 2 , 2 
        self.win.move(col, row)
        for chat in self.chat:
            self.win.addstr(chat)
            col += 1
            self.win.move(col, row)
        self.win.move(1,1)
        self.win.refresh()


def main():
    ap = AP()
    ap.add_argument('--peer', type=str, required=True)
    args = ap.parse_args()
    handler = ChatHandler([args.peer], json_protocol())
    ui = console_ui()
    ui.send = handler.send_chat
    handler.ui = ui
    connection = i2cp.Connection(handler)
    connection.open()
    connection.start()
    ui.run()

if __name__ == '__main__':
    main()
