#
# public domain
#
__doc__ = """
simple sam i2p socket implemenation
"""

from i2p import datatypes
from enum import Enum

import collections
import logging
import os
import string
import random
import socket as pysocket

from contextlib import wraps



class State(Enum):
    """
    state of a sam socket
    """
    
    Initial = 0
    """
    we are not connected to anything, initial state
    """
    
    Established = 1
    """
    we have established a session with sam
    """
    
    Ready = 2
    """
    we are ready to do stuff
    """
    
    Connecting = 3
    """
    we are connecting or binding
    """
    
    Running = 4
    """
    we are connected or bound
    """
    
    Closing = 5
    """
    closing all connections
    """
    
    Closed = 6
    """
    sam connection closed entirely
    """    
    
    Error = 7
    """
    an error occured
    """
    
class SAM:
    """
    decorator constants
    """
    SOCK_STREAM = datatypes.I2CPProtocol.STREAMING
    SOCK_DGRAM = datatypes.I2CPProtocol.DGRAM
    SOCK_RAW = datatypes.I2CPProtocol.RAW

def randnick(l):
    nick = ''
    for n in range(l):
        nick += random.choice(string.ascii_letters)
    return nick
    
def _sam_readline(sock):
    """
    read a line from a sam control socket
    """
    response = bytearray()
    while True:
        c = sock.recv(1)
        if c:
            if c == b'\n':
                break
            response += c
        else:
            break
    return response.decode('ascii')

SamReply = collections.namedtuple('SamReply', ['cmd', 'opts'])

def _sam_parse_reply(line):
    """
    parse a reply line into a dict
    """
    opts = dict()
    parts = line.split(' ')

    for part in parts[2:]:
        if '=' in part:
            idx = part.index('=')
            k = part[:idx]
            v = part[1+idx:]
            opts[k] = v
    return SamReply(parts[0], opts)

def _sam_cmd(sock, line):
    """
    do a sam command on a socket
    :returns result:
    """
    #print ('sam --> '+line)
    sock.send(bytearray(line, 'ascii'))
    sock.send(b'\n')
    _line = _sam_readline(sock)
    #print ('sam <-- '+_line)
    return _sam_parse_reply(_line)
    
class Socket(object):
    """
    base of all sam socket objects
    """

    _log = logging.getLogger("i2p.socket.sam.simple.BaseSocket")

    def samState(*states):
        def f(func):
            def check_state(self, *args_inner, **kwargs_inner):
                if self._state in states:
                    return func(self, *args_inner, **kwargs_inner)
                else:
                    raise Exception("invalid socket state: {}".format(self._state))
            return check_state
        return f

    def samType(*types):
        def f(func):
            def check_type(self, *args, **kwargs):
                if self._type in types:
                    return func(self, *args, **kwargs)
                else:
                    raise Exception("invalid socket type: {}".format(self._type))
            return check_type
        return f

    def samConnect(func):
        def check_connect(self, *args, **kwargs):
            if self._samSocket is None:
                self._log.info("connecting to sam")
                # we are not connected
                samSocket = pysocket.socket()
                try:
                    samSocket.connect(self._samAddr)
                    self._samHandshake(samSocket)
                except pysocket.timeout:
                    self._log.warn("timeout connecting to SAM")
                except pysocket.error as ex:
                    self._log.warn("error connecting to SAM: {}".format(ex))
                else:
                    self._samSocket = samSocket
            return func(self, *args, **kwargs)
        return check_connect
    
    def __init__(self, samaddr, socketType):
        """
        :param samaddr: the socket address for sam
        """
        if samaddr:
            self._samAddr = samaddr
            self._samSocket = None
            self._data_sock = None
            self._state = State.Initial
            self._type = socketType
        else:
            raise ValueError("samaddr must not be None")

    
        
        
                
    def _samHandshake(self, sock):
        """
        handshake with sam via a socket.socket instance
        """
        repl = _sam_cmd(sock, 'HELLO VERSION MIN=3.0 MAX=3.2')
        if repl.opts['RESULT'] == 'OK':
            self._state = State.Established
        
        
    @samConnect
    @samState(State.Established)
    @samType(SAM.SOCK_STREAM)
    def connect(self, addr, **i2cpOptions):
        """
        connect to a remote endpoint
        :param addr: the remote endpoint to connect to, either a destination/name or a (destination/name, port) tuple
        :param keyfile: the file containing the private keys to use or None for transient
        :param nickname: the nickname to use for tunnels or None for random decided by sam
        :param i2cpOptions: additional i2cp options to pass into sam
        """
        self._log.info('connect')
        nickname = randnick(7)
        self.bind(None, nickname, **i2cpOptions)
        if isinstance(addr, tuple):
            addr = addr[0]
        dest = self.lookup(addr)
        # new socket
        self._data_sock = pysocket.socket()
        self._data_sock.connect(self._samAddr)
        # say hello
        repl = _sam_cmd(self._data_sock, 'HELLO VERSION MIN=3.0 MAX=3.2')
        # send connect
        cmd = 'STREAM CONNECT ID={} DESTINATION={} SILENT=false'.format(nickname, dest)
        if repl.opts["RESULT"] == "OK":
            repl = _sam_cmd(self._data_sock, cmd)
            self._state = State.Running
        else:
            self._state = State.Error
        
    @samConnect
    @samState(State.Established)
    @samType(SAM.SOCK_STREAM, SAM.SOCK_DGRAM)
    def bind(self, keyfile, nickname=None, **i2cpOptions):
        """
        bind to an address
        :param keyfile: the file containing the private keys to use
        :param nickname: the nickname to use for tunnels or None for random decided by sam
        :param i2cpOptions: additional i2cp options to pass into sam
        """
        self._state = State.Connecting
        self._log.info('bind')
        if self._type == SAM.SOCK_STREAM:
            style = "STREAM"
        elif self._type == SAM.SOCK_DGRAM:
            style = "DGRAM"
        else:
            style = "RAW"
            
        self._keys = 'TRANSIENT'
        if keyfile and os.path.exists(keyfile):
            with open(keyfile) as f:
                data = f.read()
                self._keys = data.strip()
        cmd = 'SESSION CREATE STYLE={} DESTINATION={} ID={}'.format(style, self._keys, nickname)

        for opt in i2cpOptions:
            cmd += " {}={}".format(opt, i2cpOptions[opt])

        repl = _sam_cmd(self._samSocket, cmd)

        if repl.opts['RESULT'] == 'OK':
            self._keys = repl.opts['DESTINATION']
            if keyfile:
                with open(keyfile, 'w') as f:
                    f.write(self._keys)
            self._nick = nickname
            self.dest = self.lookup('ME')
            if self.dest:
                self._state = State.Ready
            else:
                self._state = State.Error
        else:
            self._state = State.Error

    @samState(State.Ready)
    @samType(SAM.SOCK_STREAM)
    def accept(self):
        cmd = 'STREAM ACCEPT ID={} SILENT=false'.format(self._nick)
        sock = pysocket.socket()
        sock.connect(self._samAddr)
        # say hello
        repl = _sam_cmd(sock, 'HELLO VERSION MIN=3.0 MAX=3.2')
        # send command
        repl = _sam_cmd(sock, cmd)
        if repl.opts['RESULT'] == 'OK':
            dest = _sam_readline(sock)
            return sock, dest
        else:
            return None, None
            
    @samState(State.Running)
    @samType(SAM.SOCK_STREAM)
    def send(self, data, flags=0):
        """
        send to remote endpoint we are connected to
        :param data: bytearray of data
        :return count:
        """
        return self._data_sock.send(data, flags)
        
    @samState(State.Running)
    @samType(SAM.SOCK_STREAM)
    def recv(self, buffersize, flags=0):
        """
        recv bytes from endpoint we are connected to
        :param buffersize: number of bytes
        :return bytearry containing <= n bytes:
        """
        return self._data_sock.recv(buffersize, flags)

    @samState(State.Running)
    @samType(SAM.SOCK_DGRAM, SAM.SOCK_RAW)
    def sendto(self, data, flags=0, *address):
        """
        send to remote endopoint udp style
        :param buff: bytearray
        :return count:
        """

    @samState(State.Running)
    @samType(SAM.SOCK_DGRAM, SAM.SOCK_RAW)
    def recvfrom(self, buffersize, flags=0):
        """
        recv bytes from a remote sender
        :param buffersize: number of bytes to recv max
        :return (data, addressInfo):
        """

    @samState(State.Running)
    def shutdown(self, flag):
        """
        shutdown sending/recving
        :param flag: 
        """

    @samState(State.Running, State.Established, State.Ready)
    def close(self):
        """
        close the connection
        """
        self._samSocket.close()
        
        
    @samState(State.Established, State.Running, State.Ready, State.Connecting)
    def lookup(self, name):
        """
        look up a name
        :param name: a name or b32 address
        :returns a b64 destination string:
        """
        repl = _sam_cmd(self._samSocket, "NAMING LOOKUP NAME={}".format(name))
        if 'VALUE' in repl.opts:
            return repl.opts['VALUE']
        
