
class Switch:
    """
    handler of packets
    """

    def __init__(self, tundev, iface_cfg=None):
        self._tundev = tundev
        self._rpc = rpc.Handler(self)
        

    def getOurIP(self):
        """
        return our ip address as string
        """
        return self._tundev.addr

    def isServer(self):
        """
        return true if we are operating in server mode
        """
        
    def registerIP(self, dest, ip):
        self._dests[ip] = dest
        
    def destForIP(self, ip):
        """
        get the destination for this ip address
        :param ip: ip address to look for
        :return: None when not found or a desthash
        """
        if ip in self._dests[ip]:
            return self._dests[ip]
    
