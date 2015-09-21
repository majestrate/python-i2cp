
class Switch:
    """
    link layer frame handler
    """

    def __init__(self, tundev):
        self._tundev = tundev

    def tunIfaceUp(self):
        """
        put the tun interface up
        """
        self._tundev.up()

    def setTunAddr(self, localaddr, remoteaddr, netmask):
        """
        set our local tun interface's addresses and netmasks
        """
        self._tundev.addr = localaddr
        self._tundev.dstaddr = remoteaddr
        self._tundev.netmask = netmask
        
    def destForIP(self, ip):
        """
        get the destination for this ip address
        :param ip: ip address to look for
        :return: None when not found or a desthash
        """
        if ip in self._addrs:
            return self._addrs[ip]
    
