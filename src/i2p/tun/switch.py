
class Switch:
    """
    link layer frame handler
    """

    def __init__(self, tundev, remote):
        self._tundev = tundev
        self._remote = remote

    def destForIP(self, ip):
        """
        get the destination for this ip address
        :param ip: ip address to look for
        :return: None when not found or a desthash
        right now this method returns the same value
        """
        return self._remote
    
