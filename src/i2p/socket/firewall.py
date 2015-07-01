
__doc__ = """
i2p socket library's firewall rules
implements a base set firewall rules for i2p endpoints
"""

class FirewallRule(object):
    """
    base firewall rule
    """

    def should_drop(self, dest, srcport, dstport):
        """
        :return: true if we want to drop packets from remote destination to our src port from their dst port
        """
        return True

    def allow_ib(self):
        """
        :return: true if we allow inbound connections
        """
        return False

class BlockRawRule(FirewallRule):

    def should_drop(self, dest, srcport, dstport):
        """
        drop all non replyable messages
        """
        return dest is None

class BlockInboundRule(FirewallRule):

    def should_drop(self, dest, srcport, dstport):
        return False

DefaultRule = BlockRawRule
