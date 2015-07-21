__doc__ = """
asyncio interface for tcp over i2p
this is wrapped by i2p.socket
"""

def open_connection(host, port, loop=None, limit=None):
    """
    asyncio.open_connection lookalike
    :return: asyncio.StreamReader, asyncio.StreamWriter lookalikes
    """
    
