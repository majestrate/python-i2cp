#
# i2p.socket default settings
#

import os

# defaults
i2cp_host = os.getenv('I2P_SOCKET_I2CP_HOST', '127.0.0.1')
i2cp_port = os.getenv('I2P_SOCKET_I2CP_PORT' , '7654')
keyfile = os.getenv('I2P_SOCKET_KEYFILE', "i2p.socket.key")
hops = os.getenv('I2P_SOCKET_HOPS', '3')
quant = os.getenv('I2P_SOCKET_TUNNELS', '3')
backup = os.getenv('I2P_SOCKET_BACKUPS', '1')
variance = os.getenv('I2P_SOCKET_VARIANCE', '0')
nick = os.getenv('I2P_SOCKET_TUNNEL_NAME', None)

def i2cp_options():
    """
    get default i2cp options
    """
    _opts = {
        'inbound.length' : hops,
        'outbound.length' : hops,
        'inbound.quantity' : quant,
        'outbound.quantity' : quant,
        'inbound.backupQuantity' :  backup,
        'outbound.backupQuantity' : backup,
        'inbound.lengthVariance' : variance,
        'outbound.lengthVariance' : variance,
    }
    if nick:
        _opts['inbound.nickname'] = nick
        _opts['outbound.nickname'] = nick 
    return _opts

def streaming_options():
    """
    get the default streaming options
    """
    _opts = {
        'i2p.streaming.connectTimeout' : '30000',
        'i2p.streaming.maxMessageSize' : '1730',
        'i2p.streaming.maxResends' : '8',
        'i2p.streaming.initialResendDelay' : '1000',
        'i2p.streaming.initialRTO' : '9000',
        'i2p.streaming.initialWindowSize' : '6',
        'i2p.streaming.maxWindowSize' : '128',
        'i2p.streaming.maxMessageSize' : '1730',
        'i2p.streaming.connectDelay' : '1000',
        'i2p.streaming.inactivityTimeout': '90000',
    }
    return _opts
