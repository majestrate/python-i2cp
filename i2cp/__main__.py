
from .client import Connection
import logging
logging.basicConfig(level=logging.INFO)
c = Connection()
c.open()
opts = {
    'inbound.quantity' : '16',
    'outbound.quantity' : '16',
    'inbound.nickname' : 'i2cpy',
    'i2cp.fastReceive':'true'
}
c.start_session(opts)
    
