
from .client import Connection
import logging
logging.basicConfig(level=logging.DEBUG)
c = Connection()
c.open()
opts = {
    'i2cp.fastReceive':'true'
}
c.start_session(opts)
c.run()
c.close()
    
