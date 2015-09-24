#
# i2p.tun -- ipv6 compatability layer for i2p
#
from future.builtins import *

# net interface
from i2p.tun import tundev
# link protocol
from i2p.tun import protocol
from i2p.tun import link
# packet switch
from i2p.tun import switch

import trollius as asyncio
from trollius import Return, From

import collections
import logging
import struct
import threading

from i2p.tun import config

def main():

    cfg = config.load()

    if cfg["remote"] == "":
        print("please set the remote destination in i2tun.json")
        return
    
    log = logging.getLogger("i2p.tun")

    if 'debug' in cfg:
        lvl = logging.DEBUG
    else:
        lvl = logging.WARN

    logging.basicConfig(level=lvl)

    iface_cfg = cfg["interface"]
    tun = tundev.opentun(iface_cfg)
    
    proto = protocol.Clumping(iface_cfg['mtu'])
    sw = switch.Switch(tun, cfg['remote'])
    # make handler
    print('creating link...')
    handler = link.Handler(cfg["remote"], tun, sw, proto, cfg["keyfile"], cfg["sam"])
    print('our address is {}'.format(handler.dest.base32()))
    tun.up()
    print('interface ready')
    try:
        handler.loop.run_forever()
    finally:
        handler.loop.close()
                           

if __name__ == "__main__":
    main()
