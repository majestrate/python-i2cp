#
# tun interface implementation for i2p.tun
#

try:
    import pytun
except ImportError:
    print("no module pytun, i2p.tun won't work without it")
    print("pip install python-pytun")
    raise

def opentun(cfg, tap=False):
    ifname  = cfg["ifname"]
    flag = pytun.IFF_TUN
    if tap:
        flag = pytun.IFF_TAP
    dev = pytun.TunTapDevice(ifname, flags=flag)
    dev.addr = cfg["addr"]
    dev.dstaddr = cfg["dstaddr"]
    dev.mtu = cfg["mtu"]
    dev.netmask = cfg["netmask"]
    return dev
