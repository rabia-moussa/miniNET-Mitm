import fcntl
import socket
import struct
import time

from constans import *

# ----------------------------- small helpers -------------------------------
def mac_bytes(mac: str) -> bytes:
    """'dc:0e:a1:35:99:b9' -> b'\\xdc\\x0e...'"""
    return bytes(int(part, 16) for part in mac.replace("-", ":").split(":"))


def mac_str(raw: bytes) -> str:
    return ":".join("%02x" % b for b in raw)


def ip_bytes(ip: str) -> bytes:
    return socket.inet_aton(ip)


def iface_mac(ifname: str) -> str:
    """Read the hardware address of an interface (SIOCGIFHWADDR)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        info = fcntl.ioctl(
            s.fileno(), 0x8927, struct.pack("256s", ifname[:15].encode())
        )
    return mac_str(info[18:24])


def iface_ip(ifname: str) -> str:
    """Read the IPv4 address of an interface (SIOCGIFADDR)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        info = fcntl.ioctl(
            s.fileno(), 0x8915, struct.pack("256s", ifname[:15].encode())
        )
    return socket.inet_ntoa(info[20:24])


def iface_netmask(ifname: str) -> str:
    """Read the IPv4 netmask of an interface (SIOCGIFNETMASK)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            info = fcntl.ioctl(
                s.fileno(), 0x891b, struct.pack("256s", ifname[:15].encode())
            )
        return socket.inet_ntoa(info[20:24])
    except OSError:
        return "255.255.255.0"


def same_subnet(ip_a: str, ip_b: str, netmask: str) -> bool:
    a = struct.unpack("!I", socket.inet_aton(ip_a))[0]
    b = struct.unpack("!I", socket.inet_aton(ip_b))[0]
    m = struct.unpack("!I", socket.inet_aton(netmask))[0]
    return (a & m) == (b & m)


def local_ipv4_addresses() -> set:
    """Every IPv4 address of this machine, so a local server is recognised
    even when it binds to a secondary address or another interface."""
    ips = {"127.0.0.1"}
    for _, name in socket.if_nameindex():
        try:
            ips.add(iface_ip(name))
        except OSError:
            pass
    return ips


# --------------------------- frame construction ----------------------------
def build_arp(op: int, sha: bytes, spa: bytes, tha: bytes, tpa: bytes) -> bytes:
    """
    Ethernet(14) + ARP(28) frame.

        Ethernet: dst(6) src(6) ethertype(2)=0x0806
        ARP     : htype(2)=1 ptype(2)=0x0800 hlen(1)=6 plen(1)=4
                  oper(2) sha(6) spa(4) tha(6) tpa(4)
    """
    ethernet = tha + sha + struct.pack("!H", ETH_P_ARP)
    arp = struct.pack("!HHBBH", 1, ETH_P_IP, 6, 4, op)
    arp += sha + spa + tha + tpa
    return ethernet + arp


def open_arp_socket(ifname: str) -> socket.socket:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                      socket.htons(ETH_P_ARP))
    s.bind((ifname, 0))
    return s


def resolve_mac(ifname: str, ip: str, timeout: float = 3.0) -> str:
    """Find the MAC that currently answers for `ip`, using a hand-built ARP."""
    me_mac = mac_bytes(iface_mac(ifname))
    me_ip = ip_bytes(iface_ip(ifname))
    request = build_arp(ARP_REQUEST, me_mac, me_ip, BROADCAST, ip_bytes(ip))

    sock = open_arp_socket(ifname)
    sock.settimeout(0.2)
    try:
        sock.send(request)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                frame, _ = sock.recvfrom(2048)
            except socket.timeout:
                sock.send(request)
                continue
            if len(frame) < 42:
                continue
            oper = struct.unpack("!H", frame[20:22])[0]
            sender_ip = frame[28:32]
            if oper == ARP_REPLY and sender_ip == ip_bytes(ip):
                return mac_str(frame[22:28])
    finally:
        sock.close()
    raise RuntimeError("Could not resolve MAC for %s" % ip)


