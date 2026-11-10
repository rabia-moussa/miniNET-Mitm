import os

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

