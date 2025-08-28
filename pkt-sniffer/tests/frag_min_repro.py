#!/usr/bin/env python3
from scapy.all import *
import subprocess
import sys

# --- L2/L3 constants ---
SRC_MAC = "d4:d8:53:5d:ab:d8"
DST_MAC = "ff:ff:ff:ff:ff:ff"
ETH_TYPE_IPV4 = 0x0800

SRC = "10.0.0.1"
DST = "10.0.0.2"
PROTO = 17  # UDP

pkts = []

# --- ID=1001: Out-of-order fragments (should reassemble) ---
base_1001 = IP(src=SRC, dst=DST, id=1001, proto=PROTO)/UDP(sport=1111, dport=2222)/("B"*3000)
fr_1001 = fragment(base_1001, fragsize=1000)
# Reorder deliberately
pkts.extend([fr_1001[2], fr_1001[0], fr_1001[1], fr_1001[3]])

# --- ID=1004: Small last fragment not 8-byte aligned (should reassemble) ---
base_1004 = IP(src=SRC, dst=DST, id=1004, proto=PROTO)/UDP(sport=1111, dport=2222)/("D"*2021)
fr_1004 = fragment(base_1004, fragsize=1000)
pkts.extend(fr_1004)

# --- Wrap with Ethernet (explicit EtherType = IPv4) ---
frames = [Ether(src=SRC_MAC, dst=DST_MAC, type=ETH_TYPE_IPV4)/p for p in pkts]

pcap_name = "frags_min.pcap"
wrpcap(pcap_name, frames)
print(f"Generated {pcap_name} with {len(frames)} frames (IDs: 1001, 1004)")

# --- Run sniffer; stream logs (no capture) ---
cmd = ["./build/pkt-sniffer", "--pcap", pcap_name]
# If you want to pass extra args (e.g., --debug), append them on the CLI:
#   python3 frag_min_repro.py --debug
cmd += sys.argv[1:]

print("Running:", " ".join(cmd))
ret = subprocess.run(cmd).returncode
print(f"pkt-sniffer exited with code {ret}")
