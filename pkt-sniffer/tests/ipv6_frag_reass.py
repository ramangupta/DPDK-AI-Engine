#!/usr/bin/env python3
"""
IPv6 Fragmentation / Reassembly Test Harness
Run: python3 ipv6_frag_reass.py
Inspect PCAP: tcpdump -nn -vvv -r frags6.pcap
"""

from scapy.all import *
import subprocess, re

# ---------------- L2/L3 constants ----------------
SRC_MAC = "d4:d8:53:5d:ab:d8"
DST_MAC = "ff:ff:ff:ff:ff:ff"

SRC = "2001:db8::1"
DST = "2001:db8::2"
PROTO = 17  # UDP

# ---------------------------- Helpers ----------------------------
def udp_pkt6(payload_size, ident, offset=0, mflag=1):
    """Generate a single IPv6/UDP packet fragment payload"""
    data = b"X" * payload_size
    udp = UDP(sport=1111, dport=2222)
    ip6 = IPv6(src=SRC, dst=DST, fl=0) / udp / Raw(load=data)
    return ip6

def make_udp_frags6(ident, payload_len, fragsize):
    data = b"B" * payload_len
    udp = UDP(sport=1111, dport=2222)
    pkt = IPv6(src=SRC, dst=DST) / udp / Raw(data)  
    frags = fragment6(pkt, fragSize=1000) # returns a list of IPv6 fragments
    return frags

# ---------------------------- Generate test cases ----------------------------
pkts = []

# 1) Happy-path large payload
payload = b"A"*2000
frags = fragment6(IPv6(src=SRC,dst=DST)/UDP(sport=1111,dport=2222)/Raw(payload), fragSize=1000)
pkts.extend(frags)

# 2) Out-of-order fragments
frags = make_udp_frags6(1001, 3000, 1000)
pkts.extend([frags[2], frags[0], frags[1], frags[3]])

# 3) Overlap
pkts.extend([
    udp_pkt6(1480, ident=1002, offset=0),
    udp_pkt6(600,  ident=1002, offset=1400),
])

# 4) Missing fragment (hole)
frags = make_udp_frags6(1003, 4000, 1000)
pkts.extend([frags[0], frags[2], frags[3]])

# 5) Small last fragment
frags = make_udp_frags6(1004, 2021, 1000)
pkts.extend(frags)

# 6) Duplicate last fragment
pkts.extend([
    udp_pkt6(500, ident=1005, offset=0),
    udp_pkt6(500, ident=1005, offset=500),
    udp_pkt6(400, ident=1005, offset=500),
])

# ---------------------------- Wrap in Ethernet ----------------------------
from scapy.layers.l2 import Ether

frames = [Ether(src=SRC_MAC, dst=DST_MAC)/f for f in pkts]

pcap_name = "frags6.pcap"
wrpcap(pcap_name, frames)
print(f"Generated {pcap_name} with {len(frames)} Ethernet/IPv6 frames")

# ---------------------------- Expected outcomes ----------------------------
expected = {
    1000: "reassembled",
    1001: "reassembled",
    1002: "reassembled",
    1003: "drop",
    1004: "reassembled",
    1005: "reassembled",
}

# ---------------------------- Run pkt-sniffer ----------------------------
proc = subprocess.Popen(
    ["./build/pkt-sniffer", "--pcap", pcap_name],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)

lines = []
for line in proc.stdout:
    print(line, end="")
    lines.append(line.strip())

proc.wait()

# ---------------------------- Analyze results ----------------------------
results = {}
for line in lines:
    m = re.search(r"IPv6 (fragment buffered|reassembled)", line)
    if m:
        action = m.group(1)
        # Extract ID if printed in your C harness logs
        id_match = re.search(r"id=(\d+)", line)
        if id_match:
            ident = int(id_match.group(1))
            if "reassembled" in action:
                results[ident] = "reassembled"
            continue
    # Alternatively, match your "[frag] id=..." log line
    m2 = re.search(r"\[frag\] id=(\d+) complete!", line)
    if m2:
        ident = int(m2.group(1))
        results[ident] = "reassembled"

# ---------------------------- Check expectations ----------------------------
print("\n=== Test Results ===")
for ident, exp in expected.items():
    got = results.get(ident, "drop")
    status = "PASS" if got == exp else "FAIL"
    print(f"ID={ident} expected={exp} got={got} => {status}")
