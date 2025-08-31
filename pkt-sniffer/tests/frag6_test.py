#!/usr/bin/env python3
"""
IPv6 Fragmentation / Reassembly Test Harness
Run: python3 tests/frag6_test.py
"""

from scapy.all import *
from scapy.layers.inet6 import IPv6ExtHdrFragment
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP
import subprocess
import random

# ---------------- L2/L3 constants ----------------
SRC_MAC = "d4:d8:53:5d:ab:d8"
DST_MAC = "ff:ff:ff:ff:ff:ff"
SRC = "2001:db8::1"
DST = "2001:db8::2"

# -----------------------------------------------------------
# Helper: fragment IPv6 packet and force frag IDs
# -----------------------------------------------------------
def make_frags6(payload_len, frag_size, ident, sport=1111, dport=2222):
    pkt = IPv6(src=SRC, dst=DST) / UDP(sport=sport, dport=dport) / Raw(b"A" * payload_len)
    frags = fragment6(pkt, fragSize=frag_size)
    for f in frags:
        if IPv6ExtHdrFragment in f:
            f[IPv6ExtHdrFragment].id = ident
    return frags

# -----------------------------------------------------------
# Build test cases
# -----------------------------------------------------------
pkts = []

# 1) Normal in-order fragments
frags = make_frags6(1800, 600, 1000)
pkts.extend(frags)

# 2) Out-of-order
frags = make_frags6(1600, 400, 1001)
random.shuffle(frags)
pkts.extend(frags)

# 3) Missing fragment (skip middle)
frags = make_frags6(1600, 400, 1003)
if len(frags) >= 4:
    pkts.extend([frags[0], frags[2], frags[3]])
else:
    pkts.extend(frags)

# 4) Small last fragment
frags = make_frags6(1600, 500, 1002)
pkts.extend(frags)

# 5) Duplicate last fragment
frags = make_frags6(1600, 500, 1004)
if frags:
    pkts.extend(frags + [frags[-1]])
else:
    pkts.extend(frags)

# 6) Large payload stress
frags = make_frags6(2000, 600, 1005)
if len(frags) >= 4:
    pkts.extend([frags[1], frags[0], frags[2], frags[3]])
else:
    pkts.extend(frags)

# -----------------------------------------------------------
# Wrap in Ethernet frames
# -----------------------------------------------------------
frames = [Ether(src=SRC_MAC, dst=DST_MAC) / f for f in pkts]
pcap_name = "frags6.pcap"
wrpcap(pcap_name, frames)
print(f"[DEBUG] Wrote {len(frames)} fragments to {pcap_name}")

# -----------------------------------------------------------
# Run sniffer (original working invocation)
# -----------------------------------------------------------
out_pcap = "sniffer_out.pcap"
lines = []
proc = subprocess.Popen(
    ["./build/pkt-sniffer", "--pcap", pcap_name, "-w", out_pcap],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)
for line in proc.stdout:
    print(line, end="")
    lines.append(line.strip())
proc.wait()

# -----------------------------------------------------------
# Expected payloads
# -----------------------------------------------------------
expected_payloads = {
    1000: b"A" * 1800,
    1001: b"A" * 1600,
    1003: b"A" * 1600,  # missing
    1002: b"A" * 1600,
    1004: b"A" * 1600,
    1005: b"A" * 2000,
}

# -----------------------------------------------------------
# Read reassembled packets
# -----------------------------------------------------------
reassembled_pcaps = rdpcap(out_pcap)
id_to_payload = {}
for pkt in reassembled_pcaps:
    if IPv6 in pkt and UDP in pkt:
        frag_hdr = pkt.getlayer(IPv6ExtHdrFragment)
        frag_id = frag_hdr.id if frag_hdr else None
        payload = bytes(pkt[UDP].payload)
        # key by frag ID if present, else by length
        id_to_payload[frag_id or len(payload)] = payload

# -----------------------------------------------------------
# Test definitions
# -----------------------------------------------------------
tests_def = [
    ("In-order",      1000, True),
    ("Out-of-order",  1001, True),
    ("Missing",       1003, False),
    ("Small-last",    1002, True),
    ("Dup-last",      1004, True),
    ("Large payload", 1005, True),
]

# -----------------------------------------------------------
# Final report
# -----------------------------------------------------------
print("\n===== IPv6 Fragmentation Reassembly Report =====")
for name, frag_id, expect_ok in tests_def:
    expected = expected_payloads[frag_id]
    # check if reassembled
    reassembled = any(f"frag_id={frag_id}" in l and "IPv6 reassembled" in l for l in lines)
    flushed     = any(f"frag_id={frag_id}" in l and "Flushing incomplete" in l for l in lines)
    payload_ok = any(payload == expected for payload in id_to_payload.values())

    ok = (expect_ok and reassembled and not flushed and payload_ok) or \
         (not expect_ok and flushed and not reassembled)

    status = "PASS" if ok else "FAIL"
    got_str = "OK" if payload_ok else "FAIL"
    print(f"{name:12s}: expected={'OK' if expect_ok else 'FAIL'} got={got_str} → {status}")
