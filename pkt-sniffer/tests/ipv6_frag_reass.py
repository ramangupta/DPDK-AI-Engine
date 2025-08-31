#!/usr/bin/env python3
"""
IPv6 Fragmentation / Reassembly Test Harness
Run: python3 tests/ipv6_frag_reass.py
"""

from scapy.all import *
from scapy.layers.inet6 import IPv6ExtHdrFragment
from scapy.layers.l2 import Ether
import subprocess

# ---------------- L2/L3 constants ----------------
SRC_MAC = "d4:d8:53:5d:ab:d8"
DST_MAC = "ff:ff:ff:ff:ff:ff"

SRC = "2001:db8::1"
DST = "2001:db8::2"

# -----------------------------------------------------------
# Helper: use Scapy's fragment6 (keeps first fragment having upper header)
# -----------------------------------------------------------
def make_frags6(payload_len, frag_size, ident, sport=1111, dport=2222):
    """Return a list of IPv6 fragments (mf set until last). Uses UDP as UL proto."""
    pkt = IPv6(src=SRC, dst=DST) / UDP(sport=sport, dport=dport) / Raw(b"A" * payload_len)
    # scapy.fragment6(packet, fragSize) returns list of fragments
    frags = fragment6(pkt, fragSize=frag_size)
    # ensure frag id matches our requested ident (scapy auto-generates id)
    # replace id field in all fragments if ident was provided
    for f in frags:
        if IPv6ExtHdrFragment in f:
            f[IPv6ExtHdrFragment].id = ident
    return frags

# -----------------------------------------------------------
# Build test cases (robust sizes so we can pick specific fragments)
# -----------------------------------------------------------
pkts = []

# 1) Normal in-order fragments (1800 split into 3x600)
frags = make_frags6(1800, 600, 1000)
print(f"[DEBUG] In-order: got {len(frags)} fragments")
pkts.extend(frags)

# 2) Out-of-order delivery (1600 split into 4x400)
frags = make_frags6(1600, 400, 1001)
print(f"[DEBUG] Out-of-order: got {len(frags)} fragments")
# shuffle order (2,0,1,3)
if len(frags) >= 4:
    pkts.extend([frags[2], frags[0], frags[1], frags[3]])
else:
    pkts.extend(frags)

# 3) Missing fragment (hole) → intentionally drop middle fragment
frags = make_frags6(1600, 400, 1003)
print(f"[DEBUG] Missing: got {len(frags)} fragments")
if len(frags) >= 4:
    pkts.extend([frags[0], frags[2], frags[3]])  # skip frag[1]
else:
    pkts.extend(frags)

# 4) Small last fragment (ensures last frag shorter)
frags = make_frags6(1600, 500, 1002)
print(f"[DEBUG] Small-last: got {len(frags)} fragments")
pkts.extend(frags)  # include all fragments (including small last)

# 5) Duplicate last fragment
frags = make_frags6(1600, 500, 1004)
print(f"[DEBUG] Dup-last: got {len(frags)} fragments")
if frags:
    pkts.extend(frags + [frags[-1]])  # duplicate last
else:
    pkts.extend(frags)

# 6) Larger payload stress (2000 split into ~600)
frags = make_frags6(2000, 600, 1005)
print(f"[DEBUG] Large payload: got {len(frags)} fragments")
if len(frags) >= 4:
    pkts.extend([frags[1], frags[0], frags[2], frags[3]])
else:
    pkts.extend(frags)

# -----------------------------------------------------------
# Wrap fragments in Ethernet frames (important)
# -----------------------------------------------------------
frames = [ Ether(src=SRC_MAC, dst=DST_MAC) / f for f in pkts ]

pcap_name = "frags6.pcap"
wrpcap(pcap_name, frames)
print(f"[DEBUG] Wrote {len(frames)} Ethernet/IPv6 fragments to {pcap_name}")

# -----------------------------------------------------------
# Run pkt-sniffer reading the PCAP
# -----------------------------------------------------------
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

# -----------------------------------------------------------
# Define test cases for reporting
# -----------------------------------------------------------
tests_def = [
    ("In-order",       "id=1000", True),   # should reassemble
    ("Out-of-order",   "id=1001", True),   # should reassemble
    ("Missing",        "id=1003", False),  # should NOT reassemble
    ("Small-last",     "id=1002", True),   # should reassemble
    ("Dup-last",       "id=1004", True),   # should reassemble
    ("Large payload",  "id=1005", True),   # should reassemble
]

# after proc.wait()
print("\n===== IPv6 Fragmentation Reassembly Report =====")
for name, frag_id_str, expect_ok in tests_def:
    # look for reassembly success marker
    reassembled = any(frag_id_str in l and "IPv6 reassembled" in l for l in lines)
    flushed     = any(frag_id_str in l and "Flushing incomplete" in l for l in lines)
    ok = (expect_ok and reassembled and not flushed) or (not expect_ok and flushed and not reassembled)
    status = "PASS" if ok else "FAIL"
    print(f"{name:12s}: expected={'OK' if expect_ok else 'FAIL'} got={'OK' if reassembled else 'FAIL'} → {status}")
