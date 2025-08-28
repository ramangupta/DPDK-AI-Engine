#!/usr/bin/env python3

# USAGE
# Run the harness: python3 frag_reassembly_test_harness.py
# Save full logs : python3 frag_reassembly_test_harness.py | tee logs.txt
# Only Summary table : python3 frag_reassembly_test_harness.py | sed -n '/^=== Test Results ===/,$p'
# Inspect the pcap : tcpdump -nn -vvv -r frags.pcap

from scapy.all import *
import subprocess, re, sys

# -------- L2/L3 constants --------
SRC_MAC = "d4:d8:53:5d:ab:d8"
DST_MAC = "ff:ff:ff:ff:ff:ff"
ETH_TYPE_IPV4 = 0x0800

SRC = "10.0.0.1"
DST = "10.0.0.2"
PROTO = 17  # UDP

# ----------------------------
# Step 1: Generate test cases
# ----------------------------
pkts = []

def udp_pkt(payload_size, ident, offset=0, mf=1):
    data = b"X" * payload_size
    ip = IP(src=SRC, dst=DST, id=ident, proto=PROTO, flags=mf, frag=offset//8)
    udp = UDP(sport=1111, dport=2222)
    return ip/udp/data

def make_udp_frags(ident, payload_len, fragsize):
    data = b"B" * payload_len
    udp = UDP(sport=1111, dport=2222)
    udp_len = 8
    udp_header = raw(udp)
    udp_payload = udp_header + data

    pkts = []
    offset = 0
    while offset < len(udp_payload):
        frag_payload = udp_payload[offset:offset+fragsize]
        mf = 1 if (offset + fragsize) < len(udp_payload) else 0
        ip = IP(src=SRC, dst=DST, id=ident, proto=PROTO, flags=mf,
                frag=offset//8) / Raw(frag_payload)
        pkts.append(ip)
        offset += fragsize
    return pkts

# 1) Happy-path
payload = b"A"*2000
base = IP(src=SRC,dst=DST,id=1000,proto=PROTO)/UDP(sport=1111,dport=2222)/payload
pkts.extend(fragment(base, fragsize=1480))

# 2) Out-of-order
frags = make_udp_frags(1001, 3000, 1000)
pkts.extend([frags[2], frags[0], frags[1], frags[3]])

# 3) Overlap
pkts.extend([
    udp_pkt(1480, ident=1002, offset=0,    mf=1),
    udp_pkt( 600, ident=1002, offset=1400, mf=0),
])

# 4) Missing fragment (hole)
base = IP(src=SRC,dst=DST,id=1003,proto=PROTO)/UDP()/b"C"*4000
fr = fragment(base, fragsize=1000)
pkts.extend([fr[0], fr[2], fr[3]])

# 5a) Small last frag
frags = make_udp_frags(1004, 2021, 1000)
pkts.extend(frags)

# 5b) Duplicate last frag
pkts.extend([
    udp_pkt(500, ident=1005, offset=0,   mf=1),
    udp_pkt(500, ident=1005, offset=500, mf=0),
    udp_pkt(400, ident=1005, offset=500, mf=0),
])

# 6) Malformed
pkts.append(IP(src=SRC,dst=DST,id=1006,proto=PROTO)/Raw(b"E"*20))

# 7) Stress: many tiny frags
base = IP(src=SRC,dst=DST,id=1007,proto=PROTO)/UDP()/b"F"*600
pkts.extend(fragment(base, fragsize=8))

# ---- Wrap every L3 packet with Ethernet ----
frames = [Ether(src=SRC_MAC, dst=DST_MAC, type=ETH_TYPE_IPV4)/p for p in pkts]

pcap_name = "frags.pcap"
wrpcap(pcap_name, frames)
print(f"Generated {pcap_name} with {len(frames)} Ethernet/IPv4 frames")

# ----------------------------
# Step 2: Expected outcomes
# ----------------------------
expected = {
    1000: "reassembled",
    1001: "reassembled",
    1002: "reassembled",
    1003: "drop",
    1004: "reassembled",
    1005: "reassembled",
    1006: "drop",
    1007: "reassembled",
}

# ----------------------------
# Step 3: Run pkt-sniffer
# ----------------------------
proc = subprocess.Popen(
    ["./build/pkt-sniffer", "--pcap", pcap_name],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    errors="replace",
    bufsize=1
)

lines = []
for line in proc.stdout:
    print(line, end="")
    lines.append(line.strip())

proc.wait()

# ----------------------------
# Step 4: Analyze results
# ----------------------------
results = {}
for line in lines:
    m = re.search(r"IPv4 (fragment buffered|reassembled) \(id=(\d+)", line)
    if m:
        action, ident = m.groups()
        ident = int(ident)
        if "reassembled" in action:
            results[ident] = "reassembled"
        # ⚠️ do not store "fragmented" here!
        continue

    m = re.search(r"\[frag\] id=(\d+) complete!", line)
    if m:
        ident = int(m.group(1))
        results[ident] = "reassembled"
        continue

# ----------------------------
# Step 5: Check expectations
# ----------------------------
print("\n=== Test Results ===")
for ident, exp in expected.items():
    got = results.get(ident, "drop")
    status = "PASS" if got == exp else "FAIL"
    print(f"ID={ident} expected={exp} got={got} => {status}")
