# TEST REPORT — Top Talkers Feature

## Overview
This document validates the **Top Talkers per-flow reporting** feature  
(User Story #7: Add Top Talkers with source/destination + ports).

The feature shows the top N flows (default 5) by packets or bytes,  
including protocol, ports, and for ARP the MAC addresses.

---

## Test Environment
- Host: Ubuntu 22.04 (x86_64)
- Tool: `pkt-sniffer` (custom build, v0.1)
- Capture: Live traffic on `wlo1`
- Interval: Report every 5s
- Output mode: Packets (default)

---

## Test Cases

### 1. IPv4 TCP Flow
**Command:**
```bash
sudo ./build/pkt-sniffer -p tcp

=== Top Talkers (last 5s, Sort Mode: Packets) ===
Flow                                                                        Proto  Pkts       Bytes     
172.66.0.227:443 -> 192.168.x.xxx:48438                                     TCP    4          483 B     
192.168.x.xxx:48438 -> 172.66.0.227:443                                     TCP    3          2.5 KB

Notes

 - Protocols now mapped via sniffer_proto.h
 - Sorting works by packets (default) or bytes (--sort bytes)
 - Output formatting aligned dynamically to longest flow string
 - Human-readable bytes (B / KB)

Verdict

✅ Feature works as expected.