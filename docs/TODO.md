todo_md = """# TODO List – Packet Sniffer Project

## ✅ Completed
- [x] Per-protocol stats with bandwidth calculation
- [x] Flow-based stats (pkts/bytes/duration/throughput)
- [x] Flow expiration mechanism (shrinking/growing table)
- [x] Time abstraction (`now_tsc` for DPDK/PCAP)

## 🔄 In Progress
- [ ] Track packet drops, errors, malformed packets (#35)

## 🚀 Backlog (Future Enhancements)
1. Bidirectional flow merging (`A↔B` shown as one entry)
2. Flow counters: active flows, new flows per interval, expired flows
3. Sorting & limiting flow output (e.g., top N by pkts/bytes/throughput)
4. Export hooks: JSON/CSV output for Grafana/ELK
5. DNS/HTTP/TLS session enrichment (decode details into flows)
6. IPv6 extension header support in flow classification
7. Configurable timeouts for flows (TCP/UDP/ICMP different)
8. Interactive CLI options (sort by, filter by proto/ip/port)
9. Integration with PCAP writer (optionally dump matching flows)
10. Unit tests for flow table insert/expire/lookup logic
"""

