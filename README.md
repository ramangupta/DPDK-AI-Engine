# 📡 dpdk-stock-ai

A next-generation **packet sniffer + analytics engine** built with **DPDK**, designed for ultra-low-latency environments like **stock trading, market data analysis, and real-time monitoring**.  
It combines **core packet capture**, **advanced analytics**, and **AI/ML-driven insights**.

---

## ✨ Vision
To build a **blazing fast, AI-powered packet engine** that can:
- Capture packets at line-rate using DPDK
- Provide deep protocol visibility (IPv4/IPv6, TCP/UDP, ICMP, DNS, and beyond)
- Detect anomalies, track top talkers, and compute real-time network stats
- Integrate with **trading systems** and **data pipelines** for actionable intelligence

---

## 🔑 Features (Work in Progress)

### Core
- ✅ Packet parsing (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, DNS)
- ✅ Realtime stats (pps, bps, per-protocol counts)
- ✅ Top talkers (per source/destination IP)
- ⬜ Fragmentation & reassembly
- ⬜ CLI options & filters

### Advanced
- ⬜ Latency & jitter analysis
- ⬜ Flow correlation (per connection tracking)
- ⬜ Deep protocol inspection (HTTP, FIX, etc.)
- ⬜ Encrypted traffic metadata analysis

### AI/ML
- ⬜ Traffic anomaly detection
- ⬜ Market signal extraction from packet patterns
- ⬜ Predictive load balancing & trading signals

### Integrations
- ⬜ Grafana dashboards (Prometheus metrics export)
- ⬜ Kafka / ZeroMQ streaming
- ⬜ PCAP replay & offline analysis

---

## 📅 Roadmap
See full roadmap here: [docs/ROADMAP.md](docs/ROADMAP.md)

---

## ⚡ Quick Start

```bash
# clone repo
git clone https://github.com/ramangupta/dpdk-stock-ai.git
cd dpdk-stock-ai

# build
meson build
ninja -C build

# run (example)
sudo ./build/pkt-sniffer -l 0-1 -n 4 -- -i eth0


🚀 Run
AF_PACKET

Capture on a given interface (example: wlo1):
sudo ./build/pkt-sniffer wlo1

DPDK

Run with a virtual device bound to AF_PACKET:
sudo ./build/pkt-sniffer --no-pci --vdev=net_af_packet0,iface=wlo1

📦 Features

Captures packets using AF_PACKET or DPDK

Decodes:

  - Ethernet
  - IPv4 / IPv6
  - TCP / UDP
  - ICMPv4 / ICMPv6
  - DNS

Human-readable packet dumps

📂 Project Structure

pkt-sniffer/
├── capture_afp.c      # AF_PACKET capture backend
├── capture_dpdk.c     # DPDK capture backend
├── capture.h
├── main.c             # Entry point
├── parse_eth.c/h      # Ethernet parsing
├── parse_ipv4.c/h     # IPv4 parsing
├── parse_ipv6.c/h     # IPv6 parsing
├── parse_l4.c/h       # TCP/UDP/ICMP parsing
├── parse_dns.c/h      # DNS parser
├── utils.c/h          # Helpers
├── meson.build
└── meson_options.txt

📜 License

MIT License

