# pkt-sniffer

A lightweight packet sniffer with pluggable backends:  
- **AF_PACKET** (default, works out of the box on Linux)  
- **DPDK** (for high-performance packet capture, requires DPDK setup)  

The sniffer parses **Ethernet, IPv4/IPv6, ICMP, UDP/TCP, and DNS**.

---

## 🔧 Build

### Prerequisites
- GCC / Clang
- [Meson](https://mesonbuild.com/) + Ninja
- (Optional) DPDK installed and configured

### Clone and build (default = AF_PACKET):
```bash
git clone https://github.com/ramangupta/dpdk-stock-ai.git
cd dpdk-stock-ai/pkt-sniffer
meson setup build -Dcapture_backend=afp
ninja -C build

Build with DPDK backend:

meson setup build -Dcapture_backend=dpdk
ninja -C build

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

⚡ Roadmap

Add more protocol parsers (ARP, HTTP, FIX for stock feeds 📈)

Performance benchmarking (AF_PACKET vs DPDK)

Integration with AI models for traffic classification

📜 License

MIT License

