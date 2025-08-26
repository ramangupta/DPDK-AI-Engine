# DPDK Stock Market AI Project 🚀📈

This repository is a collection of experiments and prototypes combining **DPDK (Data Plane Development Kit)** with **AI-driven trading strategies**.  
The long-term mission: **build a high-performance stock market feed handler + AI engine** capable of handling real-time data at low latency.  

---

## 🧩 Current Mini Projects

### 1. Packet Sniffer (TAP)
- Uses DPDK virtual device (`net_tap`) to capture packets from a TAP interface.
- Demonstrates initialization of EAL, mbuf allocation, and packet RX loop.
- Prints Ethernet/IPv4 headers and hex dumps.

### 2. TAP ↔ NIC Bridge
- Bridges traffic between a TAP device and a physical NIC using DPDK.
- Useful for connecting real traffic into the DPDK pipeline while still monitoring/debugging via TAP.

### 3. IPv4 + UDP Parser
- Extends the sniffer to parse IPv4/UDP headers.
- First step towards parsing stock exchange feeds (e.g., multicast UDP).

---

## 📂 Repo Structure

- `pkt-sniffer/` → Custom packet sniffer using DPDK (entry project)  
- `examples/`
  - `dpdk-hello/` → Minimal DPDK Hello World example  
  - `port-info/` → Utility to display DPDK ports and NIC information

---

## ⚙️ Setup & Build

### Requirements
- Linux (tested on Ubuntu 22.04)
- [DPDK 21.11+](https://www.dpdk.org/)
- GCC or Clang
- `make`

### Example: Run Packet Sniffer
```bash
# Load TUN module
sudo modprobe tun

# Build
cd pkt-sniffer
make

# Run with TAP device
sudo ./build/pkt-sniffer --no-pci --vdev=net_tap0,iface=tap0

🛠️ Roadmap
 - Add stock feed multicast capture
 - Parse exchange protocol messages (ITCH, OUCH, etc.)
 - Build order book engine in DPDK
 - Connect AI/ML models for trading strategy simulation


🤝 Contributing

This repo starts as a personal learning journey, but contributions/ideas are welcome.
The goal is to grow it into a full open-source low-latency trading lab.

📜 License

MIT License – feel free to use, learn, and extend.
