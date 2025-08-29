# pkt-sniffer – Usage Guide

`pkt-sniffer` supports **three capture backends**: `dpdk`, `afp` (AF_PACKET), and `pcap`.  
Only **one** backend is compiled in at a time, selected via **meson option**:

```bash
meson setup build -Dcapture_backend=<dpdk|afp|pcap>
ninja -C build

1. PCAP Mode (Offline)

Use this mode to replay traffic from .pcap files — e.g., for fragmentation/reassembly testing.

Build
meson setup build -Dcapture_backend=pcap
ninja -C build

Run
./build/pkt-sniffer --pcap tests/frags.pcap


2. AF_PACKET Mode (Live capture via Linux kernel)

Use this mode for Wi-Fi or non-DPDK NICs.
It uses the Linux AF_PACKET driver, so it works on standard laptops.

Build
meson setup build -Dcapture_backend=afp
ninja -C build

Run
sudo ./build/pkt-sniffer --no-pci -vdev=net_af_packet0,iface=<ifname>

3. DPDK Mode (High-performance NICs)

Use this mode for servers with DPDK-supported NICs (not Wi-Fi).
Provides high-speed zero-copy packet capture.

Build
meson setup build -Dcapture_backend=dpdk
ninja -C build

Run
sudo ./build/pkt-sniffer -l 0-1 -n 4 --vdev=net_pcap0,iface=eth0

Change eth0 to the name of your DPDK-bound NIC.
Check with dpdk-devbind.py -s.

Notes

You must rebuild if you want to switch backends:
meson setup build -Dcapture_backend=pcap --reconfigure

    - PCAP backend is recommended for testing (deterministic input).
    - AF_PACKET backend is recommended for Wi-Fi development / laptops.
    - DPDK backend is recommended for production / servers with supported NICs.