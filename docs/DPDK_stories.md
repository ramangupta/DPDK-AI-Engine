# DPDK User Stories

| ID  | Category   | Title                                   | Status  | Notes |
|-----|------------|-----------------------------------------|---------|-------|
| P1  | Perf       | Zero-copy packet forwarding mode        | READY   | Baseline perf test story |
| P2  | Perf       | Multi-core scaling with lcores and RSS  | READY   | Horizontal scale testing |
| P3  | Perf       | Line-rate capture stress testing        | READY   | 10/40/100G validation |
| P4  | Perf       | Burst mode optimization (polling, batching) | READY | Optimize RX/TX loops |
| A1  | Advanced   | NUMA-aware memory allocation            | READY   | Memory locality perf |
| A2  | Advanced   | Multi-core load balancing with RSS      | READY   | Dynamic balancing |
| A3  | Advanced   | Zero-copy packet forwarding (advanced)  | READY   | Cross-socket zero-copy |

Since we don't have a NIC we need to run DPDK in pmd-pcap mode and for that 

cd ~/dpdk
meson setup build --wipe -Denable_drivers=net/pcap
ninja -C build
sudo ninja -C build install

cd ~/dpdk
# search inside the build dir
find build -iname '*pcap*' -print
# search system install location
sudo find /usr/local/lib -iname '*pcap*' -print
# also search for pcap mentions in build logs/config
grep -iR "pcap" build/meson-logs build/meson-info.json || true

We got the pcaps successfully built in 

build/drivers/librte_net_pcap.so
build/drivers/librte_net_pcap.so.26
build/drivers/librte_net_pcap.so.26.0

export LD_LIBRARY_PATH=~/dpdk/build/drivers:~/dpdk/build/lib:$LD_LIBRARY_PATH
GDB Build

❯ sudo gdb ./build/pkt-sniffer
(gdb) run --no-pci --vdev=net_pcap0,rx_pcap=$(pwd)/dhcp_all_msgs.pcap,tx_pcap=/tmp/out.pcap

HOW TO GET ASAN FOR BETTER DEBUGGING 

How to clean build
ninja -v -t clean
ninja -v

Adding this to meson 
add_project_arguments(
  '-fsanitize=address',
  '-fno-omit-frame-pointer',
  '-g',
  '-O0',
  '-fno-stack-protector',
  language: 'c'
)

Gives Asan precedence over stack protector 

Now the linker should succeed and the executable will run under ASan. Run the program (with sudo if needed):

 sudo ./build/pkt-sniffer   --no-pci   --vdev=net_pcap0,rx_pcap=$(pwd)/dhcp_all_msgs.pcap,tx_pcap=/tmp/out.pcap   --log-level=pmd.net.pcap,8
Main Executing in DPDK mode
EAL: Detected CPU lcores: 12
EAL: Detected NUMA nodes: 1
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /var/run
...
DPDK reports 1 available ports
Found DPDK port 0
RAMAN ... DPDK init success on port 0!
RAMAN .. DPDK capture next
mbuf pkt_len=294 data_len=294 nb_segs=1
sizeof(pkt_view)=264 pkt_len=294
Got the pv  capture_from_mbufReturning now 
[len=294] ETH 02:42:ac:11:00:02 → ff:ff:ff:ff:ff:ff type=0x0800
      IPv4 0.0.0.0 → 255.255.255.255 proto=17 ihl=20 tot=280 ttl=64
    DHCP xid=0x12345678 op=1 (REQUEST)
      type=DISCOVER
      UDP 68 → 67 len=260 payload=252
RAMAN .. Anything here 
ETH_PCAP: eth_dev_close(): Closing pcap ethdev on NUMA socket 0
AddressSanitizer:DEADLYSIGNAL
=================================================================
==8173==ERROR: AddressSanitizer: SEGV on unknown address 0x7d8d5e2026c0 (pc 0x582a0e867729 bp 0x7ffe753fd0d0 sp 0x7ffe753fcff0 T0)
==8173==The signal is caused by a WRITE memory access.
    #0 0x582a0e867729 in main ../main.c:19
    #1 0x7d90e3e29d8f in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #2 0x7d90e3e29e3f in __libc_start_main_impl ../csu/libc-start.c:392
    #3 0x582a0e866d64 in _start (/home/oem/DPDK-AI-Engine/pkt-sniffer/build/pkt-sniffer+0x16d64)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV ../main.c:19 in main
==8173==ABORTING



