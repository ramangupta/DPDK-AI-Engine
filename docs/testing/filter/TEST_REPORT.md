Test Plan – pkt-sniffer

1. Objectives

 - Verify CLI parser correctness (options parsing, ignoring irrelevant args).
 - Validate packet filtering for IPv4, IPv6, protocols, and ports.
 - Ensure capture initialization works with pcap, AF_PACKET, and DPDK backends.
 - Confirm correctness of captured output format and error handling.

2. Test Environment

 - OS: Ubuntu 22.04+ (native or VM).
 - Privileges: Root (sudo) required for AF_PACKET and DPDK.
 - Interfaces: Wireless (wlo1), loopback, or virtual NICs.
 - Traffic Sources:
    ping (IPv4/IPv6 ICMP).
    curl / wget for TCP/UDP traffic.
    iperf3 for controlled TCP/UDP flows.

3. Test Scenarios

3.1 CLI Parser

3.1.1 Help Option
    
./pkt-sniffer -h

❯ sudo ./build/pkt-sniffer -h
[sudo] password for oem: 
Usage: ./build/pkt-sniffer [filter options] [DPDK EAL options]
Filter options:
  -p, --proto <dns|tcp|udp|arp>
  -P, --port <1-65535>
  -i, --ip <IPv4/IPv6>
  -H, --host <substring>
  -h, --help

Notes:
  * Unknown options (e.g., DPDK EAL flags like --no-pci, -vdev=...) are ignored.
  * DNS means TCP/53 or UDP/53.

3.1.2 Ignore options 

dpdk-stock-ai/pkt-sniffer on  master [!?] is 📦 v0.1 via C v11.4.0-gcc 
❯ sudo ./build/pkt-sniffer --no-pci -vdev=net_af_packet0,iface=wlo1
[len=91] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x0800
[ipv4] saw packet id=27093, total_length=77, ihl=20, proto=6
      IPv4 140.82.114.26 → 192.168.0.104 proto=6 ihl=20 tot=77 ttl=48
      TCP 443 → 36428 seq=2495604407 ack=1131780611 win=76 hlen=32 flags=AP

3.1.3 Invalid option - FAIL

❯ sudo ./build/pkt-sniffer -z
[len=86] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x86dd
      IPv6 fe80:0000:0000:0000:16eb:b6ff:fec4:c81c → 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d next=58 hlim=255
      ICMPv6 type=96 code=0

3.2 Filters

3.2.1 IPv4 Filters

❯ sudo ./build/pkt-sniffer -i 192.168.0.104
[len=384] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0800
[ipv4] saw packet id=54371, total_length=370, ihl=20, proto=6
      IPv4 192.168.0.104 → 172.66.0.227 proto=6 ihl=20 tot=370 ttl=64
      TCP 48438 → 443 seq=1582824546 ack=3607474501 win=2525 hlen=32 flags=AP
 TLS packet 
      TLS: content_type=23 (ApplicationData) record_len=313
      TLS Application Data (313 bytes)
[len=2048] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0800
[ipv4] saw packet id=54372, total_length=6992, ihl=20, proto=6
      IPv4 192.168.0.104 → 172.66.0.227 proto=6 ihl=20 tot=2034 ttl=64
      TCP 48438 → 443 seq=1582824864 ack=3607474501 win=2525 hlen=32 flags=AP
 TLS packet 

 3.2.2 IPv6 Filters 

 ❯ sudo ./build/pkt-sniffer -i 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d
[len=110] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x86dd
      IPv6 2606:4700:4400:0000:0000:0000:ac40:94eb → 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d next=6 hlim=58
      TCP <bad header len>
[len=114] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x86dd
      IPv6 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d → 2606:4700:4400:0000:0000:0000:ac40:94eb next=6 hlim=64
      TCP <bad header len>
[len=86] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x86dd
      IPv6 2606:4700:4400:0000:0000:0000:ac40:94eb → 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d next=6 hlim=58
      TCP <bad header len>
[len=110] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x86dd
      IPv6 2606:4700:4400:0000:0000:0000:6812:2715 → 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d next=6 hlim=58
      TCP <bad header len>


3.2.3 Invalid IP 

❯ sudo ./build/pkt-sniffer -i notanip
Invalid IPv4 address: notanip


3.3 Protocols

3.3.1 TCP

 sudo ./build/pkt-sniffer -p tcp
 curl https://example.com

[len=74] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0800
[ipv4] saw packet id=64494, total_length=60, ihl=20, proto=6
      IPv4 192.168.0.104 → 23.192.228.80 proto=6 ihl=20 tot=60 ttl=64
      TCP 46288 → 443 seq=288451973 ack=0 win=64240 hlen=40 flags=S
[len=705] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0800
[ipv4] saw packet id=54915, total_length=691, ihl=20, proto=6
      IPv4 192.168.0.104 → 172.66.0.227 proto=6 ihl=20 tot=691 ttl=64
      TCP 48438 → 443 seq=1583362367 ack=3607498094 win=2525 hlen=32 flags=AP

3.3.2 UDP

sudo ./build/pkt-sniffer -p udp
dig google.com
[len=97] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=18694, total_length=83, ihl=20, proto=17
      IPv4 127.0.0.53 → 127.0.0.1 proto=17 ihl=20 tot=83 ttl=1
        DNS RESP id=0xece1 qd=1 an=1 flags=0x8180
          Q: google.com  type=1 class=1
          A: google.com  type=1 class=1 ttl=141 A=142.250.205.110
      UDP 53 → 34154 len=63 payload=55
[len=97] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=18694, total_length=83, ihl=20, proto=17
      IPv4 127.0.0.53 → 127.0.0.1 proto=17 ihl=20 tot=83 ttl=1
        DNS RESP id=0xece1 qd=1 an=1 flags=0x8180
          Q: google.com  type=1 class=1
          A: google.com  type=1 class=1 ttl=141 A=142.250.205.110
      UDP 53 → 34154 len=63 payload=55

3.3.3 ICMP

❯ sudo ./build/pkt-sniffer -p icmp
ping 8.8.8.8

[len=98] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0800
[ipv4] saw packet id=26749, total_length=84, ihl=20, proto=1
      IPv4 192.168.0.104 → 8.8.8.8 proto=1 ihl=20 tot=84 ttl=64
      ICMPv4 type=8(EchoRequest) code=0
        Echo id=1 seq=1
[len=98] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x0800
[ipv4] saw packet id=0, total_length=84, ihl=20, proto=1
      IPv4 8.8.8.8 → 192.168.0.104 proto=1 ihl=20 tot=84 ttl=118
      ICMPv4 type=0(EchoReply) code=0
        Echo id=1 seq=1

3.3.4 ICMPv6

❯ sudo ./build/pkt-sniffer -p icmp6
ping6 google.com

[len=118] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x86dd
      IPv6 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d → 2404:6800:4007:0807:0000:0000:0000:200e next=58 hlim=64
      ICMPv6 type=96 code=6
[len=118] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x86dd
      IPv6 2404:6800:4007:0807:0000:0000:0000:200e → 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d next=58 hlim=117
      ICMPv6 type=104 code=6

3.3.5 ARP

❯ sudo ./build/pkt-sniffer -p arp
[len=60] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x0806
      ARP request: who has 192.168.0.104? tell 192.168.0.1 (14:eb:b6:c4:c8:1c)
[len=42] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0806
      ARP reply: 192.168.0.104 is at d4:d8:53:5d:ab:d8
[len=60] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x0806
      ARP request: who has 192.168.0.104? tell 192.168.0.1 (14:eb:b6:c4:c8:1c)
[len=42] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0806
      ARP reply: 192.168.0.104 is at d4:d8:53:5d:ab:d8


3.4 Port 

3.4.1 TCP port filters

sudo ./build/pkt-sniffer -p tcp -P 443
curl https://example.com

[len=94] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x86dd
      IPv6 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d → 2600:1406:5e00:0006:0000:0000:17ce:bc12 next=6 hlim=64
      TCP <bad header len>
[len=74] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0800
[ipv4] saw packet id=60530, total_length=60, ihl=20, proto=6
      IPv4 192.168.0.104 → 23.192.228.80 proto=6 ihl=20 tot=60 ttl=64
      TCP 42392 → 443 seq=1982975739 ack=0 win=64240 hlen=40 flags=S

3.4.2 UDP port filters 

❯ sudo ./build/pkt-sniffer -p udp -P 53
dig google.com

[len=93] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=61447, total_length=79, ihl=20, proto=17
      IPv4 127.0.0.1 → 127.0.0.53 proto=17 ihl=20 tot=79 ttl=64
        DNS QUERY id=0x88ca qd=1 an=0 flags=0x0120
          Q: google.com  type=1 class=1
      UDP 39917 → 53 len=59 payload=51
[len=93] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=61447, total_length=79, ihl=20, proto=17
      IPv4 127.0.0.1 → 127.0.0.53 proto=17 ihl=20 tot=79 ttl=64
        DNS QUERY id=0x88ca qd=1 an=0 flags=0x0120
          Q: google.com  type=1 class=1
      UDP 39917 → 53 len=59 payload=51
[len=97] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=53399, total_length=83, ihl=20, proto=17
      IPv4 127.0.0.53 → 127.0.0.1 proto=17 ihl=20 tot=83 ttl=1
        DNS RESP id=0x88ca qd=1 an=1 flags=0x8180
          Q: google.com  type=1 class=1
          A: google.com  type=1 class=1 ttl=68 A=142.250.205.110
      UDP 53 → 39917 len=63 payload=55
[len=97] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=53399, total_length=83, ihl=20, proto=17
      IPv4 127.0.0.53 → 127.0.0.1 proto=17 ihl=20 tot=83 ttl=1
        DNS RESP id=0x88ca qd=1 an=1 flags=0x8180
          Q: google.com  type=1 class=1
          A: google.com  type=1 class=1 ttl=68 A=142.250.205.110
      UDP 53 → 39917 len=63 payload=55


3.4.3 Invalid Port 

 sudo ./build/pkt-sniffer -p udp -P 99999
Invalid --port: 99999

3.5 Combined Filters 

3.5.1 IPv4 + TCP + Port

❯ sudo ./build/pkt-sniffer -i 192.168.0.104 -p tcp -P 22
ssh user@192.168.0.104

[len=74] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=22542, total_length=60, ihl=20, proto=6
      IPv4 192.168.0.104 → 192.168.0.104 proto=6 ihl=20 tot=60 ttl=64
      TCP 47622 → 22 seq=3029436939 ack=0 win=65495 hlen=40 flags=S
[len=74] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=22542, total_length=60, ihl=20, proto=6
      IPv4 192.168.0.104 → 192.168.0.104 proto=6 ihl=20 tot=60 ttl=64
      TCP 47622 → 22 seq=3029436939 ack=0 win=65495 hlen=40 flags=S
[len=54] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=0, total_length=40, ihl=20, proto=6
      IPv4 192.168.0.104 → 192.168.0.104 proto=6 ihl=20 tot=40 ttl=64
      TCP 22 → 47622 seq=0 ack=3029436940 win=0 hlen=20 flags=AR
[len=54] ETH 00:00:00:00:00:00 → 00:00:00:00:00:00 type=0x0800
[ipv4] saw packet id=0, total_length=40, ihl=20, proto=6
      IPv4 192.168.0.104 → 192.168.0.104 proto=6 ihl=20 tot=40 ttl=64
      TCP 22 → 47622 seq=0 ack=3029436940 win=0 hlen=20 flags=AR

3.5.2 IPv6 + UDP + Port

❯ sudo ./build/pkt-sniffer -p udp -P 53 -i 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d
dig AAAA google.com @2606:4700:4700::1111

[len=113] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x86dd
      IPv6 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d → 2606:4700:4700:0000:0000:0000:0000:1111 next=17 hlim=64
      UDP 24586 → 28755 len=59 payload=51
[len=129] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x86dd
      IPv6 2606:4700:4700:0000:0000:0000:0000:1111 → 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d next=17 hlim=58
      UDP 24588 → 62912 len=75 payload=67

3.6 Hostname 

3.6.1 IPv4

❯ sudo ./build/pkt-sniffer -H 192.168.0
[len=92] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x0800
[ipv4] saw packet id=20778, total_length=78, ihl=20, proto=6
      IPv4 140.82.114.25 → 192.168.0.104 proto=6 ihl=20 tot=78 ttl=46
      TCP 443 → 47064 seq=1475266541 ack=3004101745 win=76 hlen=32 flags=AP
 TLS packet 
      TLS: content_type=23 (ApplicationData) record_len=21
      TLS Application Data (21 bytes)
[len=96] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0800
[ipv4] saw packet id=55978, total_length=82, ihl=20, proto=6
      IPv4 192.168.0.104 → 140.82.114.25 proto=6 ihl=20 tot=82 ttl=64
      TCP 47064 → 443 seq=3004101745 ack=1475266567 win=470 hlen=32 flags=AP

3.6.2 IPv6 

❯ sudo ./build/pkt-sniffer -H 2406:7400

[len=86] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x86dd
      IPv6 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d → 2620:01ec:0bdf:0000:0000:0000:0000:0058 next=6 hlim=64
      TCP <bad header len>
[len=86] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x86dd
      IPv6 2620:01ec:0bdf:0000:0000:0000:0000:0058 → 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d next=6 hlim=55
      TCP <bad header len>

3.6.3 IPv4 hostname resolution

sudo ./build/pkt-sniffer -H google.com
ping -4 google.co
[len=98] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x0800
[ipv4] saw packet id=9898, total_length=84, ihl=20, proto=1
      IPv4 192.168.0.104 → 142.250.205.110 proto=1 ihl=20 tot=84 ttl=64
      ICMPv4 type=8(EchoRequest) code=0
        Echo id=7 seq=1
[len=98] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x0800
[ipv4] saw packet id=0, total_length=84, ihl=20, proto=1
      IPv4 142.250.205.110 → 192.168.0.104 proto=1 ihl=20 tot=84 ttl=118
      ICMPv4 type=0(EchoReply) code=0
        Echo id=7 seq=1

3.6.4 IPv6 Hostname resolution

❯ sudo ./build/pkt-sniffer -H google.com
ping google.com

[len=118] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x86dd
      IPv6 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d → 2404:6800:4007:0807:0000:0000:0000:200e next=58 hlim=64
      ICMPv6 type=96 code=6
[len=118] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x86dd
      IPv6 2404:6800:4007:0807:0000:0000:0000:200e → 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d next=58 hlim=117
      ICMPv6 type=104 code=6
[len=118] ETH d4:d8:53:5d:ab:d8 → 14:eb:b6:c4:c8:1c type=0x86dd
      IPv6 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d → 2404:6800:4007:0807:0000:0000:0000:200e next=58 hlim=64
      ICMPv6 type=96 code=6
[len=118] ETH 14:eb:b6:c4:c8:1c → d4:d8:53:5d:ab:d8 type=0x86dd
      IPv6 2404:6800:4007:0807:0000:0000:0000:200e → 2406:7400:00ce:e2b2:fdbc:2ced:059f:9d4d next=58 hlim=117
      ICMPv6 type=104 code=6








