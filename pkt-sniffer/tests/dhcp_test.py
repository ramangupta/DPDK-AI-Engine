#!/usr/bin/env python3
from scapy.all import *

# DHCP Discover (client → server broadcast)
discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff", src="02:42:ac:11:00:02") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=b'\x02\x42\xac\x11\x00\x02') /
    DHCP(options=[("message-type","discover"), "end"])
)

# DHCP Offer (server → client)
offer = (
    Ether(dst="02:42:ac:11:00:02", src="aa:bb:cc:dd:ee:ff") /
    IP(src="192.168.1.1", dst="255.255.255.255") /
    UDP(sport=67, dport=68) /
    BOOTP(chaddr=b'\x02\x42\xac\x11\x00\x02', yiaddr="192.168.1.100") /
    DHCP(options=[("message-type","offer"), ("server_id","192.168.1.1"), "end"])
)

pkts = [discover, offer]
wrpcap("dhcp_test.pcap", pkts)
print("Wrote dhcp_test.pcap with", len(pkts), "frames")

