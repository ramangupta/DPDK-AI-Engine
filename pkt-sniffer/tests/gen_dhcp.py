#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, wrpcap

# -------------------
# Constants
# -------------------
CLIENT_MAC = "02:42:ac:11:00:02"
SERVER_MAC = "aa:bb:cc:dd:ee:ff"

CLIENT_IP  = "0.0.0.0"
LEASED_IP  = "192.168.1.100"
SERVER_IP  = "192.168.1.1"
BROADCAST  = "255.255.255.255"
XID        = 0x12345678

pkts = []

def mac2bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))

# --------------------------
# Client -> Server messages
# --------------------------
discover = (
    Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src=CLIENT_IP, dst=BROADCAST) /
    UDP(sport=68, dport=67) /
    BOOTP(op=1, chaddr=mac2bytes(CLIENT_MAC), xid=XID) /
    DHCP(options=[
        ("message-type", "discover"),
        ("param_req_list", [1, 3, 6, 15, 51, 54]),  # subnet, router, DNS, domain, lease, server id
        "end"
    ])
)

request = (
    Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src=CLIENT_IP, dst=BROADCAST) /
    UDP(sport=68, dport=67) /
    BOOTP(op=1, chaddr=mac2bytes(CLIENT_MAC), xid=XID) /
    DHCP(options=[
        ("message-type", "request"),
        ("requested_addr", LEASED_IP),
        ("server_id", SERVER_IP),
        "end"
    ])
)

decline = (
    Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src=CLIENT_IP, dst=BROADCAST) /
    UDP(sport=68, dport=67) /
    BOOTP(op=1, chaddr=mac2bytes(CLIENT_MAC), xid=XID) /
    DHCP(options=[
        ("message-type", "decline"),
        ("requested_addr", LEASED_IP),
        ("server_id", SERVER_IP),
        "end"
    ])
)

release = (
    Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src=LEASED_IP, dst=BROADCAST) /
    UDP(sport=68, dport=67) /
    BOOTP(op=1, chaddr=mac2bytes(CLIENT_MAC), xid=XID) /
    DHCP(options=[
        ("message-type", "release"),
        ("server_id", SERVER_IP),
        "end"
    ])
)

inform = (
    Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src=LEASED_IP, dst=BROADCAST) /
    UDP(sport=68, dport=67) /
    BOOTP(op=1, chaddr=mac2bytes(CLIENT_MAC), xid=XID) /
    DHCP(options=[
        ("message-type", "inform"),
        "end"
    ])
)

# --------------------------
# Server -> Client messages
# --------------------------
offer = (
    Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
    IP(src=SERVER_IP, dst=BROADCAST) /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr=LEASED_IP, siaddr=SERVER_IP,
          chaddr=mac2bytes(CLIENT_MAC), xid=XID) /
    DHCP(options=[
        ("message-type", "offer"),
        ("server_id", SERVER_IP),
        ("router", SERVER_IP),
        ("dns", ["8.8.8.8", "8.8.4.4"]),
        ("lease_time", 3600),
        "end"
    ])
)

ack = (
    Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
    IP(src=SERVER_IP, dst=BROADCAST) /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr=LEASED_IP, siaddr=SERVER_IP,
          chaddr=mac2bytes(CLIENT_MAC), xid=XID) /
    DHCP(options=[
        ("message-type", "ack"),
        ("server_id", SERVER_IP),
        ("router", SERVER_IP),
        ("dns", ["8.8.8.8", "8.8.4.4"]),
        ("lease_time", 3600),
        "end"
    ])
)

nak = (
    Ether(src=SERVER_MAC, dst=CLIENT_MAC) /
    IP(src=SERVER_IP, dst=BROADCAST) /
    UDP(sport=67, dport=68) /
    BOOTP(op=2, yiaddr="0.0.0.0", siaddr=SERVER_IP,
          chaddr=mac2bytes(CLIENT_MAC), xid=XID) /
    DHCP(options=[
        ("message-type", "nak"),
        ("server_id", SERVER_IP),
        "end"
    ])
)

# Collect all messages
pkts.extend([discover, offer, request, ack, nak, decline, release, inform])

# --------------------------
# Write to PCAP
# --------------------------
wrpcap("dhcp_all_msgs.pcap", pkts)
print(f"✅ Generated dhcp_all_msgs.pcap with {len(pkts)} DHCP messages")
