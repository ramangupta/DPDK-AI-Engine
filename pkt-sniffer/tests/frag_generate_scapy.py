from scapy.all import Ether, IP, UDP, Raw, fragment, wrpcap

payload = b"A" * 10000
ip = IP(src="192.168.0.1", dst="192.168.0.2", proto=17, id=1)
udp = UDP(sport=12345, dport=80)
pkt = ip/udp/Raw(payload)

frags = fragment(pkt, fragsize=1480)

eth_src = "d4:d8:53:5d:ab:d8"
eth_dst = "ff:ff:ff:ff:ff:ff"
eth_frags = [Ether(src=eth_src, dst=eth_dst, type=0x0800)/f for f in frags]

wrpcap("frags_big.pcap", eth_frags)
print(f"Generated {len(eth_frags)} Ethernet+IP fragments")

