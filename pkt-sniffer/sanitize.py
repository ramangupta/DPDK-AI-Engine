#!/usr/bin/env python3
import re
import sys

def sanitize_file(filename):
    with open(filename, "r") as f:
        text = f.read()

    # Replace private IPv4 addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    text = re.sub(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "<PRIVATE_IPV4>", text)
    text = re.sub(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<PRIVATE_IPV4>", text)
    text = re.sub(r"\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b", "<PRIVATE_IPV4>", text)

    # Replace any other IPv4
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<PUBLIC_IPV4>", text)

    # Replace IPv6 addresses
    text = re.sub(r"\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b", "<IPV6>", text)

    with open(filename, "w") as f:
        f.write(text)

    print(f"[+] Sanitized {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sanitize_ips.py <file>")
        sys.exit(1)
    sanitize_file(sys.argv[1])
