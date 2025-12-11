#!/usr/bin/env python3
"""Simple DNS exploration for demonstration"""
import socket

domains = ["google.com", "youtube.com", "docs.google.com", "drive.google.com", "mail.google.com"]
print("=== DNS Exploration Demo ===")
print("Domain -> IP Mapping:")
for domain in domains:
    try:
        ip = socket.gethostbyname(domain)
        print(f"{domain}: {ip}")
    except:
        print(f"{domain}: Could not resolve")
