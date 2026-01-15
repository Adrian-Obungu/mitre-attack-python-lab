#!/usr/bin/env python3
"""Demo script for SYN scanning"""
import sys
sys.path.append('src')

from reconnaissance.PortScan_Enhanced import PortScanner

print("=== SYN Scan Demo ===")
print("Target: 8.8.8.8 (Google DNS)")
print("Purpose: Demonstrate MITRE T1595 - Active Scanning")
print("-" * 40)

scanner = PortScanner("8.8.8.8", [53]) # Assuming we want to scan port 53 for DNS
results = scanner.syn_scan()
print("\n> Scan Results:")

# The results are a dictionary where keys are ports and values are their status
open_ports = [port for port, status in results.items() if status == "Open"]
closed_ports = [port for port, status in results.items() if status == "Closed"]
filtered_ports = [port for port, status in results.items() if status == "Filtered"]

print(f"Open ports: {open_ports}")
print(f"Closed ports: {closed_ports}")
print(f"Filtered ports: {filtered_ports}")


if 53 in open_ports:
    print("\n✅ DNS server detected (Port 53 open)")
    print("This validates the technique works correctly")