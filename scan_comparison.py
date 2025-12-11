#!/usr/bin/env python3
"""Compare different scan types"""
import sys
sys.path.append('src')

from reconnaissance.PortScan_Enhanced import SynScan, ACKScan, XmasScan

target = "127.0.0.1"  # Safe local target

print("=== Scan Type Comparison ===")
print("MITRE Technique: T1595.001 - Port Scanning")
print("-" * 40)

print("\n1. SYN Scan (Default):")
print("   - Sends SYN packets, waits for SYN/ACK")
print("   - Stealthy, reliable")
syn_results = SynScan(target)
print(f"   Results: {syn_results}")

print("\n2. ACK Scan (Firewall Testing):")
print("   - Sends ACK packets, looks for RST responses")
print("   - Detects firewall rules")
ack_results = ACKScan(target)
print(f"   Results: {ack_results}")

print("\n3. XMAS Scan (OS Fingerprinting):")
print("   - Sends FIN, URG, PUSH flags")
print("   - Different OS responses reveal OS type")
xmas_results = XmasScan(target)
print(f"   Results: {xmas_results}")

print("\ní³š Application:")
print("- SYN: Initial reconnaissance")
print("- ACK: Firewall rule analysis")
print("- XMAS: Operating system detection")
