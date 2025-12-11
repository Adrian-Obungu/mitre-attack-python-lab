#!/usr/bin/env python3
"""Demo script for SYN scanning"""
import sys
sys.path.append('src')

from reconnaissance.PortScan_Enhanced import SynScan

print("=== SYN Scan Demo ===")
print("Target: 8.8.8.8 (Google DNS)")
print("Purpose: Demonstrate MITRE T1595 - Active Scanning")
print("-" * 40)

results = SynScan("8.8.8.8")
print("\nÌ¥ç Scan Results:")
print(f"Open ports: {results.get('open', [])}")
print(f"Closed ports: {results.get('closed', [])}")
print(f"Filtered ports: {results.get('filtered', [])}")

if 53 in results.get('open', []):
    print("\n‚úÖ DNS server detected (Port 53 open)")
    print("This validates the technique works correctly")
