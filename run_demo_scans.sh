#!/bin/bash

echo "=== MITRE ATT&CK Python Lab - Port Scanning Demo ==="
echo "Demonstrating enhanced port scanner with multiple scan types"
echo "Target: 8.8.8.8 (Google DNS - Authorized for testing)"
echo ""

echo "1. SYN Scan (Standard reconnaissance):"
python src/reconnaissance/PortScan_Enhanced.py 8.8.8.8 -t syn

echo ""
echo "2. ACK Scan (Firewall detection):"
python src/reconnaissance/PortScan_Enhanced.py 8.8.8.8 -t ack

echo ""
echo "3. XMAS Scan (Alternative technique):"
python src/reconnaissance/PortScan_Enhanced.py 8.8.8.8 -t xmas

echo ""
echo "4. DNS Scan (Service detection):"
python src/reconnaissance/PortScan_Enhanced.py 8.8.8.8 -t dns

echo ""
echo "=== Demo Complete ==="
echo "This implements MITRE ATT&CK Technique T1595 - Active Scanning"
