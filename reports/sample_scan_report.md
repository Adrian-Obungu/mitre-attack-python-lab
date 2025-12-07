# Security Scan Report - Sample
**Date:** $(date +%Y-%m-%d)
**Target:** 192.168.1.1/24 (Example Network)

## Executive Summary
A port scan was conducted to identify active services and potential vulnerabilities.

## Methodology
- **Scan Type:** SYN scan
- **Ports Scanned:** 22, 80, 443, 8080, 8443
- **Tool:** PortScan_Enhanced.py

## Findings
| Port | Service | Status | Notes |
|------|---------|--------|-------|
| 22   | SSH     | Open   | Secure Shell access |
| 80   | HTTP    | Open   | Web server |
| 443  | HTTPS   | Open   | Secure web server |
| 8080 | HTTP-Alt| Filtered| Likely firewall blocked |
| 8443 | HTTPS-Alt| Filtered| Likely firewall blocked |

## Recommendations
1. Ensure SSH is using key-based authentication
2. Update web server software
3. Review firewall rules for ports 8080/8443

## MITRE ATT&CK Mapping
- **T1595.001:** Port Scanning
- **T1046:** Network Service Discovery
