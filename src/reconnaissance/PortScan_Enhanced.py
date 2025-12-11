# -*- coding: utf-8 -*-
"""
PortScan_Enhanced.py: An Advanced Port Scanning Tool

This script provides capabilities for various network scanning techniques, including
SYN, ACK, and XMAS scans, as well as DNS reconnaissance. It is designed for
educational and authorized security assessment purposes only.

MITRE ATT&CK Mapping:
- T1046: Network Service Scanning (SYN, XMAS scans)
- T1595.001: Active Scanning: Scanning IP Blocks (ACK scan for firewall discovery)
- T1590.002: Gather Victim Host Information: DNS (DNS scan)
"""

import argparse
import logging
import random
import sys
import os
import re
import ctypes
from typing import Dict, List, Optional, Tuple

from scapy.all import IP, TCP, sr1, conf
from dns import resolver, exception

# --- Configuration ---
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, handlers=[logging.FileHandler("port_scan_enhanced.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# Suppress scapy's verbose output
conf.verb = 0

# --- Safety Warning ---
SAFETY_WARNING = """
*** LEGAL DISCLAIMER ***
This tool is intended for authorized security testing and educational purposes only.
Unauthorized scanning of networks is illegal. The user assumes all responsibility
for any unauthorized or malicious use of this script. Always obtain explicit,
written permission from the network owner before scanning.
"""

# --- Security and Validation Functions ---

def is_admin():
    """Check for administrator privileges."""
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def validate_target(target):
    """Validate the target to be a valid IP address or hostname."""
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    hostname_pattern = re.compile(r"^[a-zA-Z0-9.-]+$")
    if ip_pattern.match(target) or hostname_pattern.match(target):
        return True
    return False

def validate_and_parse_ports(ports_str: str) -> Optional[List[int]]:
    """Validate and parse port strings (e.g., '80,443' or '1-1024')."""
    ports_to_scan = set()
    try:
        if "-" in ports_str:
            start, end = map(int, ports_str.split("-"))
            if not (1 <= start <= end <= 65535):
                return None
            ports_to_scan.update(range(start, end + 1))
        else:
            ports = [int(p) for p in ports_str.split(",")]
            if not all(1 <= p <= 65535 for p in ports):
                return None
            ports_to_scan.update(ports)
        return sorted(list(ports_to_scan))
    except ValueError:
        return None

class PortScanner:
    """A class for conducting various types of network port scans."""

    def __init__(self, target_ip: str, ports: List[int], timeout: int = 2):
        """
        Initializes the PortScanner.

        Args:
            target_ip: The IP address of the target machine.
            ports: A list of port numbers to scan.
            timeout: The timeout for network packets in seconds.
        """
        self.target_ip = target_ip
        self.ports = ports
        self.timeout = timeout
        logger.info(f"PortScanner initialized for target: {self.target_ip}")

    def syn_scan(self) -> Dict[int, str]:
        """
        Performs a TCP SYN scan to identify open, closed, or filtered ports.
        MITRE ATT&CK: T1046 (Network Service Scanning)
        """
        logger.info(f"Starting SYN scan on {self.target_ip} for ports: {self.ports}")
        results = {}
        for port in self.ports:
            try:
                src_port = random.randint(1025, 65534)
                ip_packet = IP(dst=self.target_ip)
                tcp_packet = TCP(sport=src_port, dport=port, flags="S")
                response = sr1(ip_packet / tcp_packet, timeout=self.timeout, verbose=0)

                if response is None:
                    results[port] = "Filtered"
                elif response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:  # SYN/ACK
                        sr1(IP(dst=self.target_ip) / TCP(sport=src_port, dport=port, flags="R"), timeout=self.timeout, verbose=0)
                        results[port] = "Open"
                    elif response.getlayer(TCP).flags == 0x14:  # RST/ACK
                        results[port] = "Closed"
                else:
                    results[port] = "Filtered"

            except Exception as e:
                logger.error(f"Error scanning port {port}: {e}")
                results[port] = "Error"

        self._log_results("SYN Scan", results)
        return results

    def ack_scan(self) -> Dict[int, str]:
        """
        Performs a TCP ACK scan to infer firewall presence.
        MITRE ATT&CK: T1595.001 (Active Scanning) - for firewall discovery.
        """
        logger.info(f"Starting ACK scan on {self.target_ip} for ports: {self.ports}")
        results = {}
        for port in self.ports:
            try:
                src_port = random.randint(1025, 65534)
                ip_packet = IP(dst=self.target_ip)
                tcp_packet = TCP(sport=src_port, dport=port, flags="A")
                response = sr1(ip_packet / tcp_packet, timeout=self.timeout, verbose=0)

                if response is None:
                    results[port] = "Filtered (Stateful Firewall)"
                elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x4:  # RST
                    results[port] = "Unfiltered (No Firewall or Stateless)"
                else:
                    results[port] = "Filtered"

            except Exception as e:
                logger.error(f"Error during ACK scan on port {port}: {e}")
                results[port] = "Error"
        
        self._log_results("ACK Scan", results)
        return results

    def xmas_scan(self) -> Dict[int, str]:
        """
        Performs a TCP XMAS scan using FIN, PSH, and URG flags.
        MITRE ATT&CK: T1046 (Network Service Scanning)
        """
        logger.info(f"Starting XMAS scan on {self.target_ip} for ports: {self.ports}")
        results = {}
        for port in self.ports:
            try:
                src_port = random.randint(1025, 65534)
                ip_packet = IP(dst=self.target_ip)
                tcp_packet = TCP(sport=src_port, dport=port, flags="FPU") # FIN, PSH, URG
                response = sr1(ip_packet / tcp_packet, timeout=self.timeout, verbose=0)

                if response is None:
                    results[port] = "Open|Filtered"
                elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14: # RST/ACK
                    results[port] = "Closed"
                else:
                    results[port] = "Filtered"
            
            except Exception as e:
                logger.error(f"Error during XMAS scan on port {port}: {e}")
                results[port] = "Error"
        
        self._log_results("XMAS Scan", results)
        return results

    @staticmethod
    def dns_scan(target_domain: str) -> Dict[str, List[str]]:
        """
        Performs DNS reconnaissance to gather various record types.
        MITRE ATT&CK: T1590.002 (Gather Victim Host Information: DNS)
        """
        logger.info(f"Starting DNS scan for domain: {target_domain}")
        results = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(target_domain, record_type)
                results[record_type] = [str(rdata) for rdata in answers]
            except exception.NoAnswer:
                results[record_type] = ["No records found."]
            except exception.NXDOMAIN:
                logger.error(f"Domain '{target_domain}' does not exist.")
                return {"Error": [f"Domain '{target_domain}' does not exist."]}
            except Exception as e:
                logger.error(f"Error querying {record_type} records: {e}")
                results[record_type] = [f"Error: {e}"]

        logger.info("--- DNS Scan Results ---")
        for record_type, records in results.items():
            logger.info(f"  {record_type} Records:")
            for record in records:
                logger.info(f"    - {record}")
        logger.info("--------------------------")
        return results

    def _log_results(self, scan_type: str, results: Dict[int, str]):
        """Logs the results of a port scan."""
        logger.info(f"--- {scan_type} Results for {self.target_ip} ---")
        for port, status in results.items():
            logger.info(f"  Port {port}: {status}")
        logger.info("----------------------------------")

def run_demo():
    """Runs a demonstration of the scanner's capabilities against a safe target."""
    logger.info("=== Starting Port Scanner Demo Mode ===")
    demo_target = "scanme.nmap.org"
    demo_ports = [22, 80, 443, 8080]
    
    logger.info(f"Targeting: {demo_target}")
    
    # Non-privileged scans for demo
    scanner = PortScanner(demo_target, demo_ports)
    scanner.ack_scan()
    PortScanner.dns_scan(demo_target)
    
    # Privileged scan check
    if is_admin():
        scanner.syn_scan()
        scanner.xmas_scan()
    else:
        logger.warning("SYN and XMAS scans require administrator privileges. Skipping in demo mode.")
        
    logger.info("=== Demo Mode Finished ===")

def main():
    """Main function to parse arguments and initiate scans."""
    print(SAFETY_WARNING)
    
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with security enhancements.")
    parser.add_argument("target", nargs="?", help="The target IP address or domain name.")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (e.g., 80,443 or 1-1024).")
    parser.add_argument("-t", "--type", required=True, choices=["syn", "ack", "xmas", "dns"], help="Type of scan to perform.")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode against a safe target.")

    args = parser.parse_args()

    if args.demo:
        run_demo()
        sys.exit(0)

    # --- Input Validation ---
    if not args.target:
        logger.critical("Target IP or domain is required unless in demo mode.")
        parser.print_help()
        sys.exit(1)

    if not validate_target(args.target):
        logger.critical(f"Invalid target specified: {args.target}")
        sys.exit("Error: Invalid target. Please provide a valid IP address or hostname.")

    ports_to_scan = validate_and_parse_ports(args.ports)
    if ports_to_scan is None:
        logger.critical(f"Invalid port format or range: {args.ports}")
        sys.exit("Error: Invalid port format. Use '80,443' or '1-1024' with ports between 1 and 65535.")

    # --- Privilege Check ---
    privileged_scans = {"syn", "xmas"}
    if args.type in privileged_scans and not is_admin():
        logger.critical(f"'{args.type}' scan requires administrator privileges.")
        sys.exit(f"Error: '{args.type}' scan must be run with administrator privileges.")
    
    logger.info(f"Starting {args.type} scan on {args.target} for ports: {args.ports}")

    if args.type == "dns":
        PortScanner.dns_scan(args.target)
    else:
        scanner = PortScanner(target_ip=args.target, ports=ports_to_scan)
        if args.type == "syn":
            scanner.syn_scan()
        elif args.type == "ack":
            scanner.ack_scan()
        elif args.type == "xmas":
            scanner.xmas_scan()

if __name__ == "__main__":
    main()
