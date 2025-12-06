# -*- coding: utf-8 -*-
"""
HoneyResolver_Enhanced.py: An Enhanced DNS Honeypot Resolver

This script acts as a sophisticated DNS honeypot, designed to detect and log
DNS reconnaissance attempts. It provides both legitimate-looking and
honeypot-specific responses based on query patterns.

Features:
1. Real subdomain mapping (www, smtp, mail with real IPs)
2. Fake subdomain mapping with unique IPs (admin->10.0.1.1, vpn->10.0.1.2, etc.)
3. Support for A, AAAA, MX, TXT, NS, CNAME records
4. Comprehensive logging to file (honeyresolver.log)
5. Query counting and statistics
6. Graceful shutdown with Ctrl+C
7. Professional banner and help text

MITRE ATT&CK Mapping:
- T1590.002: Gather Victim Host Information: DNS (Honeypot detects this activity)
- T1018: Remote System Discovery (Honeypot detects attempts to discover internal systems via DNS)
"""

import argparse
import logging
import random
import socketserver
import sys
import time
from collections import defaultdict
from typing import Dict, List, Tuple

from dnslib import DNSHeader, DNSRecord, RR, A, AAAA, MX, TXT, NS, CNAME, PTR, QTYPE

# --- Configuration ---
HONEYPOT_DOMAIN = "example.com"  # Replace with your desired honeypot domain
LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 53

LOG_FILE = "honeyresolver.log"
LOG_FORMAT = "% (asctime)s - %(levelname)s - %(message)s"

# Set up logging to file and console
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# --- Global Statistics and Mappings ---
QUERY_STATS = defaultdict(lambda: defaultdict(int))  # {client_ip: {query_type: count}}
TOTAL_QUERIES = 0

# Real-looking IPs for common services (replace with actual public IPs if desired)
REAL_IP_BASE = "203.0.113."
REAL_IPV6_BASE = "2001:db8::"

REAL_MAPPING: Dict[str, Dict[str, List[str]]] = {
    "www." + HONEYPOT_DOMAIN: {
        "A": [REAL_IP_BASE + "1"],
        "AAAA": [REAL_IPV6_BASE + "1"],
    },
    "mail." + HONEYPOT_DOMAIN: {
        "A": [REAL_IP_BASE + "2"],
        "MX": [f"10 mail.{HONEYPOT_DOMAIN}"],
    },
    "smtp." + HONEYPOT_DOMAIN: {
        "A": [REAL_IP_BASE + "2"],
    },
    HONEYPOT_DOMAIN: { # Base domain records
        "NS": [f"ns1.{HONEYPOT_DOMAIN}", f"ns2.{HONEYPOT_DOMAIN}"],
        "MX": [f"10 mail.{HONEYPOT_DOMAIN}"],
        "TXT": [f"v=spf1 include:_spf.{HONEYPOT_DOMAIN} ~all"],
        "A": [REAL_IP_BASE + "0"],
        "AAAA": [REAL_IPV6_BASE + "0"],
    },
    f"ns1.{HONEYPOT_DOMAIN}": {"A": [REAL_IP_BASE + "10"]},
    f"ns2.{HONEYPOT_DOMAIN}": {"A": [REAL_IP_BASE + "11"]},
}

# Fake/Honeypot Mappings (using private IP ranges)
# Increment last octet for each fake subdomain to ensure unique IPs
FAKE_IP_COUNTER = 1
FAKE_MAPPING: Dict[str, Dict[str, List[str]]] = {}

def get_fake_ip() -> str:
    """Generates a unique fake IP address from a private range."""
    global FAKE_IP_COUNTER
    ip = f"10.0.1.{FAKE_IP_COUNTER}"
    FAKE_IP_COUNTER += 1
    return ip

def init_fake_mappings():
    """Initializes a set of fake subdomain to IP mappings."""
    fake_subdomains = [
        "admin", "vpn", "internal", "dev", "test", "staging", "hr", "jira",
        "confluence", "git", "secret", "private", "db", "sql", "backup",
        "remote", "server", "cluster", "control", "console", "prod", "uat",
        "legacy", "old", "secure-portal", "mgmt", "management"
    ]
    for sub in fake_subdomains:
        fqdn = f"{sub}.{HONEYPOT_DOMAIN}"
        FAKE_MAPPING[fqdn] = {"A": [get_fake_ip()]}
        FAKE_MAPPING[f"www.{sub}.{HONEYPOT_DOMAIN}"] = {"A": [get_fake_ip()]}
    
    # Add some CNAMEs to other fake services
    FAKE_MAPPING[f"portal.{HONEYPOT_DOMAIN}"] = {"CNAME": [f"admin.{HONEYPOT_DOMAIN}"]}
    FAKE_MAPPING[f"vdi.{HONEYPOT_DOMAIN}"] = {"CNAME": [f"vpn.{HONEYPOT_DOMAIN}"]}

init_fake_mappings()

# Combine all mappings for easier lookup
ALL_MAPPING = {**REAL_MAPPING, **FAKE_MAPPING}

# --- DNS Handler ---
class DNSHandler(socketserver.BaseRequestHandler):
    """
    Handles incoming DNS requests, logs them, and responds with appropriate
    real or honeypot DNS records.
    """
    def handle(self):
        global TOTAL_QUERIES
        data = self.request[0].strip()
        socket = self.request[1]
        client_address = self.client_address[0]

        TOTAL_QUERIES += 1

        try:
            d = DNSRecord.parse(data)
            qname = str(d.q.qname).lower()
            qtype = QTYPE[d.q.qtype]

            QUERY_STATS[client_address][qtype] += 1
            QUERY_STATS[client_address]["total"] += 1

            # Log the query
            is_honeypot_hit = False
            if qname in FAKE_MAPPING:
                is_honeypot_hit = True
                logger.warning(
                    f"HONEYPOT HIT: Client {client_address} queried for fake subdomain '{qname}' ({qtype})"
                )
            else:
                logger.info(
                    f"DNS Query: Client {client_address} requested '{qname}' ({qtype})"
                )

            # Prepare response
            response = d.reply()
            
            # Check if we have a direct mapping for the exact FQDN
            resolved_records = ALL_MAPPING.get(qname)
            
            if resolved_records and qtype in resolved_records:
                for rdata_str in resolved_records[qtype]:
                    if qtype == "A":
                        response.add_answer(RR(qname, QTYPE.A, rdata=A(rdata_str), ttl=60))
                    elif qtype == "AAAA":
                        response.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(rdata_str), ttl=60))
                    elif qtype == "MX":
                        priority, mx_host = rdata_str.split(" ", 1)
                        response.add_answer(RR(qname, QTYPE.MX, rdata=MX(mx_host, int(priority)), ttl=60))
                    elif qtype == "TXT":
                        response.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(rdata_str), ttl=60))
                    elif qtype == "NS":
                        response.add_answer(RR(qname, QTYPE.NS, rdata=NS(rdata_str), ttl=60))
                    elif qtype == "CNAME":
                        response.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(rdata_str), ttl=60))
            elif qname.endswith(HONEYPOT_DOMAIN + ".") and qname != HONEYPOT_DOMAIN + ".":
                # Handle subdomains that don't have explicit mappings, point to default A record
                if qtype == "A":
                    # For any non-explicitly defined subdomain, return a fake IP
                    # This catches things like 'unknown.example.com'
                    if qname not in FAKE_MAPPING:
                        fake_ip = get_fake_ip()
                        FAKE_MAPPING[qname] = {"A": [fake_ip]} # Dynamically add to honeypot
                        logger.warning(f"DYNAMIC HONEYPOT: Client {client_address} queried for unknown subdomain '{qname}', assigned fake IP {fake_ip}")
                    
                    response.add_answer(RR(qname, QTYPE.A, rdata=A(FAKE_MAPPING[qname]["A"][0]), ttl=60))
                elif qtype == "AAAA":
                    # For AAAA queries for arbitrary subdomains, return a fake IPv6
                    response.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(REAL_IPV6_BASE + str(random.randint(2, 254))), ttl=60))
            elif qname == HONEYPOT_DOMAIN + ".":
                # Handle base domain queries for types not explicitly mapped
                if qtype == "A" and "A" not in REAL_MAPPING[HONEYPOT_DOMAIN]:
                    response.add_answer(RR(qname, QTYPE.A, rdata=A(REAL_IP_BASE + "0"), ttl=60))
                if qtype == "AAAA" and "AAAA" not in REAL_MAPPING[HONEYPOT_DOMAIN]:
                    response.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(REAL_IPV6_BASE + "0"), ttl=60))
            
            # If no specific answer was added, and it's a query for the honeypot domain,
            # ensure a default NXDOMAIN or empty answer if it's not explicitly handled.
            if not response.rr and qname.endswith(HONEYPOT_DOMAIN + "."):
                response.header.ra = 1 # Recursion Available
                response.header.rcode = DNSRecord.NXDOMAIN # No Such Domain
                logger.info(f"NXDOMAIN for {qname} requested by {client_address}")

            socket.sendto(response.pack(), self.client_address)

        except Exception as e:
            logger.error(f"Error processing DNS request from {client_address}: {e}")

# --- DNS Server ---
class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """A multi-threaded UDP server for handling DNS requests."""
    daemon_threads = True
    allow_reuse_address = True

# --- Banner and Help ---
def print_banner():
    """Prints a professional-looking banner for the honeypot."""
    print("\n" + "="*70)
    print("                 HONEYRESOLVER ENHANCED - DNS HONEYPOT                ")
    print("="*70)
    print("Monitoring for suspicious DNS queries. Designed for security research.")
    print(f"Honeypot Domain: {HONEYPOT_DOMAIN}")
    print(f"Listening on   : {LISTEN_ADDR}:{LISTEN_PORT}")
    print("Press Ctrl+C to stop the server.")
    print("="*70 + "\n")

def print_help():
    """Prints help information for the script."""
    print("Usage: python HoneyResolver_Enhanced.py [--domain <honeypot_domain>] [--ip <listen_ip>] [--port <listen_port>]")
    print("\nOptions:")
    print("  --domain    Specify the honeypot domain (default: example.com)")
    print("  --ip        Specify the IP address to listen on (default: 0.0.0.0)")
    print("  --port      Specify the port to listen on (default: 53)")
    print("  --help, -h  Show this help message and exit.")
    print("\nExample:")
    print(f"  python HoneyResolver_Enhanced.py --domain myhoney.net --ip 127.0.0.1 --port 5353")
    print("\n" + "="*70 + "\n")

def main():
    """Main function to start the DNS honeypot server."""
    parser = argparse.ArgumentParser(description="Enhanced DNS Honeypot Resolver", add_help=False)
    parser.add_argument("--domain", default=HONEYPOT_DOMAIN, help="Specify the honeypot domain.")
    parser.add_argument("--ip", default=LISTEN_ADDR, help="Specify the IP address to listen on.")
    parser.add_argument("--port", type=int, default=LISTEN_PORT, help="Specify the port to listen on.")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit.")
    
    args = parser.parse_args()

    if args.help:
        print_banner()
        print_help()
        sys.exit(0)

    global HONEYPOT_DOMAIN, LISTEN_ADDR, LISTEN_PORT
    HONEYPOT_DOMAIN = args.domain.lower().strip('.')
    LISTEN_ADDR = args.ip
    LISTEN_PORT = args.port

    # Re-initialize mappings with the new domain
    global REAL_MAPPING, FAKE_MAPPING, ALL_MAPPING
    REAL_MAPPING = {
        "www." + HONEYPOT_DOMAIN: {
            "A": [REAL_IP_BASE + "1"],
            "AAAA": [REAL_IPV6_BASE + "1"],
        },
        "mail." + HONEYPOT_DOMAIN: {
            "A": [REAL_IP_BASE + "2"],
            "MX": [f"10 mail.{HONEYPOT_DOMAIN}"],
        },
        "smtp." + HONEYPOT_DOMAIN: {
            "A": [REAL_IP_BASE + "2"],
        },
        HONEYPOT_DOMAIN: { # Base domain records
            "NS": [f"ns1.{HONEYPOT_DOMAIN}", f"ns2.{HONEYPOT_DOMAIN}"],
            "MX": [f"10 mail.{HONEYPOT_DOMAIN}"],
            "TXT": [f"v=spf1 include:_spf.{HONEYPOT_DOMAIN} ~all"],
            "A": [REAL_IP_BASE + "0"],
            "AAAA": [REAL_IPV6_BASE + "0"],
        },
        f"ns1.{HONEYPOT_DOMAIN}": {"A": [REAL_IP_BASE + "10"]},
        f"ns2.{HONEYPOT_DOMAIN}": {"A": [REAL_IP_BASE + "11"]},
    }
    FAKE_IP_COUNTER = 1
    FAKE_MAPPING = {}
    init_fake_mappings() # Re-populate fake mappings
    ALL_MAPPING = {**REAL_MAPPING, **FAKE_MAPPING}

    print_banner()

    try:
        server = ThreadedUDPServer((LISTEN_ADDR, LISTEN_PORT), DNSHandler)
        logger.info(f"HoneyResolver listening on {LISTEN_ADDR}:{LISTEN_PORT} for domain {HONEYPOT_DOMAIN}...")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\nCtrl+C detected. Shutting down HoneyResolver gracefully...")
        server.shutdown()
        server.server_close()
        logger.info("HoneyResolver stopped.")
        # Optional: Print final statistics
        print("\n--- Final Query Statistics ---")
        for client_ip, stats in QUERY_STATS.items():
            print(f"Client: {client_ip}")
            for qtype, count in stats.items():
                print(f"  {qtype}: {count} queries")
        print(f"Total Queries Handled: {TOTAL_QUERIES}")
        print("------------------------------")
    except Exception as e:
        logger.critical(f"HoneyResolver critical error: {e}", exc_info=True)
    finally:
        sys.exit(0)


if __name__ == "__main__":
    main()
