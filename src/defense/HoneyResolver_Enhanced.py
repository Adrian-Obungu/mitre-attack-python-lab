#!/usr/bin/env python3
"""
Enhanced DNS Honeypot Resolver
Author: Adrian S. Obungu
"""

import time
import random
import logging
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from dnslib import *
from dnslib.server import DNSServer

# Prometheus client imports
from prometheus_client import start_http_server, Counter, Gauge

# --- Configuration Loading ---

def load_config():
    """Loads configuration from an external JSON file."""
    try:
        # Adjust path for Docker context
        config_path = os.environ.get("HONEYPOT_CONFIG", os.path.join(os.path.dirname(__file__), '..', '..', 'config', 'honeypot_config.json'))
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.critical(f"Error loading configuration file: {e}")
        sys.exit(1)

CONFIG = load_config()
HONEYPOT_DOMAIN = CONFIG.get("HONEYPOT_DOMAIN", "example.com")
LISTEN_ADDR = CONFIG.get("LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = CONFIG.get("LISTEN_PORT", 8053)
HEALTH_METRICS_PORT = CONFIG.get("HEALTH_METRICS_PORT", 8000)
REAL_SUBDOMAINS = CONFIG.get("REAL_SUBDOMAINS", {})
FAKE_SUBDOMAINS = CONFIG.get("FAKE_SUBDOMAINS", {})

# --- Prometheus Metrics ---
DNS_QUERIES_TOTAL = Counter('dns_queries_total', 'Total number of DNS queries received', ['qtype', 'category'])
DNS_RESOLVER_STATUS = Gauge('dns_resolver_status', 'Status of the DNS resolver (1=running, 0=stopped)')

# --- Structured JSON Logging ---
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "process_id": record.process,
            "thread_id": record.thread,
            "filename": record.filename,
            "lineno": record.lineno,
        }
        # Add custom fields if they exist
        if hasattr(record, 'client_ip'):
            log_record['client_ip'] = record.client_ip
        if hasattr(record, 'qname'):
            log_record['qname'] = record.qname
        if hasattr(record, 'qtype'):
            log_record['qtype'] = record.qtype
        if hasattr(record, 'response_ip'):
            log_record['response_ip'] = record.response_ip
        if hasattr(record, 'category'):
            log_record['category'] = record.category
            
        return json.dumps(log_record)

# Sanitize function to prevent log injection
def sanitize_log_input(data: str) -> str:
    """Removes potentially malicious characters from log input."""
    # Allow alphanumeric, dots, hyphens. Remove everything else.
    return re.sub(r'[^\w.-]', '', data)

# Ensure logs directory exists before setting up file handler
os.makedirs("logs", exist_ok=True)

# Setup logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Clear existing handlers to prevent duplicate output if basicConfig was called elsewhere
if logger.hasHandlers():
    logger.handlers.clear()

# Add a StreamHandler for console output (important for non-silent errors)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(JsonFormatter()) # Use JSON formatter for console as well
logger.addHandler(console_handler)

# FileHandler for JSON logging
file_handler = logging.FileHandler('logs/honeyresolver.log')
file_handler.setFormatter(JsonFormatter())
logger.addHandler(file_handler)

# --- Health Check Server ---
class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def run_health_server():
    server_address = ('0.0.0.0', HEALTH_METRICS_PORT)
    httpd = HTTPServer(server_address, HealthCheckHandler)
    logger.info(f"Health check server running on port {HEALTH_METRICS_PORT}")
    httpd.serve_forever()

class EnhancedHoneyResolver:
    """The core DNS resolver class for the honeypot."""
    def __init__(self, config):
        self.query_count = 0
        self.config = config
        logger.info("Initialized HoneyResolver for domain", extra={'domain': self.config['HONEYPOT_DOMAIN']})
        DNS_RESOLVER_STATUS.set(1) # Set status to running

    def get_response_ip(self, subdomain):
        """Determine which IP to return for a given subdomain."""
        subdomain_lower = subdomain.lower()
        
        if subdomain_lower in self.config["REAL_SUBDOMAINS"]:
            return self.config["REAL_SUBDOMAINS"][subdomain_lower], "real"
        
        if subdomain_lower in self.config["FAKE_SUBDOMAINS"]:
            return self.config["FAKE_SUBDOMAINS"][subdomain_lower], "fake"
        
        random_ip = f"10.0.2.{random.randint(1, 254)}"
        return random_ip, "random"
    
    def resolve(self, request, handler):
        """Main resolver function."""
        self.query_count += 1
        
        qname = str(request.q.qname)
        qtype = request.q.qtype
        
        # Sanitize qname before further processing and logging
        sanitized_qname = sanitize_log_input(qname)

        domain_suffix = f".{self.config['HONEYPOT_DOMAIN']}."
        if sanitized_qname.endswith(domain_suffix):
            subdomain = sanitized_qname[:-len(domain_suffix)]
        else:
            subdomain = sanitized_qname
        
        client_ip = handler.client_address[0]
        response_ip, category = self.get_response_ip(subdomain)
        
        # Increment Prometheus counter
        DNS_QUERIES_TOTAL.labels(qtype=QTYPE[qtype], category=category).inc()

        # Log with extra fields for JSON formatter
        logger.info("DNS Query received", extra={
            'client_ip': client_ip,
            'qname': sanitized_qname,
            'qtype': QTYPE[qtype],
            'response_ip': response_ip,
            'category': category
        })
        
        reply = request.reply()
        
        if qtype == QTYPE.A:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=300, rdata=A(response_ip)))
        elif qtype == QTYPE.AAAA:
            fake_ipv6 = f"2001:db8::{random.randint(1, 65535):x}:{random.randint(1, 65535):x}"
            reply.add_answer(RR(rname=qname, rtype=QTYPE.AAAA, rclass=1, ttl=300, rdata=AAAA(fake_ipv6)))
        elif qtype == QTYPE.MX:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.MX, rclass=1, ttl=300, rdata=MX(10, f"mail.{self.config['HONEYPOT_DOMAIN']}.")))
        else:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=300, rdata=A(response_ip)))
        
        return reply

def main():
    """Main function to run the DNS honeypot."""
    logger.info("Starting Enhanced DNS HoneyResolver...")

    # Start Prometheus metrics server
    start_http_server(HEALTH_METRICS_PORT)
    logger.info(f"Prometheus metrics server running on port {HEALTH_METRICS_PORT}")

    # Start Health Check server in a separate thread
    health_thread = threading.Thread(target=run_health_server, daemon=True)
    health_thread.start()

    resolver = EnhancedHoneyResolver(CONFIG)
    server = DNSServer(resolver, port=LISTEN_PORT, address=LISTEN_ADDR)
    
    try:
        server.start() # Blocking call
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.stop()
        DNS_RESOLVER_STATUS.set(0) # Set status to stopped
        logger.info(f"Total queries handled: {resolver.query_count}")
    except Exception as e:
        logger.critical(f"An unexpected error occurred: {e}")
        DNS_RESOLVER_STATUS.set(0) # Set status to stopped
        sys.exit(1)

if __name__ == "__main__":
    main()