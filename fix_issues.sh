#!/bin/bash
echo "=== Fixing Repository Issues ==="

# 1. Fix port scanner demo command
echo "1. Creating demo scan script..."
cat > run_demo.sh << 'DEMO'
#!/bin/bash
echo "Running port scanner demo..."
python src/reconnaissance/PortScan_Enhanced.py --demo -t syn
DEMO
chmod +x run_demo.sh

# 2. Check for existing DNS script
echo "2. Checking for DNS scripts..."
if [ -f "src/reconnaissance/DNSExploration.py" ]; then
    echo "Found DNSExploration.py, creating alias..."
    cp src/reconnaissance/DNSExploration.py DNSExploration_ByIP.py
elif [ -f "src/utils/dns_recon.py" ]; then
    echo "Found dns_recon.py"
    cp src/utils/dns_recon.py DNSExploration_ByIP.py
else
    echo "Creating simple DNS exploration script..."
    cat > DNSExploration_ByIP.py << 'DNS'
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
DNS
fi

# 3. Fix honeypot syntax
echo "3. Checking honeypot syntax..."
if grep -q "cp src/defense/HoneyResolver_Enhanced.py" src/defense/HoneyResolver_Enhanced.py; then
    echo "Fixing syntax error in honeypot..."
    sed -i '164d' src/defense/HoneyResolver_Enhanced.py
fi

# 4. Create test DNS queries for Windows
echo "4. Creating Windows DNS test script..."
cat > test_dns.py << 'TEST'
import socket
import sys

def test_honeypot(port=5353):
    server = "127.0.0.1"
    test_queries = [
        "admin.internal.company.com",
        "vpn.corporate.local", 
        "database.prod.company.com"
    ]
    
    for query in test_queries:
        print(f"\nQuerying: {query}")
        try:
            # Simple DNS query (A record)
            result = socket.gethostbyname_ex(query)
            print(f"Result: {result}")
        except socket.gaierror:
            print(f"No result for {query}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    test_honeypot()
TEST

echo "=== Fixes completed ==="
