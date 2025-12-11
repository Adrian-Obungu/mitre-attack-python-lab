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
