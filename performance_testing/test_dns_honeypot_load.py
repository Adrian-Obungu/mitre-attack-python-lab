
import argparse
import time
import socket
import threading
import random
import json
import os

def load_honeypot_config():
    """Loads the honeypot configuration to generate relevant queries."""
    try:
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'honeypot_config.json')
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading honeypot configuration: {e}")
        return None

def dns_query_worker(target_ip, port, domain, subdomains, qtypes, stop_event):
    """Worker thread that sends DNS queries repeatedly."""
    resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while not stop_event.is_set():
        try:
            sub = random.choice(subdomains)
            qtype = random.choice(qtypes)
            qname = f"{sub}.{domain}"
            
            # Simple manual DNS query construction
            trans_id = os.urandom(2)
            flags = b'\x01\x00'  # Standard query
            qdcount = b'\x00\x01' # One question
            ancount = b'\x00\x00'
            nscount = b'\x00\x00'
            arcount = b'\x00\x00'
            
            q_parts = qname.split('.')
            q_bytes = b''.join(len(part).to_bytes(1, 'big') + part.encode('utf-8') for part in q_parts) + b'\x00'
            
            qtype_map = {'A': 1, 'AAAA': 28, 'MX': 15}
            qtype_bytes = qtype_map.get(qtype, 1).to_bytes(2, 'big')
            qclass = b'\x00\x01' # IN class
            
            query = trans_id + flags + qdcount + ancount + nscount + arcount + q_bytes + qtype_bytes + qclass
            
            resolver.sendto(query, (target_ip, port))
            # In a real load test, we'd also process the response.
            # For just generating load, we can ignore it.
            
        except Exception as e:
            # This might get noisy if the server is down
            # print(f"Worker error: {e}")
            pass

def main():
    parser = argparse.ArgumentParser(description="DNS Honeypot Load Generator")
    parser.add_argument("--target", default="127.0.0.1", help="The IP address of the DNS honeypot server.")
    parser.add_argument("--port", type=int, default=8053, help="The port of the DNS honeypot server.")
    parser.add_argument("--qps", type=int, default=100, help="Target Queries Per Second.")
    parser.add_argument("--duration", type=int, default=10, help="Duration of the test in seconds.")
    
    args = parser.parse_args()

    config = load_honeypot_config()
    if not config:
        return

    domain = config["HONEYPOT_DOMAIN"]
    real_subs = list(config["REAL_SUBDOMAINS"].keys())
    fake_subs = list(config["FAKE_SUBDOMAINS"].keys())
    # Add some random subdomains to the mix
    random_subs = [f"test{i}" for i in range(10)]
    all_subdomains = real_subs + fake_subs + random_subs
    
    qtypes = ['A', 'AAAA', 'MX']

    print(f"Starting DNS load test on {args.target}:{args.port}...")
    print(f"Targeting ~{args.qps} QPS for {args.duration} seconds.")

    stop_event = threading.Event()
    threads = []
    
    # We need to determine how many threads we need. This is not an exact science.
    # Let's assume a simple model where each thread can generate X queries per second.
    # For this demo, let's just use a fixed number of threads as a proxy for QPS.
    # A more advanced tool would dynamically adjust.
    num_threads = max(1, int(args.qps / 10)) # Heuristic: 1 thread per 10 QPS
    
    start_time = time.time()

    for _ in range(num_threads):
        thread = threading.Thread(target=dns_query_worker, args=(args.target, args.port, domain, all_subdomains, qtypes, stop_event))
        thread.start()
        threads.append(thread)
    
    time.sleep(args.duration)
    stop_event.set()

    for thread in threads:
        thread.join()

    end_time = time.time()
    
    # This is a very rough estimate. A real tool would count sent/received packets.
    # The actual QPS depends heavily on network and system performance.
    # We are calculating based on the target QPS and duration.
    total_queries_sent_estimate = args.qps * args.duration
    actual_duration = end_time - start_time
    
    print("\n--- Load Test Summary ---")
    print(f"Test Duration: {actual_duration:.2f} seconds")
    print(f"Target QPS: {args.qps}")
    print(f"Threads: {num_threads}")
    print(f"Estimated Total Queries: {total_queries_sent_estimate}")
    print("-------------------------\n")


if __name__ == "__main__":
    main()
