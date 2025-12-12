
import socket
import threading
from queue import Queue
import argparse
import time
import re
import sys
import logging

# --- Security and Validation Functions ---

from typing import List, Optional

def validate_target(target):
    """Validate the target to be a valid IP address or hostname."""
    # Regex for a valid hostname (allows for subdomains) or an IPv4 address
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    hostname_pattern = re.compile(r"^[a-zA-Z0-9.-]+$")
    if ip_pattern.match(target) or hostname_pattern.match(target):
        return True
    return False

def validate_and_parse_ports(ports_str: str) -> Optional[List[int]]:
    """
    Parses a flexible port string and validates port numbers.
    Handles single ports ("22"), ranges ("1-100"), comma-separated lists ("80,443"),
    and mixed formats ("22,80-82,443").
    Returns a sorted list of unique, valid ports or None if validation fails.
    """
    ports_to_scan: set[int] = set()
    try:
        # Split by comma for lists of ports/ranges
        parts = ports_str.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                # It's a range
                start, end = map(int, part.split('-'))
                if not (1 <= start <= end <= 65535):
                    return None  # Invalid range or port number
                ports_to_scan.update(range(start, end + 1))
            else:
                # It's a single port
                port = int(part)
                if not (1 <= port <= 65535):
                    return None  # Invalid port number
                ports_to_scan.add(port)
    except ValueError:
        return None  # Happens if int() conversion fails

    if not ports_to_scan:
        return None

    return sorted(list(ports_to_scan))

def validate_threads(num_threads):
    """Validate the number of threads is within a reasonable range."""
    return 1 <= num_threads <= 100

# --- Main Application ---

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("tcp_scan.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# A print_lock is what is used to prevent concurrent printing
print_lock = threading.Lock()

def port_scanner(port, target):
    """
    Scans a single port on the target host.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        
        with print_lock:
            if result == 0:
                logger.info(f"Port {port} on {target} is Open")
                print(f"Port {port}: Open")
            else:
                # To avoid cluttering logs, we can choose not to log closed ports
                # logger.debug(f"Port {port} on {target} is Closed")
                print(f"Port {port}: Closed")

    except socket.error as e:
        with print_lock:
            logger.error(f"Port {port} on {target}: Error - {e}")
            print(f"Port {port}: Error - {e}")
    finally:
        s.close()

def worker(q, target):
    """
    Worker thread function to get a port from the queue and scan it.
    """
    while not q.empty():
        port = q.get()
        port_scanner(port, target)
        q.task_done()

def main():
    parser = argparse.ArgumentParser(description="A simple multi-threaded TCP connect scanner with input validation and logging.")
    parser.add_argument("target", nargs='?', default=None, help="The target IP address or hostname to scan.")
    parser.add_argument("-p", "--ports", dest="port_range", default="1-100", help="Port range to scan, e.g., 1-1024")
    parser.add_argument("-t", "--threads", dest="num_threads", type=int, default=10, help="Number of threads to use (1-100).")
    parser.add_argument("--demo", action="store_true", help="Run a demo scan on localhost for common ports.")
    
    args = parser.parse_args()

    if args.demo:
        target = "localhost"
        ports_to_scan = [22, 80, 443, 3306, 3389, 8080, 9090]
        logger.info(f"Running demo scan on {target} for ports: {ports_to_scan}")
        print(f"Running demo scan on {target} for ports: {ports_to_scan}")
    else:
        if not args.target:
            logger.critical("Target argument is required unless --demo is specified.")
            parser.error("The target argument is required unless --demo is specified.")
        
        # --- Input Validation ---
        if not validate_target(args.target):
            logger.critical(f"Invalid target specified: {args.target}")
            sys.exit("Error: Invalid target. Please provide a valid IP address or hostname.")

        ports_to_scan = validate_and_parse_ports(args.port_range)
        if not ports_to_scan:
            logger.critical(f"Invalid port range specified: {args.port_range}")
            sys.exit("Error: Invalid port format. Use '80', '1-1024', or '80,443,1000-2000'. Ports must be between 1 and 65535.")

        if not validate_threads(args.num_threads):
            logger.critical(f"Invalid number of threads: {args.num_threads}. Must be between 1 and 100.")
            sys.exit("Error: Invalid number of threads. Please choose a value between 1 and 100.")

        target = args.target

    logger.info(f"Starting scan on {target} for ports {args.port_range} with {args.num_threads} threads.")
    print(f"Scanning {target}...")
    
    q = Queue()
    for port in ports_to_scan:
        q.put(port)

    start_time = time.time()

    threads = []
    for _ in range(args.num_threads):
        thread = threading.Thread(target=worker, args=(q, target))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    q.join()

    end_time = time.time()
    
    duration = end_time - start_time
    logger.info(f"Scan completed in {duration:.2f} seconds.")
    print(f"\nScan completed in {duration:.2f} seconds.")

if __name__ == "__main__":
    main()
