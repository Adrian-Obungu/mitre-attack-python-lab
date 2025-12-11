
import argparse
import time
import socket
import threading
from queue import Queue
import multiprocessing

# This is a simplified version of the port scanner from tcp_connect_scan.py
# It is included here to make this script self-contained.

def port_scanner_worker(port_queue, target, results_queue):
    """Worker to scan ports from a queue."""
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                results_queue.put(port)
        except (socket.error, Queue.empty):
            continue

def main():
    parser = argparse.ArgumentParser(description="Port Scanner Load Test Utility")
    parser.add_argument("--target", required=True, help="The target IP address or hostname.")
    parser.add_argument("--ports", required=True, help="Port range to scan (e.g., 1-1024).")
    parser.add_argument("--workers", type=int, default=10, help="Number of concurrent worker processes.")
    
    args = parser.parse_args()

    print(f"Starting port scan load test on {args.target} with {args.workers} workers.")
    
    try:
        start_port, end_port = map(int, args.ports.split('-'))
        ports_to_scan = list(range(start_port, end_port + 1))
    except ValueError:
        print("Error: Invalid port range. Use format like '1-1024'.")
        return

    port_queue = multiprocessing.Queue()
    for port in ports_to_scan:
        port_queue.put(port)

    results_queue = multiprocessing.Queue()
    
    processes = []
    
    start_time = time.time()

    for _ in range(args.workers):
        process = multiprocessing.Process(target=port_scanner_worker, args=(port_queue, args.target, results_queue))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    end_time = time.time()

    open_ports = []
    while not results_queue.empty():
        open_ports.append(results_queue.get())

    duration = end_time - start_time
    ports_scanned = len(ports_to_scan)
    scans_per_second = ports_scanned / duration if duration > 0 else 0

    print("\n--- Load Test Summary ---")
    print(f"Target: {args.target}")
    print(f"Workers: {args.workers}")
    print(f"Ports Scanned: {ports_scanned}")
    print(f"Total Time: {duration:.2f} seconds")
    print(f"Scans per Second: {scans_per_second:.2f}")
    print(f"Open Ports Found: {sorted(open_ports)}")
    print("-------------------------\
")

if __name__ == "__main__":
    # This is necessary for multiprocessing on some platforms
    multiprocessing.freeze_support()
    main()
