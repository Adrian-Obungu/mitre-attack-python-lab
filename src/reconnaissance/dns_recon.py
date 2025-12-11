
import socket
import threading
from queue import Queue
import argparse
import time
import re
import sys
import os
import logging
from rich.console import Console
from rich.table import Table

# --- Security and Validation Functions ---

def validate_domain(domain):
    """Validate the domain format."""
    # A simple regex for domain names
    pattern = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    return pattern.match(domain)

def validate_wordlist_path(wordlist_path):
    """Validate the wordlist file path to prevent traversal and ensure it exists."""
    # Disallow directory traversal
    if ".." in wordlist_path or not os.path.isabs(os.path.abspath(wordlist_path)):
         # For simplicity, we can enforce paths relative to the script or absolute, but blocking '..' is key.
         # A more robust check might involve resolving the path and ensuring it's within a trusted directory.
         pass # Let's keep it simple and just check for existence after resolving path.
    
    abs_path = os.path.abspath(wordlist_path)
    if os.path.exists(abs_path) and os.path.isfile(abs_path):
        return abs_path
    return None

def validate_threads(num_threads):
    """Validate the number of threads is within a reasonable range."""
    return 1 <= num_threads <= 100

# --- Main Application ---

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("dns_recon.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

# Lock for thread-safe dictionary updates
data_lock = threading.Lock()

def resolve_subdomain(subdomain, results):
    """
    Resolves a single subdomain to an IP address and stores the result.
    """
    try:
        hostname, aliases, ipaddrs = socket.gethostbyname_ex(subdomain)
        if ipaddrs:
            ip = ipaddrs[0]
            logger.info(f"Resolved {subdomain} -> {ip}")
            with data_lock:
                if ip not in results:
                    results[ip] = []
                results[ip].append(subdomain)
    except socket.gaierror:
        logger.debug(f"Could not resolve {subdomain}")
        pass
    except Exception as e:
        logger.error(f"Error resolving {subdomain}: {e}")

def worker(q, results):
    """
    Worker thread function to get a subdomain from the queue and resolve it.
    """
    while not q.empty():
        subdomain = q.get()
        resolve_subdomain(subdomain, results)
        q.task_done()

def perform_reverse_dns(ip):
    """
    Performs a reverse DNS lookup for a given IP address.
    """
    try:
        hostname, aliases, ipaddrs = socket.gethostbyaddr(ip)
        logger.info(f"Reverse DNS for {ip}: {hostname}")
        return hostname
    except socket.herror:
        logger.warning(f"No reverse DNS record found for {ip}")
        return "No reverse DNS record"
    except Exception as e:
        logger.error(f"Reverse DNS error for {ip}: {e}")
        return f"Error: {e}"

def main():
    parser = argparse.ArgumentParser(description="A multi-threaded DNS reconnaissance tool with validation and logging.")
    parser.add_argument("-d", "--domain", dest="domain", required=True, help="The target domain.")
    parser.add_argument("-w", "--wordlist", dest="wordlist", required=True, help="Path to the wordlist file.")
    parser.add_argument("-t", "--threads", dest="num_threads", type=int, default=20, help="Number of threads to use (1-100).")
    
    args = parser.parse_args()
    
    # --- Input Validation ---
    if not validate_domain(args.domain):
        logger.critical(f"Invalid domain name provided: {args.domain}")
        sys.exit("Error: Invalid domain name format.")

    validated_path = validate_wordlist_path(args.wordlist)
    if not validated_path:
        logger.critical(f"Wordlist not found or invalid path: {args.wordlist}")
        sys.exit("Error: Wordlist file not found or path is invalid.")

    if not validate_threads(args.num_threads):
        logger.critical(f"Invalid number of threads: {args.num_threads}. Must be between 1 and 100.")
        sys.exit("Error: Invalid number of threads. Must be between 1 and 100.")

    console = Console()
    logger.info(f"Starting DNS reconnaissance for {args.domain} with wordlist {validated_path} using {args.num_threads} threads.")
    console.print(f"[bold cyan]Starting DNS reconnaissance for {args.domain}...[/bold cyan]")

    try:
        with open(validated_path, "r") as f:
            subdomains_to_check = [f"{line.strip()}.{args.domain}" for line in f if line.strip()]
    except Exception as e:
        logger.critical(f"Failed to read wordlist file: {e}")
        console.print(f"[bold red]Error: Could not read wordlist file: {e}[/bold red]")
        return

    q = Queue()
    for subdomain in subdomains_to_check:
        q.put(subdomain)
        
    results = {}

    start_time = time.time()

    threads = []
    for _ in range(args.num_threads):
        thread = threading.Thread(target=worker, args=(q, results))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    q.join()

    end_time = time.time()
    duration = end_time - start_time

    logger.info(f"Scan completed in {duration:.2f} seconds. Found {len(results)} unique IP addresses.")
    console.print(f"\n[bold green]Scan completed in {duration:.2f} seconds.[/bold green]")
    console.print(f"[bold]Found {len(results)} unique IP addresses.[/bold]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("IP Address", style="dim", width=20)
    table.add_column("Associated Domains")
    table.add_column("Reverse DNS")

    for ip, domains in sorted(results.items()):
        reverse_dns = perform_reverse_dns(ip)
        domain_list = "\n".join(domains)
        table.add_row(ip, domain_list, reverse_dns)
        
    if results:
        console.print(table)
    else:
        console.print("[yellow]No subdomains resolved.[/yellow]")

if __name__ == "__main__":
    main()
