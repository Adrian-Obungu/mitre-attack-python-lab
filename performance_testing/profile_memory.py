
import argparse
import sys
import os
import time
from memory_profiler import memory_usage
import multiprocessing

# Add src to path to allow for module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

def run_honeypot():
    """Wrapper to run the honeypot's main function."""
    try:
        from defense.HoneyResolver_Enhanced import main as honeypot_main
        print("Starting HoneyResolver for memory profiling...")
        honeypot_main()
    except Exception as e:
        print(f"Failed to start honeypot: {e}")

def main():
    parser = argparse.ArgumentParser(description="Memory Profiler for the DNS Honeypot")
    parser.add_argument("--duration", type=int, default=60, help="Duration to run the test in seconds.")
    parser.add_argument("--interval", type=int, default=1, help="Interval between memory samples in seconds.")
    parser.add_argument("--output", default="memory_usage.dat", help="Output file for memory usage data.")
    
    args = parser.parse_args()

    print(f"Starting memory profiling for {args.duration} seconds...")
    
    # Run the honeypot in a separate process
    honeypot_process = multiprocessing.Process(target=run_honeypot)
    honeypot_process.start()

    # Monitor the memory usage of the honeypot process
    try:
        # Use memory_usage to track the process
        # The timeout is set for the total duration of the monitoring
        mem_usage = memory_usage(
            (honeypot_process.pid,),
            interval=args.interval,
            timeout=args.duration,
            retval=True,  # Return the memory usage data
            multiprocess=True, # To track child processes
            include_children=True
        )

    finally:
        # Ensure the honeypot process is terminated
        if honeypot_process.is_alive():
            print("Terminating honeypot process...")
            honeypot_process.terminate()
            honeypot_process.join(timeout=5)
            if honeypot_process.is_alive():
                honeypot_process.kill()


    if not mem_usage:
        print("Could not gather memory usage. The process might have terminated early.")
        return

    # mem_usage might be a tuple (memory_data, return_value_of_process)
    # We are interested in the first part if retval=True
    if isinstance(mem_usage, tuple):
        mem_data = mem_usage[0]
    else: # Or it might just be the list of memory samples
        mem_data = mem_usage
        
    # Save the results to a file
    with open(args.output, 'w') as f:
        f.write("# Time (s), Memory (MB)\n")
        for i, mem in enumerate(mem_data):
            f.write(f"{i * args.interval}, {mem}\n")

    print(f"\nMemory profiling complete. Data saved to {args.output}")
    print("You can now plot the results using: python performance_testing/plot_results.py")

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
