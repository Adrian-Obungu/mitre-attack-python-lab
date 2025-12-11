import cProfile
import pstats
import sys
import os

# Add src to path to allow for module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

def run_honeypot_for_profiling():
    """
    Runs the honeypot's main function.
    This is the target for our CPU profiler.
    """
    try:
        from defense.HoneyResolver_Enhanced import main as honeypot_main
        print("Starting HoneyResolver for CPU profiling...")
        print("Run the DNS load test against this server now.")
        print("Press Ctrl+C to stop profiling and save the results.")
        honeypot_main()
    except Exception as e:
        print(f"Failed to start honeypot: {e}")

def main():
    """
    Main function to set up and run the CPU profiler.
    """
    output_file = "profile_output.pstats"
    
    profiler = cProfile.Profile()
    
    try:
        profiler.enable()
        
        run_honeypot_for_profiling()
        
    except KeyboardInterrupt:
        print("\nStopping profiler and saving data...")
    finally:
        profiler.disable()
        
        # Save the profiling stats
        stats = pstats.Stats(profiler).sort_stats('cumulative')
        stats.dump_stats(output_file)
        
        print(f"\nProfiling data saved to {output_file}")
        print("To analyze the results, start a Python interpreter and run:")
        print("import pstats")
        print(f"p = pstats.Stats('{output_file}')")
        print("p.sort_stats('cumulative').print_stats(20)")

if __name__ == "__main__":
    main()
