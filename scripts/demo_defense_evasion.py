import argparse
import json
import time
import os
import platform
import tempfile
import shutil
from pathlib import Path
import random
import string
import sys

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Mitre Attack Detectors
from src.defense_evasion.defense_impairment_detector import T1562DefenseImpairmentDetector
from src.defense_evasion.elevation_detector import T1548ElevationDetector
from src.defense_evasion.indicator_removal_detector import T1070IndicatorRemovalDetector
from src.defense_evasion.obfuscation_detector import T1027ObfuscationDetector
from src.defense_evasion.registry_monitor import T1112RegistryMonitor

def run_t1562_demo(temp_dir):
    """Demonstrates T1562 Defense Impairment Detection."""
    print("[*] Running T1562 Defense Impairment Demo...")
    detector = T1562DefenseImpairmentDetector()
    
    # Simulate tool tampering: large hosts file
    fake_hosts_path = temp_dir / "hosts"
    with open(fake_hosts_path, "w") as f:
        f.write("# This is a fake hosts file.\n" * 2000)
    
    # Simulate log file missing
    fake_log_path = temp_dir / "security.evtx"
    
    results = detector.run_checks()

    # Manually add our simulated findings for demonstration purposes
    results["tampering_indicators"].append({
        "indicator": "hosts_file_large",
        "details": f"The hosts file at {fake_hosts_path} is larger than 10KB, which might indicate tampering."
    })
    results["log_issues"].append({
        "indicator": "log_file_missing",
        "details": f"Key security log file is missing: {fake_log_path}"
    })

    print("[+] T1562 Demo Complete.")
    return results


def run_t1548_demo():
    """Demonstrates T1548 Elevation Detection."""
    print("[*] Running T1548 Elevation Detection Demo...")
    detector = T1548ElevationDetector()
    results = detector.run_checks()
    print("[+] T1548 Demo Complete.")
    return results

def run_t1070_demo(temp_dir):
    """Demonstrates T1070 Indicator Removal Detection."""
    print("[*] Running T1070 Indicator Removal Demo...")
    detector = T1070IndicatorRemovalDetector()
    results = {"log_clearing": [], "rapid_deletion": []}

    # 1. Log Clearing Demo
    log_file = temp_dir / "app.log"
    with open(log_file, "w") as f:
        f.write("Initial log entry.\n" * 10)
    baseline_size = log_file.stat().st_size

    with open(log_file, "w") as f:
        f.write("Log was cleared.\n")
    
    results["log_clearing"].append(detector.monitor_log_clearing(log_file, baseline_size))

    # 2. Rapid Deletion Demo
    deletion_dir = temp_dir / "sensitive_logs"
    deletion_dir.mkdir()
    for i in range(5):
        with open(deletion_dir / f"log_{i}.txt", "w") as f:
            f.write("secret data")
    
    # Initial scan to establish baseline
    detector.detect_rapid_deletions(deletion_dir) 
    time.sleep(1)

    for i in range(5):
        (deletion_dir / f"log_{i}.txt").unlink()

    results["rapid_deletion"].extend(detector.detect_rapid_deletions(deletion_dir))
    
    print("[+] T1070 Demo Complete.")
    return results

def run_t1027_demo(temp_dir):
    """Demonstrates T1027 Obfuscation Detection."""
    print("[*] Running T1027 Obfuscation Detection Demo...")
    detector = T1027ObfuscationDetector()
    results = []

    # 1. High Entropy File
    entropy_file = temp_dir / "packed.bin"
    random_data = os.urandom(1024)
    with open(entropy_file, "wb") as f:
        f.write(random_data)
    results.append(detector.analyze_file(entropy_file))

    # 2. Packer Signature File
    packer_file = temp_dir / "upx_packed.exe"
    with open(packer_file, "wb") as f:
        f.write(b"UPX!" + b"\x00" * 100)
    results.append(detector.analyze_file(packer_file))

    print("[+] T1027 Demo Complete.")
    return results

def run_t1112_demo():
    """Demonstrates T1112 Registry Monitoring."""
    print("[*] Running T1112 Registry Monitoring Demo...")
    if platform.system() != "Windows":
        print("[-] T1112 demo skipped (Windows only).")
        return {"status": "skipped", "reason": "Windows only"}

    detector = T1112RegistryMonitor()
    
    baseline_path = "registry_baseline.json"
    if not os.path.exists(baseline_path):
         print(f"[-] Baseline file {baseline_path} not found. Skipping comparison.")
         return {"status": "skipped", "reason": "Baseline file not found."}

    loaded_data = detector.load_snapshot(baseline_path)
    if not loaded_data:
        return {"status": "error", "reason": "Failed to load baseline snapshot."}

    current_snapshot = detector.create_registry_snapshot(loaded_data["keys"])
    changes = detector.compare_registry_snapshot(loaded_data["snapshot"], current_snapshot)
    
    print("[+] T1112 Demo Complete.")
    return {"changes_detected": changes}


def main(args):
    """
    Main function to run the defense evasion demo.
    """
    if not os.path.exists('reports'):
        os.makedirs('reports')
        
    demo_results = {}
    performance_metrics = {}
    
    # Create a temporary directory for the demo
    temp_dir = Path(tempfile.mkdtemp(prefix="def_evasion_demo_"))
    print(f"[*] Created temporary directory for demo: {temp_dir}")

    try:
        # --- T1562 Demo ---
        start_time = time.time()
        demo_results["T1562_Defense_Impairment"] = run_t1562_demo(temp_dir)
        performance_metrics["T1562"] = time.time() - start_time
        
        # --- T1548 Demo ---
        start_time = time.time()
        demo_results["T1548_Elevation_Abuse"] = run_t1548_demo()
        performance_metrics["T1548"] = time.time() - start_time

        # --- T1070 Demo ---
        start_time = time.time()
        demo_results["T1070_Indicator_Removal"] = run_t1070_demo(temp_dir)
        performance_metrics["T1070"] = time.time() - start_time

        # --- T1027 Demo ---
        start_time = time.time()
        demo_results["T1027_Obfuscation"] = run_t1027_demo(temp_dir)
        performance_metrics["T1027"] = time.time() - start_time
        
        # --- T1112 Demo ---
        start_time = time.time()
        demo_results["T1112_Registry_Modification"] = run_t1112_demo()
        performance_metrics["T1112"] = time.time() - start_time


        # --- Generate Report ---
        print("\n" + "="*50)
        print("          Defense Evasion Demo Report")
        print("="*50)

        for technique, result in demo_results.items():
            print(f"\n--- {technique} ---")
            print(json.dumps(result, indent=2))
        
        print("\n--- Performance Metrics ---")
        for technique, duration in performance_metrics.items():
            print(f"{technique}: {duration:.4f} seconds")

        # --- Export to JSON ---
        output_path = os.path.join('reports', args.output_json)
        
        report = {
            "summary": "Defense Evasion Techniques Demo",
            "timestamp": time.time(),
            "results": demo_results,
            "performance_metrics": performance_metrics,
        }
        
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4)
        
        print(f"\n[+] Full report saved to {output_path}")

    finally:
        # --- Cleanup ---
        print(f"[*] Cleaning up temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run a demonstration of all Defense Evasion detectors."
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default="defense_evasion_report.json",
        help="Path to save the JSON report.",
    )
    parser.add_argument(
        "--mode",
        choices=["all", "quick", "custom"],
        default="all",
        help="Demo mode: 'all' runs all checks, 'quick' runs a subset, 'custom' allows specifying checks.",
    )

    args = parser.parse_args()
    main(args)
