import json
import os
import subprocess
import time
import requests

RESULTS = []

def run_dns_recon(timeout=30):
    """Stage 1: DNS Reconnaissance"""
    print("Running Stage 1: DNS Reconnaissance...")
    start_time = time.time()
    try:
        result = subprocess.run(
            [
                'python',
                'src/reconnaissance/dns_recon.py',
                '-d', 'github.com',
                '-w', 'config/common_subdomains.txt',
                '--timeout', '5',
                '--limit', '10'
            ],
            timeout=timeout,
            capture_output=True,
            text=True,
            check=True
        )
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "DNS Reconnaissance",
            "technique": "T1583.001",
            "status": "success",
            "duration": duration,
            "details": f"DNS recon completed in {duration:.2f} seconds."
        })
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "DNS Reconnaissance",
            "technique": "T1583.001",
            "status": "failure",
            "duration": duration,
            "details": "DNS recon timed out."
        })
    except subprocess.CalledProcessError as e:
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "DNS Reconnaissance",
            "technique": "T1583.001",
            "status": "failure",
            "duration": duration,
            "details": f"DNS recon failed with error: {e.stderr}"
        })

def run_persistence_audit(timeout=30):
    """Stage 2: Persistence Audit"""
    print("Running Stage 2: Persistence Audit...")
    start_time = time.time()
    try:
        result = subprocess.run(
            ['python', '-c', 'from src.persistence.persistence_auditor import PersistenceAuditor; a=PersistenceAuditor(); print(a.audit())'],
            timeout=timeout,
            capture_output=True,
            text=True,
            check=True
        )
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "Persistence Audit",
            "technique": "T1547.001",
            "status": "success",
            "duration": duration,
            "details": "Persistence audit completed."
        })
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "Persistence Audit",
            "technique": "T1547.001",
            "status": "failure",
            "duration": duration,
            "details": "Persistence audit timed out."
        })
    except subprocess.CalledProcessError as e:
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "Persistence Audit",
            "technique": "T1547.001",
            "status": "failure",
            "duration": duration,
            "details": f"Persistence audit failed with error: {e.stderr}"
        })

def run_privilege_audit(timeout=30):
    """Stage 3: Privilege Audit"""
    print("Running Stage 3: Privilege Audit...")
    start_time = time.time()
    try:
        result = subprocess.run(
            ['python', '-c', 'from src.privilege.privilege_auditor import PrivilegeAuditor; a=PrivilegeAuditor(); print(a.run_all_checks())'],
            timeout=timeout,
            capture_output=True,
            text=True,
            check=True
        )
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "Privilege Audit",
            "technique": "T1037",
            "status": "success",
            "duration": duration,
            "details": "Privilege audit completed."
        })
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "Privilege Audit",
            "technique": "T1037",
            "status": "failure",
            "duration": duration,
            "details": "Privilege audit timed out."
        })
    except subprocess.CalledProcessError as e:
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "Privilege Audit",
            "technique": "T1037",
            "status": "failure",
            "duration": duration,
            "details": f"Privilege audit failed with error: {e.stderr}"
        })

def run_defense_evasion(timeout=30):
    """Stage 4: Defense Evasion"""
    print("Running Stage 4: Defense Evasion...")
    start_time = time.time()
    dummy_file_path = os.path.join("uploads", "dummy_script.py")
    try:
        # Create a dummy file in the uploads directory
        os.makedirs("uploads", exist_ok=True)
        with open(dummy_file_path, "w") as f:
            f.write("import os\nos.system('echo Hello')")
        
        payload = {"file_path": dummy_file_path}
        response = requests.post("http://127.0.0.1:8000/api/v1/analyze/obfuscation/", json=payload, timeout=timeout)
        response.raise_for_status()

        duration = time.time() - start_time
        RESULTS.append({
            "stage": "Defense Evasion",
            "technique": "T1027",
            "status": "success",
            "duration": duration,
            "details": "Defense evasion check completed."
        })
    except requests.exceptions.RequestException as e:
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "Defense Evasion",
            "technique": "T1027",
            "status": "failure",
            "duration": duration,
            "details": f"Defense evasion check failed: {e}"
        })
    finally:
        if os.path.exists(dummy_file_path):
            os.remove(dummy_file_path)

def run_indicator_removal(timeout=30):
    """Stage 5: Indicator Removal"""
    print("Running Stage 5: Indicator Removal...")
    start_time = time.time()
    log_file = "dummy_log.log"
    try:
        # Create a dummy log file
        with open(log_file, "w") as f:
            f.write("This is a log file.\n")
        
        baseline_size = os.path.getsize(log_file)
        
        # Clear the log file
        with open(log_file, "w") as f:
            f.write("")
        
        result = subprocess.run(
            ['python', '-c', f'import json; from src.defense_evasion.indicator_removal_detector import T1070IndicatorRemovalDetector; from pathlib import Path; d=T1070IndicatorRemovalDetector(); print(json.dumps(d.monitor_log_clearing(Path("{log_file}"), {baseline_size})))'],
            timeout=timeout,
            capture_output=True,
            text=True,
            check=True
        )

        output = json.loads(result.stdout)
        duration = time.time() - start_time

        if output.get("is_cleared_or_truncated"):
            RESULTS.append({
                "stage": "Indicator Removal",
                "technique": "T1070",
                "status": "success",
                "duration": duration,
                "details": "Indicator removal (log clearing) detected."
            })
        else:
            RESULTS.append({
                "stage": "Indicator Removal",
                "technique": "T1070",
                "status": "failure",
                "duration": duration,
                "details": "Indicator removal (log clearing) not detected."
            })

    except Exception as e:
        duration = time.time() - start_time
        RESULTS.append({
            "stage": "Indicator Removal",
            "technique": "T1070",
            "status": "failure",
            "duration": duration,
            "details": f"Indicator removal check failed: {e}"
        })
    finally:
        if os.path.exists(log_file):
            os.remove(log_file)


if __name__ == "__main__":
    run_dns_recon()
    run_persistence_audit()
    run_privilege_audit()
    run_defense_evasion()
    run_indicator_removal()
    
    print(json.dumps(RESULTS, indent=4))
