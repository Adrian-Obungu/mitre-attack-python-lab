import subprocess
import os
import sys
import time
import json
import requests
import signal

# --- Helper Functions ---
def run_command(command, shell=True, capture_output=True, text=True, check=False, cwd=None):
    """Helper function to run shell commands."""
    try:
        process = subprocess.run(
            command,
            shell=shell,
            capture_output=capture_output,
            text=text,
            check=check,
            cwd=cwd
        )
        return process
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        raise

def start_background_process(command, cwd=None, env=None):
    """Starts a process in the background and returns the process object."""
    print(f"Starting background process: {command}")
    # Important: if running a shell script, it needs to be executable
    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env
    )
    time.sleep(5) # Give process time to start
    return process

def terminate_process(process, name="process"):
    """Terminates a background process."""
    print(f"Terminating {name} (PID: {process.pid})...")
    if process:
        try:
            # Send SIGTERM for graceful shutdown
            os.kill(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
            print(f"{name} terminated gracefully.")
        except (ProcessLookupError, subprocess.TimeoutExpired):
            # If SIGTERM fails or times out, force kill
            print(f"Force killing {name} (PID: {process.pid})...")
            os.kill(process.pid, signal.SIGKILL)
            process.wait()
            print(f"{name} force killed.")
    print(f"{name} termination attempt complete.")

# --- Validation Tests ---

def check_log_parser_help():
    """Validates `log_parser.py --help` runs without errors."""
    print("\n--- 1. log_parser.py --help Test ---")
    print("Running 'python src/utils/log_parser.py --help'...")
    
    # We assume setup_foundation.sh has been run, so 'python' command refers to venv python.
    # The sys.path adjustment is now handled internally by log_parser.py if run as __main__.
    
    result = run_command("python src/utils/log_parser.py --help")
    if result.returncode == 0 and "usage: log_parser.py" in result.stdout:
        print("✅ 'log_parser.py --help' works without ModuleNotFoundError.")
    else:
        print(f"❌ 'log_parser.py --help' failed. Stderr: {result.stderr.strip()}")
        sys.exit(1)

def test_api_scanner_endpoint():
    """Tests if the API server starts and the scanner endpoint works."""
    print("\n--- 2. API Scanner Endpoint Test ---")
    print("Starting API server in background...")

    # Load .env variables for the subprocess, as uvicorn might not pick them up from shell env
    current_env = os.environ.copy()
    env_file_path = os.path.join(os.getcwd(), ".env")
    if os.path.exists(env_file_path):
        with open(env_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    current_env[key] = value
        print("Loaded .env variables for API server.")
    else:
        print("Warning: .env file not found. API authentication might fail if API_KEY is not set globally.")

    api_process = start_background_process(
        "python -m uvicorn src.api_server:app --port 8080",
        env=current_env
    )

    try:
        print("Triggering scanner endpoint...")
        headers = {"X-API-Key": current_env.get("API_KEY", "test-key-123")} # Use the API_KEY from .env
        scan_payload = {
            "target": "scanme.nmap.org",
            "ports": "80,443",
            "scan_type": "connect"
        }
        response = requests.post("http://localhost:8080/scan", headers=headers, json=scan_payload)
        
        if response.status_code == 200 and "Port scan initiated successfully" in response.json().get("message", ""):
            print(f"✅ API scanner endpoint works: {response.status_code} {response.json().get('message')}")
        else:
            print(f"❌ API scanner endpoint failed. Status: {response.status_code}, Response: {response.text}")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to API server. Is it running?")
        sys.exit(1)
    finally:
        terminate_process(api_process, "API server")

def test_core_modules_imports():
    """Tests if core modules (DNS, TCP, Persistence) can be imported successfully."""
    print("\n--- 3. Core Modules Import Test ---")
    project_root = os.getcwd()
    # Temporarily add project root to sys.path for these imports
    # This is mainly for testing if running this script directly
    # In normal venv operation, these should work after `setup_foundation.sh`
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    modules_to_test = [
        "src.reconnaissance.dns_recon",
        "src.reconnaissance.tcp_connect_scan",
        "src.persistence.persistence_auditor",
        "src.defense.HoneyResolver_Enhanced",
        "src.api_server", # Included as it's a core orchestrator
        "src.utils.log_parser", # Already tested with --help but good to import
    ]

    for module_name in modules_to_test:
        try:
            __import__(module_name)
            print(f"✅ Module '{module_name}' imported successfully.")
        except ImportError as e:
            print(f"❌ Module '{module_name}' import failed: {e}")
            sys.exit(1)

def test_honeyresolver_ports_again():
    """Tests HoneyResolver health (8000) and Prometheus (8001) are separate and working."""
    print("\n--- 4. HoneyResolver Port Conflict Test (Foundation) ---")
    print("Starting HoneyResolver (temp instance) in background...")

    # Ensure to use the python from the venv
    # We must ensure the .env is loaded for HONEYPOT_CONFIG which may contain HEALTH_METRICS_PORT
    current_env = os.environ.copy()
    env_file_path = os.path.join(os.getcwd(), ".env")
    if os.path.exists(env_file_path):
        with open(env_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    current_env[key] = value
        print("Loaded .env variables for HoneyResolver.")
    else:
        print("Warning: .env file not found. HoneyResolver might use default config values.")


    honeyresolver_process = start_background_process(
        "python src/defense/HoneyResolver_Enhanced.py --domain test.local --port 53535",
        env=current_env
    )

    try:
        print("Checking health endpoint on port 8000...")
        health_response = requests.get("http://localhost:8000/health")
        if health_response.status_code == 200 and "ok" in health_response.json().get("status", ""):
            print(f"✅ HoneyResolver health check on port 8000 successful.")
        else:
            print(f"❌ HoneyResolver health check on port 8000 failed. Status: {health_response.status_code}, Response: {health_response.text}")
            sys.exit(1)

        print("Checking Prometheus metrics endpoint on port 8001...")
        metrics_response = requests.get("http://localhost:8001/metrics")
        if metrics_response.status_code == 200 and "prometheus" in metrics_response.text:
            print(f"✅ Prometheus metrics on port 8001 successful.")
        else:
            print(f"❌ Prometheus metrics on port 8001 failed. Status: {metrics_response.status_code}, Response: {metrics_response.text}")
            sys.exit(1)

    except requests.exceptions.ConnectionError as e:
        print(f"❌ Could not connect to HoneyResolver endpoints: {e}")
        sys.exit(1)
    finally:
        terminate_process(honeyresolver_process, "HoneyResolver")

def test_git_status_clean():
    """Checks if the Git working tree is clean, ignoring expected untracked files."""
    print("\n--- 5. Git Status Clean Test ---")
    print("Checking 'git status --short'...")

    # We expect .env, venv/, logs/, *.log files to be ignored.
    # The .gitignore should handle this.
    result = run_command("git status --short")

    if not result.stdout.strip():
        print("✅ Git working tree is clean.")
    else:
        # Check if remaining untracked files are expected and not an issue
        # This part might need refinement if there are other intentional untracked files.
        # For now, we will pass if only expected ignored files are present.
        untracked_lines = [line for line in result.stdout.splitlines() if line.startswith('??')]
        expected_untracked = ['?? .env', '?? logs/', '?? venv/', '?? *.log'] # These are patterns, not exact matches.

        # A more robust check would parse .gitignore and then git status.
        # For simplicity, if anything other than these common ignores are present, it's a fail.
        # Assuming .gitignore now covers .env, venv/, logs/, and *.log
        # So a "clean" status is expected. If anything is untracked, it's an issue.

        if any(line.strip().startswith('??') for line in result.stdout.splitlines()):
            print("❌ Git working tree is NOT clean. Untracked/modified files found:")
            print(result.stdout)
            print("Please ensure your .gitignore is comprehensive.")
            sys.exit(1)
        else:
            print("✅ Git working tree is clean (no unexpected untracked/modified files).")


if __name__ == "__main__":
    print("--- Starting Validation of Foundation Fixes ---")
    # This script assumes 'setup_foundation.sh' has been run successfully.
    # The 'python' command should now resolve to the venv python.
    
    # Ensure all necessary scripts are executable
    os.chmod("setup_foundation.sh", 0o755)
    os.chmod("validate_foundation.py", 0o755) # Ensure this script itself is executable
    
    check_log_parser_help()
    test_api_scanner_endpoint()
    test_core_modules_imports()
    test_honeyresolver_ports_again()
    test_git_status_clean()
    print("\n--- All Foundation Fixes Validated Successfully! ---")
    sys.exit(0)
