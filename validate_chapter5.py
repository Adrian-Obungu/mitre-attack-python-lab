import subprocess
import os
import sys
import time
import json
import requests
import signal

# --- Helper Functions ---
def run_command(command, shell=True, capture_output=True, text=True, check=False, cwd=None, env=None):
    """Helper function to run shell commands."""
    try:
        process = subprocess.run(
            command,
            shell=shell,
            capture_output=capture_output,
            text=text,
            check=check,
            cwd=cwd,
            env=env
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

def test_privilege_auditor_help():
    """Validates `privilege_auditor.py --help` runs without errors."""
    print("\n--- 1. privilege_auditor.py --help Test ---")
    print("Running 'python src/privilege/privilege_auditor.py --help'...")
    
    result = run_command("python src/privilege/privilege_auditor.py --help")
    if result.returncode == 0 and "usage: privilege_auditor.py" in result.stdout:
        print("✅ 'privilege_auditor.py --help' works without ModuleNotFoundError.")
    else:
        print(f"❌ 'privilege_auditor.py --help' failed. Stderr: {result.stderr.strip()}")
        sys.exit(1)

def test_api_privilege_scan_endpoint():
    """Tests if the API server starts and the /privilege/scan endpoint works."""
    print("\n--- 2. API /privilege/scan Endpoint Test ---")
    print("Starting API server in background...")

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
        print("Triggering /privilege/scan endpoint...")
        headers = {"X-API-Key": current_env.get("API_KEY", "test-key-123")} # Use the API_KEY from .env
        response = requests.post("http://localhost:8080/privilege/scan", headers=headers)
        
        if response.status_code == 200 and "status" in response.json() and response.json()["status"] == "success":
            print(f"✅ API /privilege/scan endpoint works. Report contains {response.json()['report']['total_findings']} findings.")
        else:
            print(f"❌ API /privilege/scan endpoint failed. Status: {response.status_code}, Response: {response.text}")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to API server. Is it running?")
        sys.exit(1)
    finally:
        terminate_process(api_process, "API server")

def test_core_modules_still_work():
    """Tests if all core modules (TCP, DNS, Persistence) can be imported successfully and run --help."""
    print("\n--- 3. Core Modules Functionality Test ---")
    
    modules_to_test = [
        "src/reconnaissance/dns_recon.py",
        "src/reconnaissance/PortScan_Enhanced.py",
        "src/persistence/persistence_auditor.py",
        "src/utils/log_parser.py",
    ]

    for module_path in modules_to_test:
        print(f"Testing '{module_path} --help'...")
        result = run_command(f"python {module_path} --help")
        if result.returncode == 0 and "usage:" in result.stdout:
            print(f"✅ '{module_path} --help' works.")
        else:
            print(f"❌ '{module_path} --help' failed. Stderr: {result.stderr.strip()}")
            sys.exit(1)

def test_docker_build():
    """Tests if the docker/scanner/Dockerfile builds successfully."""
    print("\n--- 4. Docker Build Test ---")
    dockerfile_path = "docker/scanner/Dockerfile"
    if not os.path.exists(dockerfile_path):
        print(f"❌ Dockerfile not found at '{dockerfile_path}'. Skipping Docker build test.")
        return
        
    print(f"Attempting to build Docker image from '{dockerfile_path}'...")
    build_command = ["docker", "build", "-t", "mitre-scanner-test:latest", "-f", dockerfile_path, "."]
    try:
        result = run_command(build_command, cwd=".")
        if result.returncode == 0:
            print("✅ Docker image built successfully.")
        else:
            print(f"❌ Docker build failed. Stderr: {result.stderr.strip()}")
            sys.exit(1)
    except FileNotFoundError:
        print("❌ 'docker' command not found. Please ensure Docker is installed and in your PATH. Skipping Docker build test.")
    except Exception as e:
        print(f"❌ An error occurred during Docker build test: {e}")
        sys.exit(1)


def test_git_status_clean():
    """Checks if the Git working tree is clean."""
    print("\n--- 5. Git Status Clean Test ---")
    print("Checking 'git status --short'...")

    result = run_command("git status --short")

    if not result.stdout.strip():
        print("✅ Git working tree is clean.")
    else:
        print("❌ Git working tree is NOT clean. Untracked/modified files found:")
        print(result.stdout)
        print("Please ensure your .gitignore is comprehensive.")
        sys.exit(1)


if __name__ == "__main__":
    print("--- Starting Chapter 5 Fixes Validation ---")
    # Ensure all necessary scripts are executable
    os.chmod("src/privilege/privilege_auditor.py", 0o755) # Ensure CLI execution
    os.chmod("validate_chapter5.py", 0o755) # Ensure this script itself is executable
    
    test_privilege_auditor_help()
    test_api_privilege_scan_endpoint()
    test_core_modules_still_work()
    test_docker_build()
    test_git_status_clean()
    print("\n--- All Chapter 5 Fixes Validated Successfully! ---")
    sys.exit(0)
