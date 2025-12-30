import os
import subprocess
import logging
import requests
import json
import sys
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- Configuration ---
API_KEY = os.getenv("API_KEY")
API_SERVER_PORT = int(os.getenv("API_SERVER_PORT", 8080))
HONEYPOT_METRICS_PORT = int(os.getenv("HONEYPOT_METRICS_PORT", 8000))

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- FastAPI App Setup ---
app = FastAPI(
    title="MITRE ATT&CK Python Security Lab API",
    description="Orchestration layer for security tools and reports.",
    version="1.0.0",
)

# --- API Key Authentication ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(api_key: str = Depends(api_key_header)):
    """
    Authenticates requests using an API key provided in the 'X-API-Key' header.
    """
    if not API_KEY:
        logger.warning("API_KEY environment variable is not set. API authentication is disabled.")
        return True # Allow access if API_KEY is not configured
        
    if api_key and api_key == API_KEY:
        return True
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )

# --- Endpoints ---

@app.get("/health", summary="Health Check", response_description="Status of the API and connected tools.")
async def health_check(authenticated: bool = Depends(get_api_key)):
    """
    Checks the health of the API server and its core dependencies.
    """
    status = {
        "api_status": "operational",
        "authentication_enabled": bool(API_KEY),
        "dependencies": {
            "threat_intel_api_keys_configured": {
                "abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
                "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
            },
            "honeypot_metrics_reachable": False, # Will check below
            # "port_scanner_tool_present": os.path.exists("src/reconnaissance/PortScan_Enhanced.py"),
            # "log_parser_tool_present": os.path.exists("src/utils/log_parser.py"),
        }
    }

    # Check if honeypot metrics endpoint is reachable
    try:
        metrics_url = f"http://localhost:{HONEYPOT_METRICS_PORT}"
        response = requests.get(metrics_url, timeout=2)
        if response.status_code == 200:
            status["dependencies"]["honeypot_metrics_reachable"] = True
    except requests.exceptions.RequestException:
        logger.warning(f"Could not reach Honeypot metrics at {metrics_url}")
        status["dependencies"]["honeypot_metrics_reachable"] = False
    
    return status

class ScanRequest(BaseModel):
    """
    Request model for triggering a port scan.
    """
    target: str
    ports: str = "1-1024"
    scan_type: str

@app.post("/scan", summary="Trigger Port Scan", response_description="Result of the triggered port scan.")
async def trigger_port_scan(scan_request: ScanRequest, authenticated: bool = Depends(get_api_key)):
    """
    Triggers a port scan on the specified target using the given ports and scan type.
    Requires administrator privileges on the host system to perform SYN and XMAS scans.
    """
    if scan_request.scan_type in ["syn", "xmas"]:
        # In a production environment, you'd want a more robust way to check for admin
        # or have the PortScanner service run with elevated privileges.
        # For this lab, we assume the API server might be run with necessary permissions.
        logger.warning(f"SYN/XMAS scan requested for {scan_request.target}. This scan type requires elevated privileges.")

    command = [
        sys.executable, # Ensures the correct python interpreter is used
        "src/reconnaissance/PortScan_Enhanced.py",
        scan_request.target,
        "-p", scan_request.ports,
        "-t", scan_request.scan_type,
    ]

    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        return {
            "message": "Port scan initiated successfully",
            "target": scan_request.target,
            "scan_type": scan_request.scan_type,
            "stdout": process.stdout,
            "stderr": process.stderr,
        }
    except subprocess.CalledProcessError as e:
        logger.error(f"Port scan failed for {scan_request.target}: {e.stderr}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Port scan failed: {e.stderr.strip()}",
        )
    except FileNotFoundError:
        logger.critical(f"Port scanner script not found at {command[1]}. Ensure path is correct.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Port scanner script not found.",
        )

@app.get("/metrics", summary="Get Prometheus Metrics", response_description="Raw Prometheus metrics from the HoneyResolver.")
async def get_metrics(authenticated: bool = Depends(get_api_key)):
    """
    Fetches raw Prometheus metrics from the HoneyResolver component.
    """
    metrics_url = f"http://localhost:{HONEYPOT_METRICS_PORT}"
    try:
        response = requests.get(metrics_url, timeout=5)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch metrics from {metrics_url}: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Could not connect to Honeypot metrics endpoint: {e}",
        )

@app.get("/reports", summary="Get Latest Log Analysis Report", response_description="Summary of the latest parsed logs and threat scores.")
async def get_reports(authenticated: bool = Depends(get_api_key)):
    """
    Triggers the log parser and returns the latest analysis report,
    including threat scores and aggregated statistics.
    """
    command = [
        sys.executable,
        "src/utils/log_parser.py",
    ]

    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        report_lines = process.stdout.strip().split('\n')
        
        parsed_reports = []
        for line in report_lines:
            if line: # Ensure line is not empty
                try:
                    parsed_reports.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning(f"Could not decode JSON line from log parser: {line[:100]}...")
        
        if not parsed_reports:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Log parser ran but produced no valid JSON output.",
            )

        return parsed_reports

    except subprocess.CalledProcessError as e:
        logger.error(f"Log parser script failed: {e.stderr}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Log parser failed: {e.stderr.strip()}",
        )
    except FileNotFoundError:
        logger.critical(f"Log parser script not found at {command[1]}. Ensure path is correct.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Log parser script not found.",
        )

if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting API server on port {API_SERVER_PORT}")
    uvicorn.run(app, host="0.0.0.0", port=API_SERVER_PORT)