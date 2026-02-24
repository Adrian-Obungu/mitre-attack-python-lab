
"""
Reconnaissance API Routes
"""

from fastapi import APIRouter, HTTPException, Depends, Query
import logging
from typing import List, Dict, Any, Optional
from src.api.models import PortScanRequest, PortScanResponse, DnsScanRequest, DnsScanResponse, ScanType

from src.reconnaissance.PortScan_Enhanced import PortScanner
from src.api.security import verify_api_key
from src.utils.logging_config import setup_logging, JsonFormatter

logger = logging.getLogger(__name__)
if not any(isinstance(h, JsonFormatter) for h in logger.handlers):
    setup_logging(level=logging.INFO, json_format=True)

router = APIRouter(
    prefix="/recon",
    tags=["reconnaissance"],
)

@router.get("/health")
async def recon_health():
    return {"status": "healthy", "module": "reconnaissance"}

@router.post("/portscan", response_model=PortScanResponse)
async def run_port_scan(
    request: PortScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Runs an enhanced port scan against a target.

    **MITRE ATT&CK Techniques:**
    - T1046: Network Service Scanning
    - T1595.001: Active Scanning: Scanning IP Blocks

    Args:
        target (str): The target IP address or hostname.
        ports (str): Comma-separated list of ports or a range (e.g., '22,80,443' or '1-1024').
        scan_type (str): The type of scan to perform ('syn', 'ack', 'xmas').
        timeout (int): Timeout for each packet in seconds.
        max_threads (int): Maximum concurrent threads for scanning.

    Returns:
        Dict[str, Any]: Scan results.
    """
    logger.info(f"Received port scan request for target: {request.target}, ports: {request.ports}, type: {request.scan_type}")

    parsed_ports = PortScanner.validate_and_parse_ports(request.ports)
    if not parsed_ports:
        raise HTTPException(status_code=400, detail="Invalid port format. Use '80,443' or '1-1024'.")

    if not PortScanner.validate_target(request.target):
        raise HTTPException(status_code=400, detail="Invalid target. Must be a valid IP address or hostname.")

    try:
        scanner = PortScanner(target_ip=request.target, ports=parsed_ports, timeout=request.timeout, max_threads=request.max_threads)
        if request.scan_type == ScanType.syn:
            results = scanner.syn_scan()
        elif request.scan_type == ScanType.ack:
            results = scanner.ack_scan()
        elif request.scan_type == ScanType.xmas:
            results = scanner.xmas_scan()


        return PortScanResponse(target=request.target, scan_type=request.scan_type.value, results=results)
    except Exception as e:
        logger.error(f"Port scan failed for {request.target}: {e}")
        raise HTTPException(status_code=500, detail=f"Port scan failed: {e}")

@router.post("/dnsscan", response_model=DnsScanResponse)
async def run_dns_scan(
    request: DnsScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Performs DNS reconnaissance to gather various record types for a target domain.

    **MITRE ATT&CK Technique:**
    - T1590.002: Gather Victim Host Information: DNS

    Args:
        target_domain (str): The domain to perform DNS reconnaissance on.

    Returns:
        Dict[str, Any]: DNS scan results.
    """
    logger.info(f"Received DNS scan request for domain: {request.target_domain}")
    try:
        results = PortScanner.dns_scan(request.target_domain)
        if "Error" in results:
            raise HTTPException(status_code=400, detail=results["Error"][0])
        return DnsScanResponse(target_domain=request.target_domain, results=results)
    except Exception as e:
        logger.error(f"DNS scan failed for {request.target_domain}: {e}")
        raise HTTPException(status_code=500, detail=f"DNS scan failed: {e}")
