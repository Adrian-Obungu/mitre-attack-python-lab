
"""
Discovery API Routes
"""

from fastapi import APIRouter, HTTPException, Depends, Query
import logging
from typing import List, Dict, Any, Optional

from src.discovery.account_discovery import T1087AccountDiscovery
from src.discovery.network_service_discovery import T1046NetworkServiceDiscovery
from src.discovery.network_share_discovery import T1135NetworkShareDiscovery
from src.discovery.permission_groups_discovery import T1069PermissionGroupsDiscovery
from src.discovery.system_information_discovery import T1082SystemInformationDiscovery
from src.core.state_manager import SecurityStateManager
from src.api.security import verify_api_key
from src.utils.logging_config import setup_logging, JsonFormatter
from src.api.models import AccountDiscoveryResponse, NetworkServiceDiscoveryResponse, NetworkShareDiscoveryRequest, NetworkShareDiscoveryResponse, PermissionGroupsDiscoveryRequest, PermissionGroupsDiscoveryResponse, SystemInformationDiscoveryResponse

logger = logging.getLogger(__name__)
if not any(isinstance(h, JsonFormatter) for h in logger.handlers):
    setup_logging(level=logging.INFO, json_format=True)

router = APIRouter(
    prefix="/discovery",
    tags=["discovery"],
)

# Initialize state manager for detectors that require it
state_manager = SecurityStateManager()

@router.get("/health")
async def discovery_health():
    return {"status": "healthy", "module": "discovery"}

@router.get("/account_discovery/scan", response_model=AccountDiscoveryResponse)
async def scan_account_discovery(
    api_key: str = Depends(verify_api_key)
):
    """
    Scans for local and domain accounts (T1087).

    **MITRE ATT&CK Technique:**
    - T1087: Account Discovery

    Returns:
        Dict[str, Any]: A dictionary containing discovered accounts.
    """
    logger.info("Received account discovery scan request")
    try:
        detector = T1087AccountDiscovery()
        results = detector.run_checks()
        return AccountDiscoveryResponse(**results)
    except Exception as e:
        logger.error(f"Account discovery scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Account discovery scan failed: {e}")

@router.get("/network_service_discovery/scan", response_model=NetworkServiceDiscoveryResponse)
async def scan_network_service_discovery(
    api_key: str = Depends(verify_api_key)
):
    """
    Scans for network services (T1046).

    **MITRE ATT&CK Technique:**
    - T1046: Network Service Discovery

    Returns:
        Dict[str, Any]: A dictionary containing discovered network services.
    """
    logger.info("Received network service discovery scan request")
    try:
        detector = T1046NetworkServiceDiscovery()
        results = detector.run_checks()
        return NetworkServiceDiscoveryResponse(**results)
    except Exception as e:
        logger.error(f"Network service discovery scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Network service discovery scan failed: {e}")

@router.post("/network_share_discovery/scan", response_model=NetworkShareDiscoveryResponse)
async def scan_network_share_discovery(
    request: NetworkShareDiscoveryRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Scans for accessible network shares (T1135).

    **MITRE ATT&CK Technique:**
    - T1135: Network Share Discovery

    Args:
        scan_range (str): CIDR range or single IP to scan (e.g., "192.168.1.0/24" or "192.168.1.1").
        scan_id (str, optional): An optional ID for this scan run, used for state management.

    Returns:
        Dict[str, Any]: A dictionary containing discovered network shares.
    """
    logger.info(f"Received network share discovery scan request for range: {request.scan_range} (scan_id: {request.scan_id})")
    try:
        detector = T1135NetworkShareDiscovery(state_manager=state_manager)
        results = detector.run_checks(scan_range=request.scan_range, scan_id=request.scan_id)
        return NetworkShareDiscoveryResponse(**results)
    except Exception as e:
        logger.error(f"Network share discovery scan failed for range {request.scan_range}: {e}")
        raise HTTPException(status_code=500, detail=f"Network share discovery scan failed: {e}")

@router.post("/permission_groups_discovery/scan", response_model=PermissionGroupsDiscoveryResponse)
async def scan_permission_groups_discovery(
    request: PermissionGroupsDiscoveryRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Discovers system permission groups and membership (T1069).

    **MITRE ATT&CK Technique:**
    - T1069: Permission Groups Discovery

    Args:
        include_domain (bool): Whether to attempt domain-level enumeration.
        identify_service_accounts (bool): Whether to run service account heuristics.

    Returns:
        Dict[str, Any]: A dictionary containing discovered permission groups and members.
    """
    logger.info(f"Received permission groups discovery scan request (include_domain: {request.include_domain}, identify_service_accounts: {request.identify_service_accounts})")
    try:
        detector = T1069PermissionGroupsDiscovery()
        results = detector.run_checks(include_domain=request.include_domain, identify_service_accounts=request.identify_service_accounts)
        return PermissionGroupsDiscoveryResponse(**results)
    except Exception as e:
        logger.error(f"Permission groups discovery scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Permission groups discovery scan failed: {e}")

@router.get("/system_information_discovery/scan", response_model=SystemInformationDiscoveryResponse)
async def scan_system_information_discovery(
    api_key: str = Depends(verify_api_key)
):
    """
    Gathers system information (T1082).

    **MITRE ATT&CK Technique:**
    - T1082: System Information Discovery

    Returns:
        Dict[str, Any]: A dictionary containing discovered system information.
    """
    logger.info("Received system information discovery scan request")
    try:
        detector = T1082SystemInformationDiscovery()
        results = detector.run_checks()
        return SystemInformationDiscoveryResponse(**results)
    except Exception as e:
        logger.error(f"System information discovery scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"System information discovery scan failed: {e}")
