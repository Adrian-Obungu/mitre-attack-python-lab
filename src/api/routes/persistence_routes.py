
"""
Persistence API Routes
"""

from fastapi import APIRouter, HTTPException, Depends, Query
import logging
from typing import List, Dict, Any, Optional
from src.api.models import PersistenceScanRequest, PersistenceScanResponse

from src.persistence.persistence_auditor import PersistenceAuditor
from src.api.security import verify_api_key
from src.utils.logging_config import setup_logging, JsonFormatter

logger = logging.getLogger(__name__)
if not any(isinstance(h, JsonFormatter) for h in logger.handlers):
    setup_logging(level=logging.INFO, json_format=True)

router = APIRouter(
    prefix="/persistence",
    tags=["persistence"],
)

@router.get("/health")
async def persistence_health():
    return {"status": "healthy", "module": "persistence"}

@router.post("/scan", response_model=PersistenceScanResponse)
async def scan_persistence(
    request: PersistenceScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Scans for common persistence mechanisms on the system.

    **MITRE ATT&CK Techniques:**
    - T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
    - T1053.005: Scheduled Task/Job: Scheduled Task
    - T1136.001: Create Account: Local Account

    Args:
        scan_id (str, optional): An optional ID for this scan run, used for state management.

    Returns:
        Dict[str, Any]: A dictionary containing the detected persistence findings.
    """
    logger.info(f"Received persistence scan request (scan_id: {request.scan_id})")
    try:
        auditor = PersistenceAuditor()
        results = auditor.run_all_checks(scan_id=request.scan_id)
        return PersistenceScanResponse(findings=results["findings"])
    except Exception as e:
        logger.error(f"Persistence scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Persistence scan failed: {e}")
