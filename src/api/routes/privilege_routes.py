
"""
Privilege Escalation API Routes
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any, Optional
from src.api.models import PrivilegeScanRequest, PrivilegeScanResponse, PrivilegeFindingModel
import logging
from src.utils.logging_config import setup_logging, JsonFormatter

from src.privilege.privilege_auditor import PrivilegeAuditor, PrivilegeFinding
from src.api.security import verify_api_key



logger = logging.getLogger(__name__)
if not any(isinstance(h, JsonFormatter) for h in logger.handlers):
    setup_logging(level=logging.INFO, json_format=True)

router = APIRouter(
    prefix="/privilege",
    tags=["privilege"],
    responses={404: {"description": "Not found"}},
)

@router.get("/health")
async def privilege_health():
    return {"status": "healthy", "module": "privilege"}

@router.post("/scan", response_model=PrivilegeScanResponse)
async def scan_privilege(
    request: PrivilegeScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Scans for common privilege escalation vectors on the system.

    **MITRE ATT&CK Techniques:**
    - T1037: Logon Scripts
    - T1073.001: DLL Side-Loading: Python Path Hijacking
    - T1543.003: Create or Modify System Process: Windows Service
    - T1053.005: Scheduled Task/Job: Scheduled Task

    Returns:
        List[PrivilegeFinding]: A list of detected privilege escalation findings.
    """
    logger.info("Received privilege scan request")
    try:
        auditor = PrivilegeAuditor()
        report = auditor.scan()
        # Convert PrivilegeFinding dataclass instances to PrivilegeFindingModel Pydantic instances
        pydantic_report = [PrivilegeFindingModel(**finding.__dict__) for finding in report]
        return PrivilegeScanResponse(report=pydantic_report)
    except Exception as e:
        logger.error(f"Privilege scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Privilege scan failed: {e}")
