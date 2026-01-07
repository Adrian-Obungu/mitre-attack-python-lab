"""
Privilege Escalation API Routes
Provides endpoints for privilege escalation detection
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any
import logging

from src.privilege.privilege_auditor import PrivilegeAuditor
from src.api.security import verify_api_key

from src.privilege import PrivilegeFinding

router = APIRouter(
    prefix="/privilege",
    tags=["privilege"],
    responses={404: {"description": "Not found"}},
)

@router.get("/scan", response_model=Dict[str, Any])
async def scan_for_privilege_escalation(api_key: str = Depends(verify_api_key)):
    """
    Scan for privilege escalation vectors
    
    Returns:
        List of privilege escalation detections with MITRE technique mappings
    """
    try:
        auditor = PrivilegeAuditor()
        report = auditor.run_all_checks()
        return report
    except Exception as e:
        logging.error(f"Privilege scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def privilege_health():
    """Health check for privilege escalation module"""
    return {"status": "healthy", "module": "privilege_escalation"}

@router.get("/techniques")
async def get_techniques():
    """Get MITRE techniques covered by this module"""
    return {
        "techniques": [
            "T1037 - Boot or Logon Initialization Scripts",
            "T1548.002 - Bypass User Account Control",
            "T1053.005 - Scheduled Task",
            "T1543.003 - Windows Service"
        ]
    }
