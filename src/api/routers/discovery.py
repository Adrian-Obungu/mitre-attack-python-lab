import asyncio
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any

from src.discovery.account_discovery import T1087AccountDiscovery
from src.discovery.network_share_discovery import T1135NetworkShareDiscovery
from src.api.security.auth import requires_permission
from src.api.security.rbac import Permission

router = APIRouter(
    prefix="/discovery",
    tags=["Discovery"],
    dependencies=[Depends(requires_permission(Permission.READ_DISCOVERY))] # Secure all discovery endpoints
)

class AccountDiscoveryResponse(BaseModel):
    local_users: List[str]
    domain_users: List[str]
    system_accounts: List[str]
    status: str
    message: str = None
    execution_time: str = None

class LocalShare(BaseModel):
    name: str
    path: str
    type: str

class NetworkShare(BaseModel):
    host: str
    share: str
    accessible: bool

class NetworkShareDiscoveryResponse(BaseModel):
    local_shares: List[LocalShare]
    network_shares: List[NetworkShare]
    scan_range: str
    status: str
    message: str = None
    execution_time: str = None

@router.post("/accounts", response_model=AccountDiscoveryResponse, summary="Discover local, domain, and system accounts")
async def discover_accounts():
    """
    Executes account discovery checks on the system.
    """
    try:
        detector = T1087AccountDiscovery()
        results = await asyncio.to_thread(detector.run_checks)
        return AccountDiscoveryResponse(**results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

@router.post("/shares", response_model=NetworkShareDiscoveryResponse, summary="Discover accessible network shares")
async def discover_network_shares():
    """
    Executes network share discovery checks.
    """
    try:
        detector = T1135NetworkShareDiscovery()
        results = await detector.run_checks() # run_checks is async
        return NetworkShareDiscoveryResponse(**results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")
