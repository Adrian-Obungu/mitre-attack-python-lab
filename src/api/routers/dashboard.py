from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from typing import List, Dict

from src.api.security.auth import get_current_user

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)

templates = Jinja2Templates(directory="templates")

@router.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    """
    Serves the main dashboard page.
    """
    return templates.TemplateResponse(request, "dashboard.html")

@router.get("/api/metrics", dependencies=[Depends(get_current_user)])
async def get_dashboard_metrics() -> Dict:
    """
    Returns high-level stats for the dashboard.
    """
    return {
        "techniques_implemented": 12,
        "total_findings": 142,
        "api_status": "healthy",
        "last_scan": "2024-01-20T11:00:00Z"
    }

@router.get("/api/findings/recent", dependencies=[Depends(get_current_user)])
async def get_recent_findings() -> List[Dict]:
    """
    Returns a list of recent mock/scanned findings.
    """
    return [
        {"id": 1, "technique_id": "T1070", "severity": "High", "timestamp": "2024-01-20T10:55:00Z"},
        {"id": 2, "technique_id": "T1027", "severity": "Medium", "timestamp": "2024-01-20T10:50:00Z"},
        {"id": 3, "technique_id": "T1112", "severity": "Medium", "timestamp": "2024-01-20T10:45:00Z"},
    ]
