from fastapi import APIRouter, Depends, HTTPException
from src.core.state_manager import SecurityStateManager
from src.api.security.auth import requires_permission
from src.api.security.rbac import Permission

# Import detectors that will have baselines
from src.defense_evasion.indicator_removal_detector import T1070IndicatorRemovalDetector
from src.discovery.network_share_discovery import T1135NetworkShareDiscovery
from src.defense_evasion.registry_monitor import T1112RegistryMonitor

router = APIRouter(
    prefix="/scan",
    tags=["State Management"],
)

state_manager = SecurityStateManager()

@router.post("/baseline", summary="Create a baseline snapshot for all stateful detectors", dependencies=[Depends(requires_permission(Permission.WRITE_SCAN))])
async def create_baseline():
    """
    Creates and saves a baseline for all stateful security detectors.
    This should be run on a known-good state of the system.
    """
    try:
        # T1070 - Indicator Removal (logs and files)
        t1070 = T1070IndicatorRemovalDetector(state_manager=state_manager)
        t1070.run_checks(scan_id="baseline-manual")

        # T1135 - Network Shares
        t1135 = T1135NetworkShareDiscovery(state_manager=state_manager)
        t1135.run_checks(scan_range='127.0.0.1', scan_id="baseline-manual")
        
        # T1112 - Registry Monitor
        t1112 = T1112RegistryMonitor(state_manager=state_manager)
        t1112.run_checks(scan_id="baseline-manual")

        return {"status": "success", "message": "Baseline created successfully for stateful detectors."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create baseline: {e}")

@router.get("/history/{detector_name}", summary="Get the state history for a specific detector", dependencies=[Depends(requires_permission(Permission.READ_DISCOVERY))])
async def get_history(detector_name: str):
    """
    Retrieves the historical state data for a given detector.
    """
    try:
        # For simplicity, this returns the latest state, but could be extended
        # to return all states within a time window.
        latest_state = state_manager.get_latest_state(detector_name)
        if not latest_state:
            raise HTTPException(status_code=404, detail=f"No history found for detector '{detector_name}'.")
        
        return {"detector": detector_name, "latest_state": latest_state}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
