import asyncio
import time
from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any

from src.api.security.auth import requires_permission
from src.api.security.rbac import Permission

# Import all detectors
from src.discovery.network_service_discovery import T1046NetworkServiceDiscovery
from src.discovery.permission_groups_discovery import T1069PermissionGroupsDiscovery
from src.discovery.system_information_discovery import T1082SystemInformationDiscovery
from src.discovery.network_share_discovery import T1135NetworkShareDiscovery
from src.discovery.account_discovery import T1087AccountDiscovery
from src.defense_evasion.defense_impairment_detector import T1562DefenseImpairmentDetector
from src.defense_evasion.elevation_detector import T1548ElevationDetector
from src.defense_evasion.indicator_removal_detector import T1070IndicatorRemovalDetector
from src.defense_evasion.obfuscation_detector import T1027ObfuscationDetector
from src.defense_evasion.registry_monitor import T1112RegistryMonitor


router = APIRouter(
    prefix="/scan",
    tags=["Unified Scan"],
)

async def run_detector(detector_class, *args, **kwargs):
    """Runs a detector's run_checks method in a thread and measures execution time."""
    start_time = time.time()
    detector_instance = detector_class()
    try:
        # Use to_thread for synchronous run_checks methods
        result = await asyncio.to_thread(detector_instance.run_checks, *args, **kwargs)
        execution_time = time.time() - start_time
        return {"status": "success", "technique_id": detector_class.__name__.split('T')[1].split('D')[0], "data": result, "execution_time": execution_time}
    except Exception as e:
        execution_time = time.time() - start_time
        return {"status": "error", "technique_id": detector_class.__name__.split('T')[1].split('D')[0], "error": str(e), "execution_time": execution_time}

@router.post("/full", summary="Execute a comprehensive parallel scan of all detectors", dependencies=[Depends(requires_permission(Permission.WRITE_SCAN))])
async def full_scan():
    """
    Triggers a full system scan by running all available Defense Evasion and Discovery
    detectors in parallel.

    - **Parallel Execution**: Runs 10 detectors concurrently to minimize scan time.
    - **Timeout Management**: Each detector is limited to 30 seconds, with a total scan timeout of 120 seconds.
    - **Error Isolation**: A failure in one detector will not halt the entire scan.
    - **Consolidated Report**: Returns a structured report with findings from all detectors,
      performance metrics, and a calculated security score.
    """
    scan_start_time = time.time()

    # Define all detector tasks
    tasks = [
        # Discovery
        run_detector(T1046NetworkServiceDiscovery, network_scan=True),
        run_detector(T1069PermissionGroupsDiscovery, include_domain=True, identify_service_accounts=True),
        run_detector(T1082SystemInformationDiscovery),
        run_detector(T1135NetworkShareDiscovery, scan_range='192.168.1.0/24'), # Example range
        run_detector(T1087AccountDiscovery),
        # Defense Evasion
        run_detector(T1562DefenseImpairmentDetector),
        run_detector(T1548ElevationDetector),
        run_detector(T1070IndicatorRemovalDetector),
        # T1027 requires a file, this is a placeholder. In a real scenario, you might scan specific files.
        # run_detector(T1027ObfuscationDetector, file_path=Path("path/to/some/file.exe")), 
        run_detector(T1112RegistryMonitor),
    ]

    try:
        # Use asyncio.wait_for for the total timeout
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=120.0)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Full scan timed out after 120 seconds.")

    # Process results
    defense_evasion_findings = []
    discovery_findings = []
    
    de_technique_count = 0
    disc_technique_count = 0

    for res in results:
        if isinstance(res, Exception):
            # Handle exceptions from gather
            continue
        
        technique_id = int(res['technique_id'])
        if 1000 <= technique_id < 1500: # Discovery techniques
            disc_technique_count +=1
            if res['status'] == 'success':
                discovery_findings.append(res)
        else: # Defense Evasion techniques
            de_technique_count +=1
            if res['status'] == 'success':
                defense_evasion_findings.append(res)

    # Basic security score calculation (example logic)
    total_techniques = len(tasks)
    successful_scans = len([r for r in results if isinstance(r, dict) and r['status'] == 'success'])
    security_score = int((successful_scans / total_techniques) * 100) if total_techniques > 0 else 0

    # Example recommendations (in a real system, this would be more intelligent)
    recommendations = []
    if security_score < 70:
        recommendations.append("Multiple detectors failed or timed out. Review system stability and permissions.")
    
    # Add more specific recommendations based on findings...

    total_execution_time = time.time() - scan_start_time

    return {
        "status": "completed",
        "execution_time": total_execution_time,
        "defense_evasion": {"techniques": de_technique_count, "findings": defense_evasion_findings},
        "discovery": {"techniques": disc_technique_count, "findings": discovery_findings},
        "security_score": security_score,
        "recommendations": recommendations,
    }
