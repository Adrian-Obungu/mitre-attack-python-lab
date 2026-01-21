import os
import asyncio
from fastapi import APIRouter, HTTPException, Body, Depends
from pydantic import BaseModel
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from src.api.security.auth import requires_permission
from src.api.security.rbac import Permission

# --- Pydantic Models ---

class BaseScanRequest(BaseModel):
    quick_scan: bool = False

class DefenseEvasionScanRequest(BaseScanRequest):
    file_path: Optional[str] = None
    log_path: Optional[str] = None
    directory: Optional[str] = None
    baseline_path: Optional[str] = None

class FileAnalysisRequest(BaseModel):
    file_path: str

class ObfuscationAnalysisResult(BaseModel):
    file_path: str
    entropy: float
    packers_detected: List[str]
    is_obfuscated: bool
    error: Optional[str] = None

class IndicatorRemovalRequest(BaseModel):
    log_path: Optional[str] = None
    directory: Optional[str] = None

class IndicatorRemovalResponse(BaseModel):
    log_cleared: bool = False
    rapid_deletions: List[str] = []
    timestamp: datetime

class RegistryAnalysisRequest(BaseModel):
    baseline_path: str

class RegistryAnalysisResponse(BaseModel):
    changes: List[Dict[str, Any]]

class DefenseImpairmentResponse(BaseModel):
    stopped_services: List[str]
    tampering_indicators: List[Dict[str, Any]]
    log_issues: List[Dict[str, Any]]

class ElevationAnalysisResponse(BaseModel):
    uac_enabled: Any
    auto_elevation_binaries: list
    suspicious_chains: list

class FullDefenseEvasionResponse(BaseModel):
    obfuscation: Optional[ObfuscationAnalysisResult] = None
    indicator_removal: Optional[IndicatorRemovalResponse] = None
    registry: Optional[RegistryAnalysisResponse] = None
    defense_impairment: Optional[DefenseImpairmentResponse] = None
    elevation: Optional[ElevationAnalysisResponse] = None

# --- API Router ---

router = APIRouter(
    prefix="/analyze",
    tags=["Defense Evasion Analysis"],
    dependencies=[Depends(requires_permission(Permission.READ_EVASION))]
)

SAFE_DIRECTORY = Path("./").resolve()

def validate_path(path_str: str) -> Path:
    if ".." in path_str:
        raise HTTPException(status_code=400, detail="Invalid path. Directory traversal is not permitted.")
    if os.path.isabs(path_str) and not path_str.startswith(str(SAFE_DIRECTORY)):
        raise HTTPException(status_code=400, detail="Invalid path. Absolute paths outside the project's scope are not permitted.")
    file_path = Path(path_str).resolve()
    if SAFE_DIRECTORY not in file_path.parents and file_path != SAFE_DIRECTORY:
        raise HTTPException(status_code=400, detail="Invalid path. Directory traversal is not permitted.")
    return file_path

@router.post("/obfuscation", response_model=ObfuscationAnalysisResult, summary="Analyze a file for obfuscation")
async def analyze_file_for_obfuscation(request: FileAnalysisRequest):
    try:
        safe_file_path = validate_path(request.file_path)
        detector = T1027ObfuscationDetector()
        result = await asyncio.to_thread(detector.analyze_file, safe_file_path)
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

@router.post("/indicator-removal", response_model=IndicatorRemovalResponse, summary="Detect indicator removal")
async def analyze_indicator_removal(request: IndicatorRemovalRequest):
    if not request.log_path and not request.directory:
        raise HTTPException(status_code=422, detail="At least one of 'log_path' or 'directory' must be provided.")
    
    log_cleared = False
    rapid_deletions = []
    detector = T1070IndicatorRemovalDetector()

    if request.log_path:
        try:
            safe_log_path = validate_path(request.log_path)
            baseline_size = await asyncio.to_thread(safe_log_path.stat)
            result = await asyncio.to_thread(detector.monitor_log_clearing, safe_log_path, baseline_size.st_size + 1)
            log_cleared = result.get("is_cleared_or_truncated", False)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Log file not found: {request.log_path}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An unexpected error occurred during log analysis: {e}")

    if request.directory:
        try:
            safe_directory_path = validate_path(request.directory)
            deletions = await asyncio.to_thread(detector.detect_rapid_deletions, safe_directory_path)
            for d in deletions:
                rapid_deletions.extend(d.get("deleted_files", []))
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail=f"Directory not found: {request.directory}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An unexpected error occurred during directory analysis: {e}")

    return IndicatorRemovalResponse(log_cleared=log_cleared, rapid_deletions=rapid_deletions, timestamp=datetime.now())

@router.post("/registry", response_model=RegistryAnalysisResponse, summary="Analyze registry for unauthorized persistence entries")
async def scan_registry(request: RegistryAnalysisRequest):
    try:
        safe_baseline_path = validate_path(request.baseline_path)
        monitor = T1112RegistryMonitor()
        
        loaded_data = await asyncio.to_thread(monitor.load_snapshot, str(safe_baseline_path))
        if not loaded_data:
            raise HTTPException(status_code=400, detail="Invalid or empty baseline snapshot.")
        
        baseline_snapshot = loaded_data["snapshot"]
        keys_to_snapshot = loaded_data["keys"]

        current_snapshot = await asyncio.to_thread(monitor.create_registry_snapshot, keys_to_snapshot)
        changes = await asyncio.to_thread(monitor.compare_registry_snapshot, baseline_snapshot, current_snapshot)
        return RegistryAnalysisResponse(changes=changes)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

@router.post("/defense-impairment", response_model=DefenseImpairmentResponse, summary="Check for security tool tampering and service disabling")
async def check_defense_impairment(request: BaseScanRequest):
    try:
        detector = T1562DefenseImpairmentDetector()
        results = await asyncio.to_thread(detector.run_checks)
        return DefenseImpairmentResponse(**results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

@router.post("/elevation", response_model=ElevationAnalysisResponse, summary="Detect privilege escalation and UAC bypass attempts")
async def check_elevation_abuse(request: BaseScanRequest):
    try:
        detector = T1548ElevationDetector()
        results = await asyncio.to_thread(detector.run_checks)
        return ElevationAnalysisResponse(**results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

@router.post("/scan-all", response_model=FullDefenseEvasionResponse, summary="Execute all defense evasion detectors")
async def scan_all_defense_evasion(request: DefenseEvasionScanRequest):
    
    async def run_obfuscation():
        if request.file_path:
            return await analyze_file_for_obfuscation(FileAnalysisRequest(file_path=request.file_path))
        return ObfuscationAnalysisResult(file_path="N/A", entropy=0, packers_detected=[], is_obfuscated=False, error="No file provided for scan")

    async def run_indicator_removal():
        if request.log_path or request.directory:
            return await analyze_indicator_removal(IndicatorRemovalRequest(log_path=request.log_path, directory=request.directory))
        return IndicatorRemovalResponse(timestamp=datetime.now())

    async def run_registry():
        if request.baseline_path:
            return await scan_registry(RegistryAnalysisRequest(baseline_path=request.baseline_path))
        return RegistryAnalysisResponse(changes=[])

    async def run_defense_impairment():
        return await check_defense_impairment(BaseScanRequest(quick_scan=request.quick_scan))

    async def run_elevation():
        return await check_elevation_abuse(BaseScanRequest(quick_scan=request.quick_scan))

    try:
        tasks = [
            run_obfuscation(),
            run_indicator_removal(),
            run_registry(),
            run_defense_impairment(),
            run_elevation(),
        ]
        
        results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=45.0)

        response_data = {
            "obfuscation": results[0],
            "indicator_removal": results[1],
            "registry": results[2],
            "defense_impairment": results[3],
            "elevation": results[4],
        }
        
        return FullDefenseEvasionResponse(**response_data)

    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Scan timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred during the full scan: {e}")
