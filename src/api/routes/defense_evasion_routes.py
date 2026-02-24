
"""
Defense Evasion API Routes
"""

from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File
import logging
from typing import List, Dict, Any, Optional
from src.api.models import ObfuscationAnalysisResult, IndicatorRemovalScanRequest, IndicatorRemovalScanResponse, RegistryMonitorScanRequest, RegistryMonitorScanResponse, DefenseImpairmentScanResponse
from pathlib import Path
import shutil

from src.defense_evasion.obfuscation_detector import T1027ObfuscationDetector
from src.defense_evasion.indicator_removal_detector import T1070IndicatorRemovalDetector
from src.defense_evasion.registry_monitor import T1112RegistryMonitor
from src.defense_evasion.defense_impairment_detector import T1562DefenseImpairmentDetector
from src.core.state_manager import SecurityStateManager
from src.api.security import verify_api_key
from src.utils.logging_config import setup_logging, JsonFormatter

logger = logging.getLogger(__name__)
if not any(isinstance(h, JsonFormatter) for h in logger.handlers):
    setup_logging(level=logging.INFO, json_format=True)

router = APIRouter(
    prefix="/defense_evasion",
    tags=["defense_evasion"],
)

# Initialize state manager for detectors that require it
state_manager = SecurityStateManager()

@router.get("/health")
async def defense_evasion_health():
    return {"status": "healthy", "module": "defense_evasion"}

@router.post("/obfuscation/analyze", response_model=ObfuscationAnalysisResult)
async def analyze_obfuscation(
    file: UploadFile = File(..., description="File to analyze for obfuscation"),
    api_key: str = Depends(verify_api_key)
):
    """
    Analyzes an uploaded file for signs of obfuscation (T1027).

    **MITRE ATT&CK Technique:**
    - T1027: Obfuscated Files or Information

    Args:
        file (UploadFile): The file to upload and analyze.

    Returns:
        Dict[str, Any]: Analysis results including entropy and detected packers.
    """
    logger.info(f"Received obfuscation analysis request for file: {file.filename}")
    temp_file_path = Path(f"/tmp/{file.filename}")
    try:
        with temp_file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        detector = T1027ObfuscationDetector()
        results = detector.analyze_file(temp_file_path)
        return ObfuscationAnalysisResult(**results)
    except Exception as e:
        logger.error(f"Obfuscation analysis failed for {file.filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Obfuscation analysis failed: {e}")
    finally:
        if temp_file_path.exists():
            temp_file_path.unlink()

@router.post("/indicator_removal/scan", response_model=IndicatorRemovalScanResponse)
async def scan_indicator_removal(
    request: IndicatorRemovalScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Scans for signs of indicator removal (e.g., log truncation) (T1070).

    **MITRE ATT&CK Technique:**
    - T1070: Indicator Removal

    Args:
        scan_id (str, optional): An optional ID for this scan run, used for state management.

    Returns:
        Dict[str, Any]: A dictionary containing detected indicator removal findings.
    """
    logger.info(f"Received indicator removal scan request (scan_id: {request.scan_id})")
    try:
        detector = T1070IndicatorRemovalDetector(state_manager=state_manager)
        results = detector.run_checks(scan_id=request.scan_id)
        return IndicatorRemovalScanResponse(**results)
    except Exception as e:
        logger.error(f"Indicator removal scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Indicator removal scan failed: {e}")

@router.post("/registry_monitor/scan", response_model=RegistryMonitorScanResponse)
async def scan_registry_monitor(
    request: RegistryMonitorScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Monitors the Windows registry for suspicious modifications (T1112).

    **MITRE ATT&CK Technique:**
    - T1112: Modify Registry

    Args:
        scan_id (str, optional): An optional ID for this scan run, used for state management.

    Returns:
        Dict[str, Any]: A dictionary containing detected registry changes.
    """
    logger.info(f"Received registry monitor scan request (scan_id: {request.scan_id})")
    try:
        detector = T1112RegistryMonitor(state_manager=state_manager)
        results = detector.run_checks(scan_id=request.scan_id)
        return RegistryMonitorScanResponse(detected_changes=results)
    except Exception as e:
        logger.error(f"Registry monitor scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Registry monitor scan failed: {e}")

@router.get("/defense_impairment/scan", response_model=DefenseImpairmentScanResponse)
async def scan_defense_impairment(
    api_key: str = Depends(verify_api_key)
):
    """
    Detects defense impairment techniques (T1562).

    **MITRE ATT&CK Technique:**
    - T1562: Impair Defenses

    Returns:
        Dict[str, Any]: A dictionary containing detected defense impairment findings.
    """
    logger.info("Received defense impairment scan request")
    try:
        detector = T1562DefenseImpairmentDetector()
        results = detector.run_checks()
        return DefenseImpairmentScanResponse(**results)
    except Exception as e:
        logger.error(f"Defense impairment scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Defense impairment scan failed: {e}")
