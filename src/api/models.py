
from pydantic import BaseModel, Field
from enum import Enum
from typing import List, Dict, Any, Optional

# --- Reconnaissance Models ---
class ScanType(str, Enum):
    syn = "syn"
    ack = "ack"
    xmas = "xmas"

class PortScanRequest(BaseModel):
    target: str = Field(..., description="Target IP address or hostname")
    ports: str = Field("22,80,443", description="Ports to scan (e.g., '22,80,443' or '1-1024')")
    scan_type: ScanType = Field(ScanType.syn, description="Type of scan: 'syn', 'ack', 'xmas'")
    timeout: int = Field(2, description="Timeout for each packet in seconds")
    max_threads: int = Field(10, description="Maximum concurrent threads for scanning")

class PortScanResult(BaseModel):
    port: int
    status: str

class PortScanResponse(BaseModel):
    target: str
    scan_type: str
    results: Dict[int, str]

class DnsScanRequest(BaseModel):
    target_domain: str = Field(..., description="Target domain for DNS reconnaissance")

class DnsScanResponse(BaseModel):
    target_domain: str
    results: Dict[str, List[str]]

# --- Persistence Models ---
class PersistenceScanRequest(BaseModel):
    scan_id: Optional[str] = Field(None, description="Optional ID for this scan run")

class PersistenceFinding(BaseModel):
    technique_id: str
    technique_name: str
    description: str
    risk_level: str
    evidence: str
    mitigation: str
    timestamp: str
    details: Optional[Dict[str, Any]] = None

class PersistenceScanResponse(BaseModel):
    findings: List[PersistenceFinding]

# --- Privilege Escalation Models ---
class PrivilegeScanRequest(BaseModel):
    pass # No specific parameters for now

class PrivilegeFindingModel(BaseModel):
    technique_id: str
    technique_name: str
    description: str
    risk_level: str
    evidence: str
    mitigation: str
    timestamp: str
    details: Optional[Dict[str, Any]] = None

class PrivilegeScanResponse(BaseModel):
    report: List[PrivilegeFindingModel]

# --- Defense Evasion Models ---
class ObfuscationAnalysisRequest(BaseModel):
    # For file uploads, FastAPI handles the file object directly, no Pydantic model needed for the file itself
    pass

class ObfuscationAnalysisResult(BaseModel):
    file_path: str
    entropy: float
    packers_detected: List[str]
    is_obfuscated: bool
    error: Optional[str] = None

class IndicatorRemovalScanRequest(BaseModel):
    scan_id: Optional[str] = Field(None, description="Optional ID for this scan run")

class IndicatorRemovalScanResponse(BaseModel):
    log_truncation: List[Dict[str, Any]]
    rapid_file_deletion: List[Dict[str, Any]]

class RegistryMonitorScanRequest(BaseModel):
    scan_id: Optional[str] = Field(None, description="Optional ID for this scan run")

class RegistryMonitorScanResponse(BaseModel):
    detected_changes: List[Dict[str, Any]]

class DefenseImpairmentScanResponse(BaseModel):
    stopped_services: List[str]
    tampering_indicators: List[Dict[str, Any]]
    log_issues: List[Dict[str, Any]]

# --- Discovery Models ---
class AccountDiscoveryResponse(BaseModel):
    local_accounts: List[str]
    domain_accounts: List[str]
    status: str

class NetworkServiceDiscoveryResponse(BaseModel):
    discovered_services: List[Dict[str, Any]]
    status: str

class NetworkShareDiscoveryRequest(BaseModel):
    scan_range: str = Field("127.0.0.1", description="CIDR range or single IP to scan for network shares")
    scan_id: Optional[str] = Field(None, description="Optional ID for this scan run")

class NetworkShareDiscoveryResponse(BaseModel):
    all_discovered_shares: List[Dict[str, Any]]
    newly_discovered_shares: List[Dict[str, Any]]
    scan_range: str

class PermissionGroupsDiscoveryRequest(BaseModel):
    include_domain: bool = Field(False, description="Whether to attempt domain-level enumeration")
    identify_service_accounts: bool = Field(False, description="Whether to run service account heuristics")

class PermissionGroupsDiscoveryResponse(BaseModel):
    local_groups: List[Dict[str, Any]]
    domain_groups: List[Dict[str, Any]]
    platform_groups: Dict[str, Any]
    service_accounts: List[str]
    status: str
    execution_time: str

class SystemInformationDiscoveryResponse(BaseModel):
    system_info: Dict[str, Any]
    status: str
