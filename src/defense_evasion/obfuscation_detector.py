import math
import logging
from src.utils.logging_config import setup_logging, JsonFormatter
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)
if not any(isinstance(h, JsonFormatter) for h in logger.handlers):
    setup_logging(level=logging.INFO, json_format=True)

class T1027ObfuscationDetector:
    """
    Detects obfuscated files by analyzing file entropy and searching for common
    packer signatures, mapping to MITRE ATT&CK Technique T1027.
    """

    def __init__(self):
        """
        Initializes the T1027ObfuscationDetector.
        """
        self.packer_signatures = {
            "UPX": [
                b'UPX!',
                b'UPX0',
                b'UPX1',
                b'UPX2'
            ],
            "ASPack": [
                b'.aspack',
                b'ASPack'
            ]
        }
        self.entropy_threshold = 6.8
        logger.info("T1027ObfuscationDetector initialized.")

    def analyze(self, process_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes a process or file path supplied as a dictionary for signs of
        obfuscation.  This is a convenience wrapper around ``analyze_file``
        that accepts the same dict-based interface used elsewhere in the lab.

        Args:
            process_info: A dictionary that MUST contain at least one of:
                - ``file_path`` (str | Path): path to the file to inspect, OR
                - ``process_name`` (str): bare filename / process name used as
                  a label when no on-disk file is available.

        Returns:
            A dictionary with the analysis result.  When ``file_path`` is
            provided and the file exists on disk the result mirrors
            ``analyze_file``.  When only ``process_name`` is given (e.g.
            during unit tests or live-process inspection) the method returns
            a lightweight result without entropy analysis.

        Example::

            detector = T1027ObfuscationDetector()
            # Inspect an actual file
            result = detector.analyze({'file_path': '/usr/bin/ls'})
            # Inspect by process name only (no file read)
            result = detector.analyze({'process_name': 'suspicious.exe'})
            print(f'Detection result: {result}')
        """
        file_path: Optional[Path] = None

        if "file_path" in process_info:
            file_path = Path(process_info["file_path"])
        elif "process_name" in process_info:
            # Attempt to resolve the process name as a path; if it does not
            # exist on disk return a metadata-only result.
            candidate = Path(process_info["process_name"])
            if candidate.is_file():
                file_path = candidate

        if file_path is not None and file_path.is_file():
            return self.analyze_file(file_path)

        # No resolvable file — return a safe metadata-only result so callers
        # that pass a bare process name (e.g. quick CLI checks) do not crash.
        label = str(process_info.get("file_path") or process_info.get("process_name", "unknown"))
        logger.info(f"No on-disk file found for '{label}'; returning metadata-only result.")
        return {
            "process_name": label,
            "entropy": None,
            "packers_detected": [],
            "is_obfuscated": False,
            "note": "File not found on disk; entropy analysis skipped.",
        }

    def analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Analyzes a given file for signs of obfuscation.

        Args:
            file_path: The path to the file to analyze.

        Returns:
            A dictionary containing the analysis results, including entropy
            and any detected packers.
        """
        if not file_path.is_file():
            logger.error(f"File not found: {file_path}")
            raise FileNotFoundError(f"The specified file does not exist: {file_path}")

        try:
            with file_path.open('rb') as f:
                file_content = f.read()

            entropy = self._calculate_entropy(file_content)
            detected_packers = self._detect_packers(file_content)

            return {
                "file_path": str(file_path),
                "entropy": entropy,
                "packers_detected": detected_packers,
                "is_obfuscated": entropy > self.entropy_threshold or bool(detected_packers)
            }
        except Exception as e:
            logger.error(f"Failed to analyze file {file_path}: {e}")
            return {
                "file_path": str(file_path),
                "error": str(e)
            }

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of bytes data."""
        if not data:
            return 0.0
        freq: Dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0.0
        total = len(data)
        for count in freq.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy

    def _detect_packers(self, data: bytes) -> List[str]:
        """
        Detects common packers by searching for their signatures in the data.

        Args:
            data: The data (in bytes) to scan.

        Returns:
            A list of names of detected packers.
        """
        detected = []
        for packer, signatures in self.packer_signatures.items():
            for signature in signatures:
                if signature in data:
                    detected.append(packer)
                    break  # Move to the next packer once one signature is found
        return detected


# --- FastAPI Endpoint Schema (for documentation purposes) ---
"""
from pydantic import BaseModel
from typing import List

class ObfuscationAnalysisRequest(BaseModel):
    file_path: str

class ObfuscationAnalysisResponse(BaseModel):
    file_path: str
    entropy: float
    packers_detected: List[str]
    is_obfuscated: bool
    error: str = None

# Example FastAPI endpoint:
# @app.post("/api/v1/analyze/obfuscation", response_model=ObfuscationAnalysisResponse)
# async def analyze_obfuscation(request: ObfuscationAnalysisRequest):
#     detector = T1027ObfuscationDetector()
#     result = detector.analyze_file(Path(request.file_path))
#     return result
"""
