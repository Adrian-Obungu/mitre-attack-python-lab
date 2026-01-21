import secrets
import pytest
from pathlib import Path
from src.defense_evasion.obfuscation_detector import T1027ObfuscationDetector

@pytest.fixture
def mock_files(tmp_path):
    """
    Pytest fixture to create mock files for testing.
    - A normal text file with low entropy.
    - A file with high entropy (random bytes).
    - A file containing a UPX signature.
    """
    normal_file = tmp_path / "normal.txt"
    normal_file.write_text("This is a normal file with very low entropy." * 10)

    high_entropy_file = tmp_path / "high_entropy.bin"
    high_entropy_file.write_bytes(secrets.token_bytes(1024))  # Truly random

    upx_packed_file = tmp_path / "upx_packed.exe"
    upx_packed_file.write_bytes(b"Some executable data... UPX! ... more data")

    return {
        "normal": normal_file,
        "high_entropy": high_entropy_file,
        "upx_packed": upx_packed_file
    }

def test_detector_initialization():
    """Test that the detector initializes correctly."""
    detector = T1027ObfuscationDetector()
    assert detector is not None
    assert "UPX" in detector.packer_signatures

def test_entropy_calculation():
    """Test the entropy calculation logic."""
    detector = T1027ObfuscationDetector()
    # Low entropy data
    low_entropy_data = b"aaaaaaaa"
    assert detector._calculate_entropy(low_entropy_data) == 0.0

    # High entropy data
    high_entropy_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    assert detector._calculate_entropy(high_entropy_data) == 3.0

def test_packer_detection():
    """Test the packer detection logic."""
    detector = T1027ObfuscationDetector()
    upx_data = b"UPX! is a common signature."
    aspack_data = b"This file uses .aspack section."
    
    assert "UPX" in detector._detect_packers(upx_data)
    assert "ASPack" in detector._detect_packers(aspack_data)
    assert not detector._detect_packers(b"This is a normal file.")

def test_analyze_normal_file(mock_files):
    """Test analysis of a normal, non-obfuscated file."""
    detector = T1027ObfuscationDetector()
    result = detector.analyze_file(mock_files["normal"])
    
    assert not result["is_obfuscated"]
    assert "error" not in result
    assert result["entropy"] < 4.0 # Normal text should have low entropy
    assert not result["packers_detected"]

def test_analyze_high_entropy_file(mock_files):
    """Test analysis of a file with high entropy."""
    detector = T1027ObfuscationDetector()
    result = detector.analyze_file(mock_files["high_entropy"])
    
    assert result["is_obfuscated"]
    assert "error" not in result
    assert result["entropy"] > detector.entropy_threshold  # Should be ~7.9-8.0

def test_analyze_packed_file(mock_files):
    """Test analysis of a file with a packer signature."""
    detector = T1027ObfuscationDetector()
    result = detector.analyze_file(mock_files["upx_packed"])
    
    assert result["is_obfuscated"]
    assert "error" not in result
    assert "UPX" in result["packers_detected"]

def test_file_not_found():
    """Test that FileNotFoundError is raised for a non-existent file."""
    detector = T1027ObfuscationDetector()
    with pytest.raises(FileNotFoundError):
        detector.analyze_file(Path("non_existent_file.txt"))
