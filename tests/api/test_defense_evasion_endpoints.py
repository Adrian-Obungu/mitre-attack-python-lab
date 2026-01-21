import pytest
from fastapi.testclient import TestClient
from src.api.main import app
import platform

client = TestClient(app)

def test_read_main():
    response = client.get("/")
    assert response.status_code == 200

def test_registry_endpoint():
    if platform.system() != "Windows":
        pytest.skip("Windows-specific test")
    
    # Create a dummy baseline file
    with open("registry_baseline.json", "w") as f:
        f.write('{"keys": {"HKCU_Run": ["HKEY_CURRENT_USER", "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"]}, "snapshot": {"HKCU_Run": {}}}')

    response = client.post("/api/v1/analyze/registry", json={"baseline_path": "registry_baseline.json"})
    assert response.status_code == 200
    assert "changes" in response.json()

def test_defense_impairment_endpoint():
    response = client.post("/api/v1/analyze/defense-impairment", json={"quick_scan": True})
    assert response.status_code == 200
    assert "stopped_services" in response.json()

def test_elevation_endpoint():
    response = client.post("/api/v1/analyze/elevation", json={"quick_scan": True})
    assert response.status_code == 200
    assert "uac_enabled" in response.json()

def test_scan_all_endpoint():
    response = client.post("/api/v1/analyze/scan-all", json={"quick_scan": True})
    assert response.status_code == 200
    data = response.json()
    assert "obfuscation" in data
    assert "indicator_removal" in data
    assert "registry" in data
    assert "defense_impairment" in data
    assert "elevation" in data
