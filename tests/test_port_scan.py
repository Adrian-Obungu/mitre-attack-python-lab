#!/usr/bin/env python3
"""Tests for PortScan_Enhanced.py"""

import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_import_port_scanner():
    """Test that PortScanner can be imported"""
    try:
        from reconnaissance.PortScan_Enhanced import PortScanner
        assert True
    except ImportError as e:
        pytest.fail(f"Failed to import PortScanner: {e}")

def test_dummy():
    """Dummy test to ensure pytest works"""
    assert 1 + 1 == 2

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
