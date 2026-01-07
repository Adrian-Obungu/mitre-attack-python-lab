"""
API Security Utilities
"""

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader

# API Key security (simplified for development)
API_KEY = "dev-key-123"  # In production, use environment variable
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    """Verify API key for protected endpoints"""
    if not api_key or api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API Key")
    return api_key
