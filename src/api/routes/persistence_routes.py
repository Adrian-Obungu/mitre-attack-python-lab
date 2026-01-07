"""
Persistence API Routes
"""

from fastapi import APIRouter, HTTPException
import logging

router = APIRouter(
    prefix="/persistence",
    tags=["persistence"],
)

@router.get("/health")
async def persistence_health():
    return {"status": "healthy", "module": "persistence"}
