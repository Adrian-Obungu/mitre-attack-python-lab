"""
Reconnaissance API Routes
"""

from fastapi import APIRouter, HTTPException
import logging

router = APIRouter(
    prefix="/recon",
    tags=["reconnaissance"],
)

@router.get("/health")
async def recon_health():
    return {"status": "healthy", "module": "reconnaissance"}
