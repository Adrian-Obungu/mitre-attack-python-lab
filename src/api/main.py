"""
FastAPI application for MITRE ATT&CK Python Lab
"""

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
import logging
from typing import List

# Import route modules
from .routes import recon_routes, persistence_routes, privilege_routes

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from .security import verify_api_key

# Create FastAPI app
app = FastAPI(
    title="MITRE ATT&CK Python Lab API",
    description="API for security testing and detection tools",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(recon_routes.router)
app.include_router(persistence_routes.router)
app.include_router(privilege_routes.router)

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "MITRE ATT&CK Python Lab API",
        "version": "1.0.0",
        "endpoints": [
            "/recon/* - Reconnaissance tools",
            "/persistence/* - Persistence detection",
            "/privilege/* - Privilege escalation detection",
            "/docs - API documentation",
            "/health - Health check"
        ]
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "mitre-attack-lab"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
