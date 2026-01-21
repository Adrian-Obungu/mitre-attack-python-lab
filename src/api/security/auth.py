from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from starlette.status import HTTP_403_FORBIDDEN, HTTP_401_UNAUTHORIZED
import os
import logging
from typing import Optional, Dict

from .rbac import UserRole, Permission, ROLE_PERMISSIONS

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Mock user database
# In a real application, this would be a database query.
MOCK_USERS: Dict[str, UserRole] = {
    os.getenv("API_KEY", "test_api_key"): UserRole.ANALYST,
    os.getenv("ADMIN_API_KEY", "admin_api_key"): UserRole.ADMIN,
    "demo-key-2024": UserRole.VIEWER,
}

def get_mock_users() -> Dict[str, UserRole]:
    return MOCK_USERS

class User:
    def __init__(self, api_key: str, role: UserRole):
        self.api_key = api_key
        self.role = role

async def get_current_user(api_key: str = Security(api_key_header), mock_users: Dict[str, UserRole] = Depends(get_mock_users)) -> User:
    if not api_key:
        logger.warning("Missing API Key")
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Missing API Key",
        )
    
    role = mock_users.get(api_key)
    if not role:
        logger.warning(f"Invalid API Key: {api_key}")
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Could not validate credentials"
        )
    
    logger.info(f"User with role {role.value} authenticated successfully.")
    return User(api_key=api_key, role=role)

def requires_permission(permission: Permission):
    def dependency(user: User = Depends(get_current_user)) -> bool:
        user_permissions = ROLE_PERMISSIONS.get(user.role, [])
        if permission not in user_permissions:
            logger.error(f"User with role {user.role.value} does not have permission {permission.value}")
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail=f"User does not have permission: {permission.value}",
            )
        logger.info(f"User with role {user.role.value} has required permission: {permission.value}")
        return True
    return dependency
