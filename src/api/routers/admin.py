from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict

from src.api.security.auth import requires_permission, get_mock_users
from src.api.security.rbac import Permission, UserRole

router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
    dependencies=[Depends(requires_permission(Permission.MANAGE_USERS))]
)

class UserRoleAssignment(BaseModel):
    api_key: str
    role: UserRole

@router.post("/users", summary="Assign a role to a user")
def assign_role(assignment: UserRoleAssignment, mock_users: Dict[str, UserRole] = Depends(get_mock_users)):
    """
    Assign a role to a user specified by their API key.
    """
    if assignment.api_key not in mock_users:
        raise HTTPException(status_code=404, detail="User not found")
    
    mock_users[assignment.api_key] = assignment.role
    return {"message": f"User {assignment.api_key} assigned role {assignment.role.value}"}

@router.get("/users", summary="List all users and their roles")
def list_users(mock_users: Dict[str, UserRole] = Depends(get_mock_users)) -> Dict[str, UserRole]:
    """
    List all users and their current roles.
    """
    return mock_users
