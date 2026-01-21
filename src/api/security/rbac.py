from enum import Enum
from typing import Dict, List

class UserRole(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"
    AUDITOR = "auditor"

class Permission(str, Enum):
    READ_DISCOVERY = "read:discovery"
    READ_EVASION = "read:evasion"
    READ_LATERAL = "read:lateral"
    WRITE_SCAN = "write:scan"
    MANAGE_USERS = "manage:users"
    READ_AUDIT = "read:audit" # For auditors

# Mapping of roles to their granted permissions
ROLE_PERMISSIONS: Dict[UserRole, List[Permission]] = {
    UserRole.VIEWER: [
        Permission.READ_DISCOVERY,
    ],
    UserRole.ANALYST: [
        Permission.READ_DISCOVERY,
        Permission.READ_EVASION,
        Permission.READ_LATERAL,
    ],
    UserRole.ADMIN: [
        Permission.READ_DISCOVERY,
        Permission.READ_EVASION,
        Permission.READ_LATERAL,
        Permission.WRITE_SCAN,
        Permission.MANAGE_USERS,
        Permission.READ_AUDIT,
    ],
    UserRole.AUDITOR: [
        Permission.READ_DISCOVERY,
        Permission.READ_EVASION,
        Permission.READ_LATERAL,
        Permission.READ_AUDIT,
    ],
}
