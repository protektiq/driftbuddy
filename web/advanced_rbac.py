"""
Advanced RBAC for DriftBuddy Web Interface - Phase 3
Provides custom roles, permissions, and hierarchical access control
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship

from .auth import get_current_active_user
from .models import Organization, User, UserRole

# Additional RBAC models
Base = declarative_base()

# Many-to-many relationship tables
user_roles = Table("user_roles", Base.metadata, Column("user_id", Integer, ForeignKey("users.id")), Column("role_id", Integer, ForeignKey("custom_roles.id")))

role_permissions = Table(
    "role_permissions", Base.metadata, Column("role_id", Integer, ForeignKey("custom_roles.id")), Column("permission_id", Integer, ForeignKey("permissions.id"))
)


class CustomRole(Base):
    """Custom role model for advanced RBAC"""

    __tablename__ = "custom_roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(500))
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="custom_roles")
    users = relationship("User", secondary=user_roles, back_populates="custom_roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")


class Permission(Base):
    """Permission model for granular access control"""

    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(500))
    resource = Column(String(100), nullable=False)  # e.g., "scan", "user", "report"
    action = Column(String(100), nullable=False)  # e.g., "create", "read", "update", "delete"
    conditions = Column(JSON)  # Additional conditions for permission
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    roles = relationship("CustomRole", secondary=role_permissions, back_populates="permissions")


class RoleHierarchy(Base):
    """Role hierarchy model for inheritance"""

    __tablename__ = "role_hierarchies"

    id = Column(Integer, primary_key=True, index=True)
    parent_role_id = Column(Integer, ForeignKey("custom_roles.id"), nullable=False)
    child_role_id = Column(Integer, ForeignKey("custom_roles.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    parent_role = relationship("CustomRole", foreign_keys=[parent_role_id])
    child_role = relationship("CustomRole", foreign_keys=[child_role_id])


class AdvancedRBAC:
    """Advanced RBAC system with custom roles and permissions"""

    def __init__(self):
        self.default_permissions = self._load_default_permissions()
        self.role_templates = self._load_role_templates()

    def _load_default_permissions(self) -> Dict[str, List[Dict[str, str]]]:
        """Load default permissions for different resources"""
        return {
            "scan": [
                {"action": "create", "description": "Create new scans"},
                {"action": "read", "description": "View scan results"},
                {"action": "update", "description": "Modify scan settings"},
                {"action": "delete", "description": "Delete scans"},
                {"action": "run", "description": "Execute scans"},
                {"action": "export", "description": "Export scan data"},
            ],
            "user": [
                {"action": "create", "description": "Create new users"},
                {"action": "read", "description": "View user information"},
                {"action": "update", "description": "Modify user settings"},
                {"action": "delete", "description": "Delete users"},
                {"action": "assign_roles", "description": "Assign roles to users"},
            ],
            "report": [
                {"action": "create", "description": "Generate reports"},
                {"action": "read", "description": "View reports"},
                {"action": "export", "description": "Export reports"},
                {"action": "schedule", "description": "Schedule report generation"},
            ],
            "organization": [
                {"action": "read", "description": "View organization information"},
                {"action": "update", "description": "Modify organization settings"},
                {"action": "manage_users", "description": "Manage organization users"},
                {"action": "manage_roles", "description": "Manage organization roles"},
            ],
            "cloud": [
                {"action": "connect", "description": "Connect cloud accounts"},
                {"action": "scan", "description": "Scan cloud infrastructure"},
                {"action": "manage_credentials", "description": "Manage cloud credentials"},
            ],
            "compliance": [
                {"action": "read", "description": "View compliance reports"},
                {"action": "generate", "description": "Generate compliance reports"},
                {"action": "export", "description": "Export compliance data"},
            ],
        }

    def _load_role_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load predefined role templates"""
        return {
            "security_analyst": {
                "name": "Security Analyst",
                "description": "Security analyst with comprehensive access to security features",
                "permissions": [
                    "scan:create",
                    "scan:read",
                    "scan:run",
                    "scan:export",
                    "report:create",
                    "report:read",
                    "report:export",
                    "cloud:connect",
                    "cloud:scan",
                    "compliance:read",
                    "compliance:generate",
                    "compliance:export",
                ],
            },
            "security_manager": {
                "name": "Security Manager",
                "description": "Security manager with team management capabilities",
                "permissions": [
                    "scan:create",
                    "scan:read",
                    "scan:update",
                    "scan:delete",
                    "scan:run",
                    "scan:export",
                    "user:read",
                    "user:update",
                    "report:create",
                    "report:read",
                    "report:export",
                    "report:schedule",
                    "cloud:connect",
                    "cloud:scan",
                    "cloud:manage_credentials",
                    "compliance:read",
                    "compliance:generate",
                    "compliance:export",
                    "organization:read",
                    "organization:manage_users",
                ],
            },
            "compliance_auditor": {
                "name": "Compliance Auditor",
                "description": "Compliance auditor with focus on reporting and auditing",
                "permissions": [
                    "scan:read",
                    "scan:export",
                    "report:create",
                    "report:read",
                    "report:export",
                    "report:schedule",
                    "compliance:read",
                    "compliance:generate",
                    "compliance:export",
                ],
            },
            "developer": {
                "name": "Developer",
                "description": "Developer with limited access to security features",
                "permissions": ["scan:create", "scan:read", "scan:run", "report:read"],
            },
            "viewer": {"name": "Viewer", "description": "Read-only access to security information", "permissions": ["scan:read", "report:read"]},
        }

    async def create_custom_role(
        self, db: Session, name: str, description: str, organization_id: int, permissions: List[str], created_by: User
    ) -> Dict[str, Any]:
        """Create a custom role with specific permissions"""
        try:
            # Check if role name already exists
            existing_role = db.query(CustomRole).filter(CustomRole.name == name, CustomRole.organization_id == organization_id).first()

            if existing_role:
                return {"success": False, "error": "Role name already exists"}

            # Create custom role
            role = CustomRole(name=name, description=description, organization_id=organization_id, created_at=datetime.utcnow(), updated_at=datetime.utcnow())

            db.add(role)
            db.flush()  # Get the role ID

            # Add permissions
            for permission_name in permissions:
                permission = db.query(Permission).filter(Permission.name == permission_name).first()
                if permission:
                    role.permissions.append(permission)

            db.commit()

            return {
                "success": True,
                "role": {"id": role.id, "name": role.name, "description": role.description, "permissions": [p.name for p in role.permissions]},
            }

        except Exception as e:
            db.rollback()
            return {"success": False, "error": f"Failed to create role: {str(e)}"}

    async def create_role_from_template(
        self, db: Session, template_name: str, organization_id: int, custom_name: Optional[str] = None, additional_permissions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Create a role from a predefined template"""
        if template_name not in self.role_templates:
            return {"success": False, "error": f"Template {template_name} not found"}

        template = self.role_templates[template_name]
        name = custom_name or template["name"]
        permissions = template["permissions"].copy()

        if additional_permissions:
            permissions.extend(additional_permissions)

        return await self.create_custom_role(
            db=db, name=name, description=template["description"], organization_id=organization_id, permissions=permissions, created_by=None  # System created
        )

    async def assign_role_to_user(self, db: Session, user_id: int, role_id: int, assigned_by: User) -> Dict[str, Any]:
        """Assign a custom role to a user"""
        try:
            user = db.query(User).filter(User.id == user_id).first()
            role = db.query(CustomRole).filter(CustomRole.id == role_id).first()

            if not user:
                return {"success": False, "error": "User not found"}

            if not role:
                return {"success": False, "error": "Role not found"}

            # Check if user already has this role
            if role in user.custom_roles:
                return {"success": False, "error": "User already has this role"}

            # Assign role
            user.custom_roles.append(role)
            db.commit()

            return {"success": True, "message": f"Role {role.name} assigned to user {user.username}"}

        except Exception as e:
            db.rollback()
            return {"success": False, "error": f"Failed to assign role: {str(e)}"}

    async def remove_role_from_user(self, db: Session, user_id: int, role_id: int, removed_by: User) -> Dict[str, Any]:
        """Remove a custom role from a user"""
        try:
            user = db.query(User).filter(User.id == user_id).first()
            role = db.query(CustomRole).filter(CustomRole.id == role_id).first()

            if not user:
                return {"success": False, "error": "User not found"}

            if not role:
                return {"success": False, "error": "Role not found"}

            # Remove role
            if role in user.custom_roles:
                user.custom_roles.remove(role)
                db.commit()

                return {"success": True, "message": f"Role {role.name} removed from user {user.username}"}
            else:
                return {"success": False, "error": "User does not have this role"}

        except Exception as e:
            db.rollback()
            return {"success": False, "error": f"Failed to remove role: {str(e)}"}

    async def check_permission(self, db: Session, user: User, resource: str, action: str, conditions: Optional[Dict[str, Any]] = None) -> bool:
        """Check if user has permission for specific resource and action"""
        try:
            # Get all permissions for the user (including inherited)
            user_permissions = await self._get_user_permissions(db, user)

            # Check for exact permission
            permission_name = f"{resource}:{action}"
            if permission_name in user_permissions:
                # Check conditions if provided
                if conditions:
                    return await self._check_permission_conditions(db, user, permission_name, conditions)
                return True

            # Check for wildcard permissions
            wildcard_permission = f"{resource}:*"
            if wildcard_permission in user_permissions:
                if conditions:
                    return await self._check_permission_conditions(db, user, wildcard_permission, conditions)
                return True

            return False

        except Exception as e:
            print(f"Permission check failed: {str(e)}")
            return False

    async def _get_user_permissions(self, db: Session, user: User) -> Set[str]:
        """Get all permissions for a user including inherited ones"""
        permissions = set()

        # Get permissions from custom roles
        for role in user.custom_roles:
            for permission in role.permissions:
                permissions.add(permission.name)

        # Get permissions from built-in role
        built_in_permissions = self._get_built_in_permissions(user.role)
        permissions.update(built_in_permissions)

        # Get inherited permissions from role hierarchy
        inherited_permissions = await self._get_inherited_permissions(db, user)
        permissions.update(inherited_permissions)

        return permissions

    def _get_built_in_permissions(self, role: str) -> Set[str]:
        """Get permissions for built-in roles"""
        role_permissions = {
            "admin": ["*:*"],  # All permissions
            "appsec": ["scan:*", "report:*", "cloud:*", "compliance:*", "user:read", "user:update", "organization:read"],
            "developer": ["scan:create", "scan:read", "scan:run", "report:read"],
        }

        return set(role_permissions.get(role, []))

    async def _get_inherited_permissions(self, db: Session, user: User) -> Set[str]:
        """Get permissions inherited through role hierarchy"""
        inherited_permissions = set()

        for role in user.custom_roles:
            # Get parent roles
            parent_roles = db.query(CustomRole).join(RoleHierarchy).filter(RoleHierarchy.child_role_id == role.id).all()

            for parent_role in parent_roles:
                for permission in parent_role.permissions:
                    inherited_permissions.add(permission.name)

        return inherited_permissions

    async def _check_permission_conditions(self, db: Session, user: User, permission_name: str, conditions: Dict[str, Any]) -> bool:
        """Check additional conditions for permission"""
        # Example conditions:
        # - organization_id: user must belong to specific organization
        # - time_restriction: permission only valid during certain hours
        # - ip_restriction: permission only valid from specific IP ranges

        if "organization_id" in conditions:
            if user.organization_id != conditions["organization_id"]:
                return False

        if "time_restriction" in conditions:
            current_hour = datetime.utcnow().hour
            start_hour = conditions["time_restriction"].get("start", 0)
            end_hour = conditions["time_restriction"].get("end", 23)

            if not (start_hour <= current_hour <= end_hour):
                return False

        if "ip_restriction" in conditions:
            # This would require request context
            # For now, return True
            pass

        return True

    async def get_user_roles(self, db: Session, user: User) -> List[Dict[str, Any]]:
        """Get all roles for a user"""
        roles = []

        # Built-in role
        roles.append({"id": None, "name": user.role, "type": "built_in", "description": f"Built-in {user.role} role"})

        # Custom roles
        for role in user.custom_roles:
            roles.append(
                {"id": role.id, "name": role.name, "type": "custom", "description": role.description, "permissions": [p.name for p in role.permissions]}
            )

        return roles

    async def get_organization_roles(self, db: Session, organization_id: int) -> List[Dict[str, Any]]:
        """Get all roles for an organization"""
        roles = db.query(CustomRole).filter(CustomRole.organization_id == organization_id, CustomRole.is_active == True).all()

        return [
            {
                "id": role.id,
                "name": role.name,
                "description": role.description,
                "permissions": [p.name for p in role.permissions],
                "user_count": len(role.users),
            }
            for role in roles
        ]

    async def get_available_permissions(self) -> Dict[str, List[Dict[str, str]]]:
        """Get all available permissions"""
        return self.default_permissions

    async def get_role_templates(self) -> Dict[str, Dict[str, Any]]:
        """Get available role templates"""
        return self.role_templates

    async def create_permission(
        self, db: Session, name: str, description: str, resource: str, action: str, conditions: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create a new permission"""
        try:
            # Check if permission already exists
            existing_permission = db.query(Permission).filter(Permission.name == name).first()

            if existing_permission:
                return {"success": False, "error": "Permission already exists"}

            # Create permission
            permission = Permission(
                name=name, description=description, resource=resource, action=action, conditions=conditions or {}, created_at=datetime.utcnow()
            )

            db.add(permission)
            db.commit()

            return {
                "success": True,
                "permission": {
                    "id": permission.id,
                    "name": permission.name,
                    "description": permission.description,
                    "resource": permission.resource,
                    "action": permission.action,
                },
            }

        except Exception as e:
            db.rollback()
            return {"success": False, "error": f"Failed to create permission: {str(e)}"}

    async def setup_default_permissions(self, db: Session) -> Dict[str, Any]:
        """Set up default permissions in the database"""
        try:
            created_count = 0

            for resource, permissions in self.default_permissions.items():
                for perm in permissions:
                    permission_name = f"{resource}:{perm['action']}"

                    # Check if permission already exists
                    existing = db.query(Permission).filter(Permission.name == permission_name).first()

                    if not existing:
                        permission = Permission(
                            name=permission_name,
                            description=perm["description"],
                            resource=resource,
                            action=perm["action"],
                            conditions={},
                            created_at=datetime.utcnow(),
                        )

                        db.add(permission)
                        created_count += 1

            db.commit()

            return {"success": True, "message": f"Created {created_count} default permissions"}

        except Exception as e:
            db.rollback()
            return {"success": False, "error": f"Failed to setup permissions: {str(e)}"}
