"""
Advanced RBAC API for DriftBuddy Web Interface - Phase 3
Provides comprehensive role-based access control with custom roles, permissions, and hierarchies
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Form, status
from sqlalchemy.orm import Session

from .auth import get_current_active_user, require_admin
from .database import get_db
from .models import (
    CustomRole,
    CustomRoleCreate,
    CustomRoleResponse,
    Permission,
    PermissionResponse,
    RoleHierarchy,
    User,
    UserResponse,
)
from .advanced_rbac import AdvancedRBAC

# Create router
router = APIRouter(prefix="/api/rbac", tags=["RBAC"])

# Initialize RBAC service
rbac_service = AdvancedRBAC()


@router.post("/roles", response_model=Dict[str, Any])
async def create_custom_role(
    name: str = Form(...),
    description: str = Form(...),
    organization_id: int = Form(...),
    permissions: str = Form(...),  # JSON string of permissions
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create a custom role with specific permissions"""
    try:
        permissions_list = json.loads(permissions)
        result = await rbac_service.create_custom_role(
            db, name, description, organization_id, permissions_list, current_user
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create role: {str(e)}")


@router.post("/roles/template", response_model=Dict[str, Any])
async def create_role_from_template(
    template_name: str = Form(...),
    organization_id: int = Form(...),
    custom_name: Optional[str] = Form(None),
    additional_permissions: Optional[str] = Form(None),  # JSON string
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create a role from a predefined template"""
    try:
        additional_perms = json.loads(additional_permissions) if additional_permissions else None
        result = await rbac_service.create_role_from_template(
            db, template_name, organization_id, custom_name, additional_perms
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create role from template: {str(e)}")


@router.get("/roles", response_model=List[CustomRoleResponse])
async def list_custom_roles(
    organization_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all custom roles for an organization"""
    try:
        if organization_id is None:
            organization_id = current_user.organization_id

        roles = await rbac_service.get_organization_roles(db, organization_id)
        return roles
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get roles: {str(e)}")


@router.get("/roles/{role_id}", response_model=CustomRoleResponse)
async def get_custom_role(
    role_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific custom role"""
    try:
        role = db.query(CustomRole).filter(CustomRole.id == role_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        # Check if user has access to this role
        if role.organization_id != current_user.organization_id and current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Access denied")

        return CustomRoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            organization_id=role.organization_id,
            is_active=role.is_active,
            permissions=[p.name for p in role.permissions],
            user_count=len(role.users),
            created_at=role.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get role: {str(e)}")


@router.put("/roles/{role_id}", response_model=Dict[str, Any])
async def update_custom_role(
    role_id: int,
    name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    permissions: Optional[str] = Form(None),  # JSON string
    is_active: Optional[bool] = Form(None),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update a custom role"""
    try:
        role = db.query(CustomRole).filter(CustomRole.id == role_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        # Update fields
        if name is not None:
            role.name = name
        if description is not None:
            role.description = description
        if is_active is not None:
            role.is_active = is_active
        if permissions is not None:
            permissions_list = json.loads(permissions)
            # Clear existing permissions and add new ones
            role.permissions.clear()
            for perm_name in permissions_list:
                permission = db.query(Permission).filter(Permission.name == perm_name).first()
                if permission:
                    role.permissions.append(permission)

        role.updated_at = datetime.utcnow()
        db.commit()

        return {
            "success": True,
            "message": f"Role {role.name} updated successfully",
            "role": {
                "id": role.id,
                "name": role.name,
                "description": role.description,
                "permissions": [p.name for p in role.permissions]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to update role: {str(e)}")


@router.delete("/roles/{role_id}", response_model=Dict[str, Any])
async def delete_custom_role(
    role_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete a custom role"""
    try:
        role = db.query(CustomRole).filter(CustomRole.id == role_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        # Check if role is assigned to any users
        if role.users:
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot delete role '{role.name}' - it is assigned to {len(role.users)} users"
            )

        db.delete(role)
        db.commit()

        return {"success": True, "message": f"Role {role.name} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to delete role: {str(e)}")


@router.post("/users/{user_id}/roles/{role_id}", response_model=Dict[str, Any])
async def assign_role_to_user(
    user_id: int,
    role_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Assign a role to a user"""
    try:
        result = await rbac_service.assign_role_to_user(db, user_id, role_id, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to assign role: {str(e)}")


@router.delete("/users/{user_id}/roles/{role_id}", response_model=Dict[str, Any])
async def remove_role_from_user(
    user_id: int,
    role_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Remove a role from a user"""
    try:
        result = await rbac_service.remove_role_from_user(db, user_id, role_id, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to remove role: {str(e)}")


@router.get("/users/{user_id}/roles", response_model=List[Dict[str, Any]])
async def get_user_roles(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all roles for a user"""
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check if current user has access to view this user's roles
        if user.id != current_user.id and current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Access denied")

        roles = await rbac_service.get_user_roles(db, user)
        return roles
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get user roles: {str(e)}")


@router.get("/permissions", response_model=Dict[str, List[Dict[str, str]]], operation_id="get_available_permissions_rbac")
async def get_available_permissions(current_user: User = Depends(get_current_active_user)):
    """Get available permissions for role creation"""
    try:
        permissions = await rbac_service.get_available_permissions()
        return permissions
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get permissions: {str(e)}")


@router.get("/templates", response_model=Dict[str, Dict[str, Any]], operation_id="get_role_templates_rbac")
async def get_role_templates(current_user: User = Depends(get_current_active_user)):
    """Get available role templates"""
    try:
        templates = await rbac_service.get_role_templates()
        return templates
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get role templates: {str(e)}")


@router.post("/permissions", response_model=Dict[str, Any])
async def create_permission(
    name: str = Form(...),
    description: str = Form(...),
    resource: str = Form(...),
    action: str = Form(...),
    conditions: Optional[str] = Form(None),  # JSON string
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create a new permission"""
    try:
        conditions_dict = json.loads(conditions) if conditions else None
        result = await rbac_service.create_permission(
            db, name, description, resource, action, conditions_dict
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create permission: {str(e)}")


@router.get("/permissions/all", response_model=List[PermissionResponse])
async def list_all_permissions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all permissions in the system"""
    try:
        permissions = db.query(Permission).all()
        return [
            PermissionResponse(
                id=p.id,
                name=p.name,
                description=p.description,
                resource=p.resource,
                action=p.action,
                conditions=p.conditions or {}
            )
            for p in permissions
        ]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get permissions: {str(e)}")


@router.post("/hierarchy", response_model=Dict[str, Any])
async def create_role_hierarchy(
    parent_role_id: int = Form(...),
    child_role_id: int = Form(...),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create a role hierarchy relationship"""
    try:
        # Check if roles exist
        parent_role = db.query(CustomRole).filter(CustomRole.id == parent_role_id).first()
        child_role = db.query(CustomRole).filter(CustomRole.id == child_role_id).first()

        if not parent_role or not child_role:
            raise HTTPException(status_code=404, detail="Role not found")

        # Check for circular references
        if parent_role_id == child_role_id:
            raise HTTPException(status_code=400, detail="Cannot create hierarchy with same role")

        # Check if hierarchy already exists
        existing = db.query(RoleHierarchy).filter(
            RoleHierarchy.parent_role_id == parent_role_id,
            RoleHierarchy.child_role_id == child_role_id
        ).first()

        if existing:
            raise HTTPException(status_code=400, detail="Role hierarchy already exists")

        # Create hierarchy
        hierarchy = RoleHierarchy(
            parent_role_id=parent_role_id,
            child_role_id=child_role_id,
            created_at=datetime.utcnow()
        )

        db.add(hierarchy)
        db.commit()

        return {
            "success": True,
            "message": f"Role hierarchy created: {parent_role.name} -> {child_role.name}"
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create hierarchy: {str(e)}")


@router.delete("/hierarchy/{hierarchy_id}", response_model=Dict[str, Any])
async def delete_role_hierarchy(
    hierarchy_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete a role hierarchy relationship"""
    try:
        hierarchy = db.query(RoleHierarchy).filter(RoleHierarchy.id == hierarchy_id).first()
        if not hierarchy:
            raise HTTPException(status_code=404, detail="Role hierarchy not found")

        db.delete(hierarchy)
        db.commit()

        return {"success": True, "message": "Role hierarchy deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to delete hierarchy: {str(e)}")


@router.get("/hierarchy", response_model=List[Dict[str, Any]])
async def list_role_hierarchies(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all role hierarchies"""
    try:
        hierarchies = db.query(RoleHierarchy).all()
        return [
            {
                "id": h.id,
                "parent_role": {"id": h.parent_role.id, "name": h.parent_role.name},
                "child_role": {"id": h.child_role.id, "name": h.child_role.name},
                "created_at": h.created_at
            }
            for h in hierarchies
        ]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get hierarchies: {str(e)}")


@router.post("/check-permission", response_model=Dict[str, Any])
async def check_user_permission(
    resource: str = Form(...),
    action: str = Form(...),
    conditions: Optional[str] = Form(None),  # JSON string
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Check if current user has a specific permission"""
    try:
        conditions_dict = json.loads(conditions) if conditions else None
        has_permission = await rbac_service.check_permission(
            db, current_user, resource, action, conditions_dict
        )

        return {
            "has_permission": has_permission,
            "user_id": current_user.id,
            "resource": resource,
            "action": action,
            "conditions": conditions_dict
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to check permission: {str(e)}")


@router.get("/my-permissions", response_model=Dict[str, Any])
async def get_my_permissions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all permissions for the current user"""
    try:
        user_permissions = await rbac_service._get_user_permissions(db, current_user)
        user_roles = await rbac_service.get_user_roles(db, current_user)

        return {
            "user_id": current_user.id,
            "username": current_user.username,
            "built_in_role": current_user.role,
            "custom_roles": [r for r in user_roles if r["type"] == "custom"],
            "permissions": list(user_permissions)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get user permissions: {str(e)}")


@router.post("/setup-defaults", response_model=Dict[str, Any])
async def setup_default_rbac(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Set up default RBAC permissions and roles"""
    try:
        from .database import setup_rbac_system
        setup_rbac_system(db)
        return {"success": True, "message": "RBAC system initialized successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to setup RBAC: {str(e)}") 