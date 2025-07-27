"""
Authentication and authorization utilities for DriftBuddy Web Interface
"""

import os
from datetime import datetime, timedelta
from typing import Optional, Union

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .database import get_db
from .models import User, UserRole

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token scheme
security = HTTPBearer()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> Optional[dict]:
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)) -> User:
    """Get the current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = verify_token(credentials.credentials)
        if payload is None:
            raise credentials_exception

        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception

    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get the current active user"""
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user


def check_permission(user: User, required_role: UserRole) -> bool:
    """Check if user has the required role permission"""
    role_hierarchy = {UserRole.DEVELOPER: 1, UserRole.APPSEC: 2, UserRole.ADMIN: 3}

    user_level = role_hierarchy.get(UserRole(user.role), 0)
    required_level = role_hierarchy.get(required_role, 0)

    return user_level >= required_level


def require_role(required_role: UserRole):
    """Dependency to require a specific role"""

    def role_checker(current_user: User = Depends(get_current_active_user)):
        if not check_permission(current_user, required_role):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Access denied. Required role: {required_role.value}")
        return current_user

    return role_checker


# Role-specific dependencies
require_developer = require_role(UserRole.DEVELOPER)
require_appsec = require_role(UserRole.APPSEC)
require_admin = require_role(UserRole.ADMIN)


def get_user_permissions(user: User) -> dict:
    """Get user permissions based on role"""
    base_permissions = {
        "view_scans": True,
        "create_scans": True,
        "view_findings": True,
        "view_chat": True,
    }

    if user.role == UserRole.ADMIN:
        base_permissions.update(
            {
                "manage_users": True,
                "manage_organizations": True,
                "view_all_scans": True,
                "delete_scans": True,
                "manage_settings": True,
            }
        )
    elif user.role == UserRole.APPSEC:
        base_permissions.update(
            {
                "view_all_scans": True,
                "delete_scans": True,
                "manage_settings": True,
            }
        )

    return base_permissions
