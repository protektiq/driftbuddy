"""
Database models for DriftBuddy Web Interface
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class UserRole(str, Enum):
    """User roles for RBAC"""

    DEVELOPER = "developer"
    APPSEC = "appsec"
    ADMIN = "admin"


class ScanStatus(str, Enum):
    """Scan status enumeration"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class User(Base):
    """User model for authentication and RBAC"""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default=UserRole.DEVELOPER.value, nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="users")
    scans = relationship("Scan", back_populates="user")


class Organization(Base):
    """Organization model for multi-tenancy"""

    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, index=True, nullable=False)
    settings = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    users = relationship("User", back_populates="organization")


class Scan(Base):
    """Scan model for tracking security scans"""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default=ScanStatus.PENDING.value, nullable=False)
    scan_type = Column(String(50), default="kics", nullable=False)  # kics, steampipe, combined
    results = Column(JSON, default={})
    metadata = Column(JSON, default={})  # File paths, scan configuration, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="scans")
    organization = relationship("Organization")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    """Finding model for security issues"""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    query_name = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)  # HIGH, MEDIUM, LOW, INFO
    description = Column(Text, nullable=False)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    remediation = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=True)  # 1-25 scale
    business_impact = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")


class ChatHistory(Base):
    """Chat history for AI interactions"""

    __tablename__ = "chat_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=False)
    metadata = Column(JSON, default={})  # AI model used, tokens, etc.
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User")
    scan = relationship("Scan")


# Pydantic models for API requests/responses
class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    role: UserRole = UserRole.DEVELOPER
    organization_id: Optional[int] = None


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    role: UserRole
    organization_id: Optional[int]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    name: str
    description: Optional[str] = None
    scan_type: str = "kics"


class ScanResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    status: ScanStatus
    scan_type: str
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime]
    findings_count: Optional[int] = 0

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: int
    query_name: str
    severity: str
    description: str
    file_path: Optional[str]
    line_number: Optional[int]
    remediation: Optional[str]
    ai_explanation: Optional[str]
    risk_score: Optional[int]
    business_impact: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ChatMessage(BaseModel):
    prompt: str
    scan_id: Optional[int] = None


class ChatResponse(BaseModel):
    response: str
    metadata: dict
    created_at: datetime

    class Config:
        from_attributes = True
