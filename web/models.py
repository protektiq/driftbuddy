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
    Table,
    Float,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

# Many-to-many relationship tables for RBAC
user_roles = Table(
    "user_roles", 
    Base.metadata, 
    Column("user_id", Integer, ForeignKey("users.id")), 
    Column("role_id", Integer, ForeignKey("custom_roles.id"))
)

role_permissions = Table(
    "role_permissions", 
    Base.metadata, 
    Column("role_id", Integer, ForeignKey("custom_roles.id")), 
    Column("permission_id", Integer, ForeignKey("permissions.id"))
)


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
    custom_roles = relationship("CustomRole", secondary=user_roles, back_populates="users")


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
    custom_roles = relationship("CustomRole", back_populates="organization")


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
    scan_metadata = Column(JSON, default={})  # File paths, scan configuration, etc.
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
    integration_id = Column(Integer, ForeignKey("integrations.id"), nullable=True)  # For external findings
    query_name = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)  # HIGH, MEDIUM, LOW, INFO
    description = Column(Text, nullable=False)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    remediation = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=True)  # 1-25 scale
    business_impact = Column(Text, nullable=True)
    source = Column(String(100), nullable=True)  # kics, aws_security_hub, github_dependabot, etc.
    raw_data = Column(JSON, default={})  # Original data from external source
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    integration = relationship("Integration", back_populates="findings")


class ChatHistory(Base):
    """Chat history for AI interactions"""

    __tablename__ = "chat_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    prompt = Column(Text, nullable=False)
    response = Column(Text, nullable=False)
    chat_metadata = Column(JSON, default={})  # AI model used, tokens, etc.
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
    organization_id: Optional[int] = None
    is_active: bool
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    name: str
    description: Optional[str] = None
    scan_type: str = "kics"
    target_path: Optional[str] = None


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


class Report(Base):
    """Report model for storing generated reports"""

    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    name = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False)  # scan_report, compliance_report, executive_summary
    format = Column(String(20), nullable=False)  # html, pdf, json
    status = Column(String(50), default="generating")  # generating, completed, failed
    file_path = Column(String(500), nullable=True)
    report_metadata = Column(JSON, default={})  # Executive summary, charts, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")
    scan = relationship("Scan")


class ReportResponse(BaseModel):
    id: int
    name: str
    report_type: str
    format: str
    status: str
    file_path: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ChatResponse(BaseModel):
    response: str
    metadata: dict
    created_at: datetime

    class Config:
        from_attributes = True


# RBAC Pydantic models
class CustomRoleCreate(BaseModel):
    name: str
    description: str
    organization_id: int
    permissions: List[str]


class CustomRoleResponse(BaseModel):
    id: int
    name: str
    description: str
    organization_id: int
    is_active: bool
    permissions: List[str]
    user_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class PermissionResponse(BaseModel):
    id: int
    name: str
    description: str
    resource: str
    action: str
    conditions: dict

    class Config:
        from_attributes = True


class RoleTemplateResponse(BaseModel):
    name: str
    description: str
    permissions: List[str]

    class Config:
        from_attributes = True


# Compliance Reporting Models
class ComplianceFramework(Base):
    """Compliance framework model (SOC 2, ISO 27001, PCI DSS, NIST)"""

    __tablename__ = "compliance_frameworks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)  # SOC 2, ISO 27001, PCI DSS, NIST
    version = Column(String(50), nullable=False)  # 2017, 2022, etc.
    description = Column(Text, nullable=True)
    category = Column(String(100), nullable=False)  # security, privacy, financial, etc.
    is_active = Column(Boolean, default=True)
    framework_metadata = Column(JSON, default={})  # Framework-specific metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    controls = relationship("ComplianceControl", back_populates="framework")
    assessments = relationship("ComplianceAssessment", back_populates="framework")


class ComplianceControl(Base):
    """Individual control within a compliance framework"""

    __tablename__ = "compliance_controls"

    id = Column(Integer, primary_key=True, index=True)
    framework_id = Column(Integer, ForeignKey("compliance_frameworks.id"), nullable=False)
    control_id = Column(String(100), nullable=False)  # CC6.1, A.5.1.1, etc.
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100), nullable=False)  # Access Control, Risk Assessment, etc.
    priority = Column(String(50), default="medium")  # high, medium, low
    implementation_guidance = Column(Text, nullable=True)
    testing_procedures = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    framework = relationship("ComplianceFramework", back_populates="controls")
    assessment_results = relationship("AssessmentControlResult", back_populates="control")


class ComplianceAssessment(Base):
    """Compliance assessment for a specific framework"""

    __tablename__ = "compliance_assessments"

    id = Column(Integer, primary_key=True, index=True)
    framework_id = Column(Integer, ForeignKey("compliance_frameworks.id"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    assessment_type = Column(String(100), nullable=False)  # initial, periodic, follow-up
    status = Column(String(50), default="draft")  # draft, in_progress, completed, failed
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    assessor_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    overall_score = Column(Integer, nullable=True)  # 0-100
    compliance_percentage = Column(Float, nullable=True)  # 0.0-100.0
    assessment_metadata = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    framework = relationship("ComplianceFramework", back_populates="assessments")
    organization = relationship("Organization")
    assessor = relationship("User")
    control_results = relationship("AssessmentControlResult", back_populates="assessment")
    evidence_items = relationship("ComplianceEvidence", back_populates="assessment")


class AssessmentControlResult(Base):
    """Results for individual controls within an assessment"""

    __tablename__ = "assessment_control_results"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("compliance_assessments.id"), nullable=False)
    control_id = Column(Integer, ForeignKey("compliance_controls.id"), nullable=False)
    status = Column(String(50), nullable=False)  # compliant, non_compliant, partially_compliant, not_applicable
    score = Column(Integer, nullable=True)  # 0-100
    findings = Column(Text, nullable=True)
    remediation_plan = Column(Text, nullable=True)
    evidence_count = Column(Integer, default=0)
    last_tested = Column(DateTime, nullable=True)
    tester_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    assessment = relationship("ComplianceAssessment", back_populates="control_results")
    control = relationship("ComplianceControl", back_populates="assessment_results")
    tester = relationship("User")
    evidence_items = relationship("ComplianceEvidence", back_populates="control_result")


class ComplianceEvidence(Base):
    """Evidence collected for compliance controls"""

    __tablename__ = "compliance_evidence"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("compliance_assessments.id"), nullable=False)
    control_result_id = Column(Integer, ForeignKey("assessment_control_results.id"), nullable=True)
    evidence_type = Column(String(100), nullable=False)  # document, screenshot, log, interview, observation
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    file_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)
    mime_type = Column(String(100), nullable=True)
    evidence_data = Column(JSON, nullable=True)  # Structured evidence data
    collected_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow)
    is_verified = Column(Boolean, default=False)
    verified_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    assessment = relationship("ComplianceAssessment", back_populates="evidence_items")
    control_result = relationship("AssessmentControlResult", back_populates="evidence_items")
    collector = relationship("User", foreign_keys=[collected_by])
    verifier = relationship("User", foreign_keys=[verified_by])


class AuditEvent(Base):
    """Audit trail for compliance activities"""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    event_type = Column(String(100), nullable=False)  # assessment_created, evidence_collected, control_tested
    event_category = Column(String(100), nullable=False)  # compliance, security, access
    description = Column(Text, nullable=False)
    resource_type = Column(String(100), nullable=True)  # assessment, control, evidence
    resource_id = Column(Integer, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    event_metadata = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User")


class RemediationTask(Base):
    """Remediation tasks for compliance gaps"""

    __tablename__ = "remediation_tasks"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("compliance_assessments.id"), nullable=False)
    control_result_id = Column(Integer, ForeignKey("assessment_control_results.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    priority = Column(String(50), default="medium")  # high, medium, low
    status = Column(String(50), default="open")  # open, in_progress, completed, cancelled
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    due_date = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    completion_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    assessment = relationship("ComplianceAssessment")
    control_result = relationship("AssessmentControlResult")
    assignee = relationship("User")


# Pydantic models for API
class ComplianceFrameworkCreate(BaseModel):
    name: str
    version: str
    description: Optional[str] = None
    category: str
    framework_metadata: Optional[dict] = {}


class ComplianceFrameworkResponse(BaseModel):
    id: int
    name: str
    version: str
    description: Optional[str]
    category: str
    is_active: bool
    control_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class ComplianceControlResponse(BaseModel):
    id: int
    control_id: str
    title: str
    description: str
    category: str
    priority: str
    implementation_guidance: Optional[str]
    testing_procedures: Optional[str]

    class Config:
        from_attributes = True


class ComplianceAssessmentCreate(BaseModel):
    framework_id: int
    name: str
    description: Optional[str] = None
    assessment_type: str
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None


class ComplianceAssessmentResponse(BaseModel):
    id: int
    framework_name: str
    name: str
    description: Optional[str]
    assessment_type: str
    status: str
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    overall_score: Optional[int]
    compliance_percentage: Optional[float]
    control_count: int
    compliant_count: int
    non_compliant_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class AssessmentControlResultResponse(BaseModel):
    id: int
    control_id: str
    control_title: str
    status: str
    score: Optional[int]
    findings: Optional[str]
    remediation_plan: Optional[str]
    evidence_count: int
    last_tested: Optional[datetime]

    class Config:
        from_attributes = True


class ComplianceEvidenceCreate(BaseModel):
    control_result_id: int
    evidence_type: str
    title: str
    description: Optional[str] = None
    evidence_data: Optional[dict] = None


class ComplianceEvidenceResponse(BaseModel):
    id: int
    evidence_type: str
    title: str
    description: Optional[str]
    file_path: Optional[str]
    file_size: Optional[int]
    mime_type: Optional[str]
    is_verified: bool
    collected_at: datetime
    verified_at: Optional[datetime]

    class Config:
        from_attributes = True


class AuditEventResponse(BaseModel):
    id: int
    event_type: str
    event_category: str
    description: str
    resource_type: Optional[str]
    resource_id: Optional[int]
    ip_address: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class RemediationTaskCreate(BaseModel):
    control_result_id: int
    title: str
    description: Optional[str] = None
    priority: str = "medium"
    assigned_to: Optional[int] = None
    due_date: Optional[datetime] = None


class RemediationTaskResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    priority: str
    status: str
    assigned_to: Optional[str]
    due_date: Optional[datetime]
    completed_at: Optional[datetime]
    completion_notes: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# Advanced Analytics & ML Models
class MLModel(Base):
    """Machine Learning model for security analytics"""

    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    model_type = Column(String(50), nullable=False)  # vulnerability_prediction, risk_scoring, anomaly_detection
    version = Column(String(20), nullable=False)
    description = Column(Text, nullable=True)
    model_path = Column(String(500), nullable=True)  # Path to saved model file
    model_metadata = Column(JSON, default={})  # Model parameters, metrics, etc.
    is_active = Column(Boolean, default=True)
    accuracy = Column(Float, nullable=True)  # Model accuracy score
    last_trained = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    predictions = relationship("MLPrediction", back_populates="model")
    training_data = relationship("MLTrainingData", back_populates="model")


class MLPrediction(Base):
    """Predictions made by ML models"""

    __tablename__ = "ml_predictions"

    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(Integer, ForeignKey("ml_models.id"), nullable=False)
    prediction_type = Column(String(50), nullable=False)  # vulnerability_risk, attack_probability, compliance_gap
    target_id = Column(Integer, nullable=True)  # ID of the target (finding, scan, etc.)
    target_type = Column(String(50), nullable=True)  # finding, scan, compliance_control
    prediction_value = Column(Float, nullable=False)  # Predicted value (0.0-1.0)
    confidence_score = Column(Float, nullable=True)  # Confidence in prediction
    prediction_data = Column(JSON, default={})  # Input features used for prediction
    prediction_result = Column(JSON, default={})  # Detailed prediction results
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    model = relationship("MLModel", back_populates="predictions")


class MLTrainingData(Base):
    """Training data for ML models"""

    __tablename__ = "ml_training_data"

    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(Integer, ForeignKey("ml_models.id"), nullable=False)
    data_type = Column(String(50), nullable=False)  # vulnerability_data, risk_data, compliance_data
    features = Column(JSON, nullable=False)  # Input features
    target = Column(Float, nullable=False)  # Target value for training
    training_metadata = Column(JSON, default={})  # Additional metadata
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    model = relationship("MLModel", back_populates="training_data")


class SecurityInsight(Base):
    """AI-generated security insights"""

    __tablename__ = "security_insights"

    id = Column(Integer, primary_key=True, index=True)
    insight_type = Column(String(50), nullable=False)  # trend, anomaly, recommendation, risk_alert
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), default="medium")  # low, medium, high, critical
    confidence = Column(Float, nullable=True)  # Confidence in the insight
    insight_data = Column(JSON, default={})  # Supporting data for the insight
    source_data = Column(JSON, default={})  # Data sources used
    is_actionable = Column(Boolean, default=True)
    action_taken = Column(Boolean, default=False)
    action_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    # Relationships
    related_findings = relationship("Finding", secondary="insight_findings")
    related_scans = relationship("Scan", secondary="insight_scans")


class RiskScore(Base):
    """Risk scoring for various entities"""

    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String(50), nullable=False)  # finding, scan, organization, compliance_control
    entity_id = Column(Integer, nullable=False)
    risk_score = Column(Float, nullable=False)  # 0.0-100.0
    risk_level = Column(String(20), nullable=False)  # low, medium, high, critical
    factors = Column(JSON, default={})  # Risk factors and weights
    calculation_method = Column(String(50), nullable=False)  # ml_model, rule_based, hybrid
    last_calculated = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class AnomalyDetection(Base):
    """Anomaly detection results"""

    __tablename__ = "anomaly_detections"

    id = Column(Integer, primary_key=True, index=True)
    anomaly_type = Column(String(50), nullable=False)  # scan_anomaly, finding_anomaly, behavior_anomaly
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(Integer, nullable=False)
    anomaly_score = Column(Float, nullable=False)  # 0.0-1.0
    severity = Column(String(20), default="medium")
    description = Column(Text, nullable=False)
    detection_data = Column(JSON, default={})  # Data that triggered the anomaly
    baseline_data = Column(JSON, default={})  # Baseline for comparison
    is_false_positive = Column(Boolean, nullable=True)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    reviewer = relationship("User")


class AnalyticsEvent(Base):
    """Analytics events for tracking user behavior and system usage"""

    __tablename__ = "analytics_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    event_type = Column(String(100), nullable=False)  # scan_created, finding_viewed, report_generated
    event_category = Column(String(50), nullable=False)  # user_action, system_event, security_event
    event_data = Column(JSON, default={})  # Event-specific data
    session_id = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User")


class TrendAnalysis(Base):
    """Trend analysis results"""

    __tablename__ = "trend_analyses"

    id = Column(Integer, primary_key=True, index=True)
    trend_type = Column(String(50), nullable=False)  # vulnerability_trend, risk_trend, compliance_trend
    metric_name = Column(String(100), nullable=False)
    time_period = Column(String(50), nullable=False)  # daily, weekly, monthly, quarterly
    trend_direction = Column(String(20), nullable=False)  # increasing, decreasing, stable
    trend_strength = Column(Float, nullable=True)  # 0.0-1.0
    data_points = Column(JSON, default={})  # Historical data points
    analysis_summary = Column(Text, nullable=True)
    recommendations = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)


class PredictiveAlert(Base):
    """Predictive alerts based on ML models"""

    __tablename__ = "predictive_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(50), nullable=False)  # vulnerability_prediction, risk_escalation, compliance_gap
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    predicted_value = Column(Float, nullable=False)
    confidence = Column(Float, nullable=True)
    severity = Column(String(20), default="medium")
    trigger_conditions = Column(JSON, default={})
    prediction_horizon = Column(Integer, nullable=True)  # Days into the future
    is_active = Column(Boolean, default=True)
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    acknowledged_by_user = relationship("User")


# Junction tables for many-to-many relationships
insight_findings = Table(
    "insight_findings",
    Base.metadata,
    Column("insight_id", Integer, ForeignKey("security_insights.id")),
    Column("finding_id", Integer, ForeignKey("findings.id"))
)

insight_scans = Table(
    "insight_scans",
    Base.metadata,
    Column("insight_id", Integer, ForeignKey("security_insights.id")),
    Column("scan_id", Integer, ForeignKey("scans.id"))
)


# Integration Models
class Integration(Base):
    """Integration model for external services"""

    __tablename__ = "integrations"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(50), nullable=False)  # aws, azure, gcp, github, slack, teams, jira, email
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    config = Column(JSON, default={})  # Integration-specific configuration
    is_active = Column(Boolean, default=True)
    last_sync = Column(DateTime, nullable=True)
    sync_frequency = Column(String(50), default="daily")  # hourly, daily, weekly, manual
    error_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    logs = relationship("IntegrationLog", back_populates="integration")
    findings = relationship("Finding", back_populates="integration")


class IntegrationLog(Base):
    """Integration activity logs"""

    __tablename__ = "integration_logs"

    id = Column(Integer, primary_key=True, index=True)
    integration_id = Column(Integer, ForeignKey("integrations.id"), nullable=False)
    activity_type = Column(String(50), nullable=False)  # sync, test, error, notification
    details = Column(JSON, default={})  # Activity-specific details
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    integration = relationship("Integration", back_populates="logs")


# Pydantic models for API
class MLModelCreate(BaseModel):
    name: str
    model_type: str
    version: str
    description: Optional[str] = None
    model_metadata: Optional[dict] = {}


class MLModelResponse(BaseModel):
    id: int
    name: str
    model_type: str
    version: str
    description: Optional[str]
    is_active: bool
    accuracy: Optional[float]
    last_trained: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class MLPredictionCreate(BaseModel):
    model_id: int
    prediction_type: str
    target_id: Optional[int] = None
    target_type: Optional[str] = None
    prediction_data: dict


class MLPredictionResponse(BaseModel):
    id: int
    model_name: str
    prediction_type: str
    target_id: Optional[int]
    target_type: Optional[str]
    prediction_value: float
    confidence_score: Optional[float]
    prediction_result: dict
    created_at: datetime

    class Config:
        from_attributes = True


class SecurityInsightCreate(BaseModel):
    insight_type: str
    title: str
    description: str
    severity: str = "medium"
    confidence: Optional[float] = None
    insight_data: Optional[dict] = {}
    source_data: Optional[dict] = {}


class SecurityInsightResponse(BaseModel):
    id: int
    insight_type: str
    title: str
    description: str
    severity: str
    confidence: Optional[float]
    is_actionable: bool
    action_taken: bool
    created_at: datetime

    class Config:
        from_attributes = True


class RiskScoreCreate(BaseModel):
    entity_type: str
    entity_id: int
    risk_score: float
    risk_level: str
    factors: Optional[dict] = {}
    calculation_method: str


class RiskScoreResponse(BaseModel):
    id: int
    entity_type: str
    entity_id: int
    risk_score: float
    risk_level: str
    factors: dict
    calculation_method: str
    last_calculated: datetime

    class Config:
        from_attributes = True


class AnomalyDetectionResponse(BaseModel):
    id: int
    anomaly_type: str
    entity_type: str
    entity_id: int
    anomaly_score: float
    severity: str
    description: str
    is_false_positive: Optional[bool]
    created_at: datetime

    class Config:
        from_attributes = True


class TrendAnalysisResponse(BaseModel):
    id: int
    trend_type: str
    metric_name: str
    time_period: str
    trend_direction: str
    trend_strength: Optional[float]
    analysis_summary: Optional[str]
    recommendations: dict
    created_at: datetime

    class Config:
        from_attributes = True


class PredictiveAlertCreate(BaseModel):
    alert_type: str
    title: str
    description: str
    predicted_value: float
    confidence: Optional[float] = None
    severity: str = "medium"
    trigger_conditions: Optional[dict] = {}
    prediction_horizon: Optional[int] = None


class PredictiveAlertResponse(BaseModel):
    id: int
    alert_type: str
    title: str
    description: str
    predicted_value: float
    confidence: Optional[float]
    severity: str
    prediction_horizon: Optional[int]
    is_active: bool
    acknowledged_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class AnalyticsDashboardResponse(BaseModel):
    total_predictions: int
    active_models: int
    recent_insights: int
    average_risk_score: float
    anomaly_count: int
    trend_analyses: int
    predictive_alerts: int
    model_accuracy: dict
    risk_distribution: dict
    insight_summary: dict

    class Config:
        from_attributes = True

# Integration Pydantic Models
class IntegrationCreate(BaseModel):
    provider: str
    name: str
    description: Optional[str] = None
    config: dict
    sync_frequency: str = "daily"


class IntegrationResponse(BaseModel):
    id: int
    provider: str
    name: str
    description: Optional[str]
    is_active: bool
    last_sync: Optional[datetime]
    sync_frequency: str
    error_count: int
    last_error: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class IntegrationTestRequest(BaseModel):
    provider: str
    config: dict


class IntegrationTestResponse(BaseModel):
    status: str
    message: str
    services_available: List[str]


class IntegrationSyncRequest(BaseModel):
    integration_id: int


class IntegrationSyncResponse(BaseModel):
    status: str
    message: str
    findings_synced: Optional[int] = 0


class IntegrationLogResponse(BaseModel):
    id: int
    activity_type: str
    details: dict
    timestamp: datetime

    class Config:
        from_attributes = True
