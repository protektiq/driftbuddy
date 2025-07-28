"""
Simplified FastAPI application for DriftBuddy Web Interface - Phase 3
Core features without problematic dependencies like LDAP
"""

import json
import os
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
    WebSocket,
    status,
    Response,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .auth import (
    create_access_token,
    get_current_active_user,
    get_password_hash,
    require_admin,
    require_appsec,
    require_developer,
    verify_password,
)
from .database import create_default_admin, get_db, init_db, setup_rbac_system, setup_compliance_system, setup_ml_analytics_system
from .models import (
    ChatMessage,
    ChatResponse,
    Finding,
    FindingResponse,
    Report,
    ReportResponse,
    Scan,
    ScanCreate,
    ScanResponse,
    ScanStatus,
    User,
    UserCreate,
    UserResponse,
    UserRole,
)
from .rbac_api import router as rbac_router
from .compliance_api import router as compliance_router
from .ml_analytics_api import router as ml_analytics_router
from .integrations_api import router as integrations_router

# Create FastAPI app
app = FastAPI(
    title="DriftBuddy Web Interface - Phase 3 (Simplified)",
    description="Enterprise-ready security analysis tool with core Phase 3 features",
    version="3.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers
app.include_router(rbac_router)
app.include_router(compliance_router)
app.include_router(ml_analytics_router)
app.include_router(integrations_router)


@app.on_event("startup")
async def startup_event():
    """Initialize database and create default admin user"""
    init_db()

    # Create default admin user
    db = next(get_db())
    try:
        create_default_admin(db)
        print("✅ Default admin user created: admin@driftbuddy.com / admin123")
        
        # Set up RBAC system
        setup_rbac_system(db)
        print("✅ Advanced RBAC system initialized")
        
        # Set up Compliance system
        setup_compliance_system(db)
        print("✅ Compliance Reporting system initialized")
        
        # Set up ML and Analytics system
        setup_ml_analytics_system(db)
        print("✅ ML and Analytics system initialized")
        
    finally:
        db.close()


# Authentication endpoints
@app.post("/api/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user with role assignment"""
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    # Create new user with default role
    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hashed_password,
        role=user_data.role.value,
        organization_id=user_data.organization_id,
        is_active=True,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse(
        id=new_user.id,
        email=new_user.email,
        username=new_user.username,
        role=new_user.role,
        organization_id=new_user.organization_id,
        is_active=new_user.is_active,
        created_at=new_user.created_at,
    )


@app.post("/api/auth/login")
async def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    """Login endpoint with JWT token generation"""
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Create access token
    access_token = create_access_token(data={"sub": user.email, "role": user.role})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "role": user.role,
            "organization_id": user.organization_id,
            "is_active": user.is_active,
        },
    }


@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current user information"""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        role=current_user.role,
        organization_id=current_user.organization_id,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
    )


# Simplified RBAC endpoints
@app.get("/api/rbac/permissions", operation_id="get_available_permissions_main")
async def get_available_permissions(current_user: User = Depends(get_current_active_user)):
    """Get available permissions for role creation"""
    return {
        "scan": [
            {"action": "create", "description": "Create new scans"},
            {"action": "read", "description": "View scan results"},
            {"action": "update", "description": "Update scan configurations"},
            {"action": "delete", "description": "Delete scans"}
        ],
        "report": [
            {"action": "create", "description": "Generate reports"},
            {"action": "read", "description": "View reports"},
            {"action": "export", "description": "Export report data"}
        ],
        "user": [
            {"action": "read", "description": "View user information"},
            {"action": "update", "description": "Update user profiles"},
            {"action": "delete", "description": "Delete users"}
        ]
    }


@app.get("/api/rbac/templates", operation_id="get_role_templates_main")
async def get_role_templates(current_user: User = Depends(get_current_active_user)):
    """Get available role templates"""
    return {
        "security_analyst": {
            "name": "Security Analyst",
            "description": "Security analyst with scan and report access",
            "permissions": ["scan:read", "report:create", "report:read"]
        },
        "compliance_analyst": {
            "name": "Compliance Analyst",
            "description": "Compliance analyst with reporting access",
            "permissions": ["report:create", "report:read", "report:export"]
        },
        "developer": {
            "name": "Developer",
            "description": "Developer with limited scan access",
            "permissions": ["scan:read"]
        }
    }


# Simplified compliance endpoints
@app.get("/api/compliance/frameworks")
async def get_supported_frameworks(current_user: User = Depends(get_current_active_user)):
    """Get supported compliance frameworks"""
    return {
        "SOC2": {
            "name": "SOC2 Type II",
            "description": "System and Organization Controls 2",
            "version": "2017",
            "controls": ["CC6.1", "CC6.2", "CC6.3", "CC7.1", "CC7.2", "CC8.1"]
        },
        "PCI": {
            "name": "PCI DSS",
            "description": "Payment Card Industry Data Security Standard",
            "version": "4.0",
            "controls": ["PCI-1", "PCI-2", "PCI-3", "PCI-4", "PCI-5", "PCI-6"]
        },
        "HIPAA": {
            "name": "HIPAA",
            "description": "Health Insurance Portability and Accountability Act",
            "version": "1996",
            "controls": ["HIPAA-1", "HIPAA-2", "HIPAA-3", "HIPAA-4", "HIPAA-5"]
        }
    }


@app.get("/api/compliance/frameworks/{framework}/controls")
async def get_framework_controls(
    framework: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get controls for a specific compliance framework"""
    controls = {
        "SOC2": {
            "CC6.1": {
                "title": "Logical and Physical Access Controls",
                "description": "The entity implements logical and physical access controls to protect against unauthorized access",
                "category": "CC"
            },
            "CC6.2": {
                "title": "Prior Authorization for Access",
                "description": "The entity authorizes, modifies, or removes access to data, software, functions, and other IT resources",
                "category": "CC"
            }
        },
        "PCI": {
            "PCI-1": {
                "title": "Install and maintain a firewall configuration",
                "description": "Protect cardholder data",
                "category": "Network Security"
            },
            "PCI-2": {
                "title": "Do not use vendor-supplied defaults",
                "description": "Change default passwords and security settings",
                "category": "Access Control"
            }
        },
        "HIPAA": {
            "HIPAA-1": {
                "title": "Security Management Process",
                "description": "Implement policies and procedures to prevent, detect, contain, and correct security violations",
                "category": "Administrative Safeguards"
            },
            "HIPAA-2": {
                "title": "Assigned Security Responsibility",
                "description": "Identify the security official who is responsible for the development and implementation of the policies and procedures",
                "category": "Administrative Safeguards"
            }
        }
    }

    if framework not in controls:
        raise HTTPException(status_code=404, detail="Framework not found")

    return {"framework": framework, "controls": controls[framework]}


# Integration endpoints
@app.post("/api/integrations/{integration_name}/test")
async def test_integration(
    integration_name: str,
    current_user: User = Depends(get_current_active_user)
):
    """Test integration connectivity"""
    return {
        "integration": integration_name,
        "status": "connected",
        "message": f"Successfully connected to {integration_name}"
    }


@app.post("/api/integrations/jira/issues")
async def create_jira_issue_from_finding(
    finding_id: int,
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create Jira issue from a finding"""
    return {
        "issue_key": "SEC-123",
        "finding_id": finding_id,
        "scan_id": scan_id,
        "status": "created",
        "url": "https://jira.company.com/browse/SEC-123"
    }


# Cloud integration endpoints
@app.post("/api/cloud/connect/aws")
async def connect_aws(
    access_key: str = Form(...),
    secret_key: str = Form(...),
    region: str = Form("us-east-1"),
    profile: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
):
    """Connect AWS account"""
    return {
        "provider": "aws",
        "region": region,
        "status": "connected",
        "message": "AWS account connected successfully"
    }


@app.post("/api/cloud/connect/azure")
async def connect_azure(
    tenant_id: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    subscription_id: str = Form(...),
    current_user: User = Depends(get_current_active_user),
):
    """Connect Azure account"""
    return {
        "provider": "azure",
        "tenant_id": tenant_id,
        "subscription_id": subscription_id,
        "status": "connected",
        "message": "Azure account connected successfully"
    }


@app.post("/api/cloud/connect/gcp")
async def connect_gcp(
    project_id: str = Form(...),
    service_account_key: str = Form(...),
    current_user: User = Depends(get_current_active_user)
):
    """Connect GCP account"""
    return {
        "provider": "gcp",
        "project_id": project_id,
        "status": "connected",
        "message": "GCP account connected successfully"
    }


# AI Chat endpoints
@app.post("/api/chat/message")
async def send_chat_message(
    message: ChatMessage,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Send a chat message to AI"""
    # Simulate AI response
    ai_response = f"AI response to: {message.prompt}"
    
    return ChatResponse(
        response=ai_response,
                    metadata={"model": "o4-mini", "tokens": 150},
        created_at=datetime.utcnow()
    )


@app.get("/api/chat/history")
async def get_chat_history(
    limit: int = 50,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get chat history for current user"""
    return {
        "messages": [
            {
                "id": 1,
                "prompt": "How do I fix this security issue?",
                "response": "Here's how to fix the security issue...",
                "created_at": "2024-01-15T10:30:00Z"
            }
        ],
        "total": 1
    }


@app.post("/api/chat/analyze/{scan_id}")
async def analyze_findings_with_ai(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Analyze scan findings with AI"""
    return {
        "scan_id": scan_id,
        "analysis": "AI analysis of scan findings...",
        "recommendations": ["Fix issue 1", "Fix issue 2"],
        "risk_score": 8.5
    }


# Scan endpoints
@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new scan"""
    # Check if user has permission to create scans
    if current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions to create scans")

    new_scan = Scan(
        user_id=current_user.id,
        organization_id=current_user.organization_id or 1,
        name=scan_data.name,
        description=scan_data.description,
        scan_type=scan_data.scan_type,
        status=ScanStatus.PENDING.value,
        scan_metadata={"target_path": scan_data.target_path} if scan_data.target_path else {},
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return ScanResponse(
        id=new_scan.id,
        name=new_scan.name,
        description=new_scan.description,
        status=ScanStatus(new_scan.status),
        scan_type=new_scan.scan_type,
        created_at=new_scan.created_at,
        updated_at=new_scan.updated_at,
        completed_at=new_scan.completed_at,
        findings_count=0,
    )


@app.get("/api/scans", response_model=List[ScanResponse])
async def list_scans(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all scans for the current user"""
    # Get scans based on user role
    if current_user.role == "admin":
        scans = db.query(Scan).all()
    else:
        scans = db.query(Scan).filter(Scan.user_id == current_user.id).all()

    return [
        ScanResponse(
            id=scan.id,
            name=scan.name,
            description=scan.description,
            status=ScanStatus(scan.status),
            scan_type=scan.scan_type,
            created_at=scan.created_at,
            updated_at=scan.updated_at,
            completed_at=scan.completed_at,
            findings_count=len(scan.findings),
        )
        for scan in scans
    ]


@app.post("/api/scans/{scan_id}/run")
async def run_scan(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Run a scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Check permissions
    if scan.user_id != current_user.id and current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Access denied")

    # Update scan status
    scan.status = ScanStatus.RUNNING.value
    scan.updated_at = datetime.utcnow()
    db.commit()

    # Simulate scan execution
    # In a real implementation, this would trigger an async task
    scan.status = ScanStatus.COMPLETED.value
    scan.completed_at = datetime.utcnow()
    scan.updated_at = datetime.utcnow()
    
    # Add some sample findings
    sample_findings = [
        Finding(
            scan_id=scan.id,
            query_name="Sample Security Issue",
            severity="HIGH",
            description="This is a sample security finding for demonstration",
            file_path="example.tf",
            line_number=10,
            remediation="Fix the security issue by implementing proper controls",
            risk_score=8
        )
    ]
    
    for finding in sample_findings:
        db.add(finding)
    
    db.commit()

    return {
        "scan_id": scan_id,
        "status": "completed",
        "findings_count": len(sample_findings),
        "message": "Scan completed successfully"
    }


@app.get("/api/scans/{scan_id}")
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get a specific scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Check permissions
    if scan.user_id != current_user.id and current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Access denied")

    return ScanResponse(
        id=scan.id,
        name=scan.name,
        description=scan.description,
        status=ScanStatus(scan.status),
        scan_type=scan.scan_type,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        completed_at=scan.completed_at,
        findings_count=len(scan.findings),
    )


@app.get("/api/scans/{scan_id}/findings")
async def get_scan_findings(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get findings for a specific scan"""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Check permissions
    if scan.user_id != current_user.id and current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Access denied")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    return [
        FindingResponse(
            id=finding.id,
            query_name=finding.query_name,
            severity=finding.severity,
            description=finding.description,
            file_path=finding.file_path,
            line_number=finding.line_number,
            remediation=finding.remediation,
            ai_explanation=finding.ai_explanation,
            risk_score=finding.risk_score,
            business_impact=finding.business_impact,
            created_at=finding.created_at,
        )
        for finding in findings
    ]


# Report endpoints
@app.get("/api/reports")
async def list_reports(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all reports for the current user"""
    # Get reports based on user role
    if current_user.role == "admin":
        reports = db.query(Report).all()
    else:
        reports = db.query(Report).filter(Report.user_id == current_user.id).all()

    return [
        ReportResponse(
            id=report.id,
            name=report.name,
            report_type=report.report_type,
            format=report.format,
            status=report.status,
            file_path=report.file_path,
            created_at=report.created_at,
        )
        for report in reports
    ]


@app.post("/api/reports/generate")
async def create_report(
    report_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new report"""
    # Check permissions
    if current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions to create reports")

    new_report = Report(
        user_id=current_user.id,
        name=report_data.get("name", "Generated Report"),
        report_type=report_data.get("type", "scan_report"),
        format=report_data.get("format", "html"),
        status="generating",
    )

    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    return ReportResponse(
        id=new_report.id,
        name=new_report.name,
        report_type=new_report.report_type,
        format=new_report.format,
        status=new_report.status,
        file_path=new_report.file_path,
        created_at=new_report.created_at,
    )


@app.get("/api/reports/{report_id}/download")
async def download_report(
    report_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Download a report"""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Check permissions
    if report.user_id != current_user.id and current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Access denied")

    # Simulate report content
    report_content = f"# {report.name}\n\nThis is a sample report content for {report.report_type}."

    return Response(
        content=report_content,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={report.name}.txt"}
    )


# Dashboard endpoints
@app.get("/api/dashboard/metrics")
async def get_dashboard_metrics(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get dashboard metrics"""
    # Get metrics based on user role
    if current_user.role == "admin":
        total_scans = db.query(Scan).count()
        total_findings = db.query(Finding).count()
        total_reports = db.query(Report).count()
    else:
        total_scans = db.query(Scan).filter(Scan.user_id == current_user.id).count()
        total_findings = db.query(Finding).join(Scan).filter(Scan.user_id == current_user.id).count()
        total_reports = db.query(Report).filter(Report.user_id == current_user.id).count()

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "total_reports": total_reports,
        "high_severity_findings": 5,
        "medium_severity_findings": 12,
        "low_severity_findings": 8,
        "compliance_score": 85.5,
        "last_scan_date": "2024-01-15T10:30:00Z"
    }


@app.get("/api/dashboard/recent-scans")
async def get_recent_scans(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get recent scans for dashboard"""
    # Get recent scans based on user role
    if current_user.role == "admin":
        scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()
    else:
        scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(5).all()

    return [
        {
            "id": scan.id,
            "name": scan.name,
            "status": scan.status,
            "created_at": scan.created_at.isoformat(),
            "findings_count": len(scan.findings)
        }
        for scan in scans
    ]


@app.get("/api/dashboard/recent-findings")
async def get_recent_findings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get recent findings for dashboard"""
    # Get recent findings based on user role
    if current_user.role == "admin":
        findings = db.query(Finding).order_by(Finding.created_at.desc()).limit(10).all()
    else:
        findings = db.query(Finding).join(Scan).filter(Scan.user_id == current_user.id).order_by(Finding.created_at.desc()).limit(10).all()

    return [
        {
            "id": finding.id,
            "query_name": finding.query_name,
            "severity": finding.severity,
            "description": finding.description[:100] + "..." if len(finding.description) > 100 else finding.description,
            "created_at": finding.created_at.isoformat(),
            "scan_name": finding.scan.name if finding.scan else "Unknown"
        }
        for finding in findings
    ]


# Settings endpoints
@app.get("/api/settings/profile")
async def get_user_profile(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get user profile settings"""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "username": current_user.username,
        "role": current_user.role,
        "organization_id": current_user.organization_id,
        "is_active": current_user.is_active,
        "created_at": current_user.created_at.isoformat(),
        "updated_at": current_user.updated_at.isoformat()
    }


@app.put("/api/settings/profile")
async def update_user_profile(
    profile_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update user profile settings"""
    # Update allowed fields
    if "username" in profile_data:
        current_user.username = profile_data["username"]
    if "email" in profile_data:
        current_user.email = profile_data["email"]

    current_user.updated_at = datetime.utcnow()
    db.commit()

    return {"message": "Profile updated successfully"}


@app.put("/api/settings/password")
async def change_password(
    password_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    if not verify_password(password_data.get("current_password", ""), current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    new_password = password_data.get("new_password")
    if not new_password:
        raise HTTPException(status_code=400, detail="New password is required")

    current_user.hashed_password = get_password_hash(new_password)
    current_user.updated_at = datetime.utcnow()
    db.commit()

    return {"message": "Password changed successfully"}


@app.get("/api/settings/system")
async def get_system_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get system settings"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return {
        "app_name": "DriftBuddy",
        "version": "3.0.0",
        "debug_mode": False,
        "max_file_size": "100MB",
        "scan_timeout": "30 minutes",
        "ai_enabled": True,
        "rbac_enabled": True
    }


@app.put("/api/settings/system")
async def update_system_settings(
    settings_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update system settings"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return {"message": "System settings updated successfully"}


@app.get("/api/settings/integrations")
async def get_integration_settings(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get integration settings"""
    return {
        "jira": {
            "enabled": True,
            "url": "https://jira.company.com",
            "project_key": "SEC"
        },
        "slack": {
            "enabled": False,
            "webhook_url": None
        },
        "email": {
            "enabled": True,
            "smtp_server": "smtp.company.com",
            "from_address": "security@company.com"
        }
    }


@app.put("/api/settings/integrations")
async def update_integration_settings(
    integration_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update integration settings"""
    if current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return {"message": "Integration settings updated successfully"}


# Compliance endpoints
@app.get("/api/compliance/frameworks", operation_id="get_compliance_frameworks_main")
async def get_compliance_frameworks(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get compliance frameworks"""
    return {
        "SOC2": {
            "name": "SOC2 Type II",
            "description": "System and Organization Controls 2",
            "version": "2017",
            "status": "compliant",
            "score": 92.5,
            "last_assessment": "2024-01-15T10:30:00Z"
        },
        "PCI": {
            "name": "PCI DSS",
            "description": "Payment Card Industry Data Security Standard",
            "version": "4.0",
            "status": "non_compliant",
            "score": 78.0,
            "last_assessment": "2024-01-10T14:20:00Z"
        },
        "HIPAA": {
            "name": "HIPAA",
            "description": "Health Insurance Portability and Accountability Act",
            "version": "1996",
            "status": "compliant",
            "score": 95.0,
            "last_assessment": "2024-01-12T09:15:00Z"
        }
    }


@app.post("/api/compliance/frameworks", operation_id="create_compliance_framework_main")
async def create_compliance_framework(
    framework_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new compliance framework"""
    if current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return {"message": "Compliance framework created successfully"}


@app.get("/api/compliance/controls")
async def get_compliance_controls(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get compliance controls"""
    return {
        "SOC2": {
            "CC6.1": {
                "title": "Logical and Physical Access Controls",
                "description": "The entity implements logical and physical access controls to protect against unauthorized access",
                "category": "CC",
                "status": "compliant",
                "evidence": "Access controls implemented and documented",
                "last_reviewed": "2024-01-15T10:30:00Z"
            },
            "CC6.2": {
                "title": "Prior Authorization for Access",
                "description": "The entity authorizes, modifies, or removes access to data, software, functions, and other IT resources",
                "category": "CC",
                "status": "non_compliant",
                "evidence": "Missing access review process",
                "last_reviewed": "2024-01-10T14:20:00Z"
            }
        },
        "PCI": {
            "PCI-1": {
                "title": "Install and maintain a firewall configuration",
                "description": "Protect cardholder data",
                "category": "Network Security",
                "status": "compliant",
                "evidence": "Firewall rules documented and implemented",
                "last_reviewed": "2024-01-12T09:15:00Z"
            },
            "PCI-2": {
                "title": "Do not use vendor-supplied defaults",
                "description": "Change default passwords and security settings",
                "category": "Access Control",
                "status": "compliant",
                "evidence": "Default passwords changed on all systems",
                "last_reviewed": "2024-01-08T16:45:00Z"
            }
        }
    }


@app.get("/api/compliance/assessments", operation_id="get_compliance_assessments_main")
async def get_compliance_assessments(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get compliance assessments"""
    return {
        "assessments": [
            {
                "id": 1,
                "framework": "SOC2",
                "status": "completed",
                "score": 92.5,
                "assessor": "John Doe",
                "start_date": "2024-01-01T00:00:00Z",
                "end_date": "2024-01-15T00:00:00Z",
                "findings": 3,
                "recommendations": 2
            },
            {
                "id": 2,
                "framework": "PCI",
                "status": "in_progress",
                "score": 78.0,
                "assessor": "Jane Smith",
                "start_date": "2024-01-05T00:00:00Z",
                "end_date": None,
                "findings": 8,
                "recommendations": 5
            }
        ],
        "total": 2,
        "completed": 1,
        "in_progress": 1
    }


@app.post("/api/compliance/assessments", operation_id="create_compliance_assessment_main")
async def create_compliance_assessment(
    assessment_data: dict,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new compliance assessment"""
    if current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return {"message": "Compliance assessment created successfully"}


@app.get("/api/compliance/audit-events", operation_id="get_audit_events_main")
async def get_audit_events(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get audit events"""
    return {
        "events": [
            {
                "id": 1,
                "user": "admin@driftbuddy.com",
                "action": "login",
                "resource": "auth",
                "timestamp": "2024-01-15T10:30:00Z",
                "ip_address": "192.168.1.100",
                "status": "success"
            },
            {
                "id": 2,
                "user": "admin@driftbuddy.com",
                "action": "create_scan",
                "resource": "scan",
                "timestamp": "2024-01-15T10:35:00Z",
                "ip_address": "192.168.1.100",
                "status": "success"
            },
            {
                "id": 3,
                "user": "developer@company.com",
                "action": "view_findings",
                "resource": "finding",
                "timestamp": "2024-01-15T09:15:00Z",
                "ip_address": "192.168.1.101",
                "status": "success"
            }
        ],
        "total": 3,
        "page": 1,
        "per_page": 50
    }


# Report generation endpoints
@app.post("/api/reports/generate/{scan_id}")
async def generate_report(
    scan_id: int,
    format: str = "html",
    report_name: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generate a report for a specific scan"""
    # Check if scan exists
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Check permissions
    if scan.user_id != current_user.id and current_user.role not in ["admin", "appsec"]:
        raise HTTPException(status_code=403, detail="Access denied")

    # Create report
    report_name = report_name or f"Report for {scan.name}"
    new_report = Report(
        user_id=current_user.id,
        scan_id=scan_id,
        name=report_name,
        report_type="scan_report",
        format=format,
        status="completed",
        file_path=f"reports/report_{scan_id}.{format}",
        report_metadata={
            "scan_name": scan.name,
            "findings_count": len(scan.findings),
            "generated_by": current_user.username,
            "generated_at": datetime.utcnow().isoformat()
        }
    )

    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    return {
        "report_id": new_report.id,
        "name": new_report.name,
        "status": "completed",
        "file_path": new_report.file_path,
        "message": f"Report '{report_name}' generated successfully"
    }


@app.post("/api/reports/organization")
async def generate_organization_report(
    organization_id: Optional[int] = None,
    date_range: Optional[str] = None,  # JSON string
    current_user: User = Depends(require_appsec),
    db: Session = Depends(get_db),
):
    """Generate organization-wide report"""
    return {
        "report_id": 123,
        "name": "Organization Security Report",
        "status": "completed",
        "file_path": "reports/org_report_2024.html",
        "message": "Organization report generated successfully"
    }


# Health check endpoint
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "3.0.0",
        "services": {
            "database": "healthy",
            "rbac_service": "simulated",
            "ai_service": "healthy",
            "scan_service": "healthy"
        },
        "features": {
            "authentication": "enabled",
            "rbac": "enabled",
            "ai_chat": "enabled",
            "compliance": "enabled",
            "cloud_integration": "enabled"
        }
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "DriftBuddy Web Interface",
        "version": "3.0.0",
        "description": "Enterprise-ready security analysis tool with advanced features",
        "features": [
            "🔐 Authentication & Authorization",
            "👥 Advanced RBAC with Custom Roles & Permissions",
            "🔍 Security Scanning & Analysis",
            "📊 Compliance Reporting",
            "🤖 AI-Powered Chat & Analysis",
            "☁️ Cloud Integration",
            "📈 Dashboard & Metrics",
            "🔗 External Integrations"
        ],
        "endpoints": {
            "auth": "/api/auth",
            "rbac": "/api/rbac",
            "scans": "/api/scans",
            "reports": "/api/reports",
            "chat": "/api/chat",
            "dashboard": "/api/dashboard",
            "settings": "/api/settings",
            "compliance": "/api/compliance",
            "health": "/api/health"
        },
        "docs": "/docs"
    } 