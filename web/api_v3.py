"""
FastAPI application for DriftBuddy Web Interface - Phase 3
Includes advanced RBAC, compliance reporting, external integrations, and enhanced features
"""

import json
import os
from typing import Any, Dict, List, Optional

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
    WebSocket,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .advanced_rbac import AdvancedRBAC
from .ai_chat import AIChatService
from .auth import (
    create_access_token,
    get_current_active_user,
    get_password_hash,
    require_admin,
    require_appsec,
    require_developer,
    verify_password,
)
from .cloud_connector import CloudConnector
from .compliance_reporting import ComplianceReportingService
from .database import create_default_admin, get_db, init_db
from .integration_apis import IntegrationService
from .models import (
    ChatMessage,
    ChatResponse,
    FindingResponse,
    ScanCreate,
    ScanResponse,
    User,
    UserCreate,
    UserResponse,
    UserRole,
)
from .reporting import ReportingService
from .services import FileService, ScanService
from .websocket import websocket_service

# Create FastAPI app
app = FastAPI(
    title="DriftBuddy Web Interface - Phase 3",
    description="Enterprise-ready security analysis tool with advanced RBAC, compliance reporting, and external integrations",
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

# Initialize services
scan_service = ScanService()
file_service = FileService()
cloud_connector = CloudConnector()
ai_chat_service = AIChatService()
reporting_service = ReportingService()
compliance_service = ComplianceReportingService()
integration_service = IntegrationService()
rbac_service = AdvancedRBAC()


@app.on_event("startup")
async def startup_event():
    """Initialize database and create default admin user"""
    init_db()

    # Create default admin user
    db = next(get_db())
    try:
        create_default_admin(db)
        print("✅ Default admin user created: admin@driftbuddy.com / admin123")
    finally:
        db.close()


# Authentication endpoints (enhanced with RBAC)
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
        role=UserRole.DEVELOPER,  # Default role
        is_active=True
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse(
        id=new_user.id,
        email=new_user.email,
        username=new_user.username,
        role=new_user.role,
        is_active=new_user.is_active
    )


@app.post("/api/auth/login")
async def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    """Login with enhanced role-based access"""
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Create access token with role information
    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            role=user.role,
            is_active=user.is_active
        )
    }


@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current user information with permissions"""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        role=current_user.role,
        is_active=current_user.is_active
    )


# Advanced RBAC endpoints
@app.post("/api/rbac/roles")
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


@app.post("/api/rbac/roles/template")
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


@app.post("/api/rbac/users/{user_id}/roles/{role_id}")
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


@app.get("/api/rbac/permissions")
async def get_available_permissions(current_user: User = Depends(get_current_active_user)):
    """Get available permissions for role creation"""
    try:
        permissions = await rbac_service.get_available_permissions()
        return permissions
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get permissions: {str(e)}")


@app.get("/api/rbac/templates")
async def get_role_templates(current_user: User = Depends(get_current_active_user)):
    """Get available role templates"""
    try:
        templates = await rbac_service.get_role_templates()
        return templates
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get role templates: {str(e)}")


# Compliance reporting endpoints
@app.post("/api/compliance/reports/{framework}")
async def generate_compliance_report(
    framework: str,
    scan_ids: str = Form(...),  # JSON string of scan IDs
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generate compliance report for specific framework"""
    try:
        scan_id_list = json.loads(scan_ids)
        result = await compliance_service.generate_compliance_report(db, framework, scan_id_list, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate compliance report: {str(e)}")


@app.get("/api/compliance/frameworks")
async def get_supported_frameworks(current_user: User = Depends(get_current_active_user)):
    """Get supported compliance frameworks"""
    try:
        frameworks = await compliance_service.get_supported_frameworks()
        return frameworks
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get frameworks: {str(e)}")


@app.get("/api/compliance/frameworks/{framework}/controls")
async def get_framework_controls(
    framework: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get controls for a specific compliance framework"""
    try:
        controls = await compliance_service.get_framework_controls(framework)
        return controls
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get framework controls: {str(e)}")


# External integrations endpoints
@app.post("/api/integrations/{integration_name}/test")
async def test_integration(
    integration_name: str,
    current_user: User = Depends(get_current_active_user)
):
    """Test connection to external integration"""
    try:
        result = await integration_service.test_integration(integration_name)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to test integration: {str(e)}")


@app.post("/api/integrations/jira/issues")
async def create_jira_issue_from_finding(
    finding_id: int,
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create Jira issue from security finding"""
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        
        if not finding or not scan:
            raise HTTPException(status_code=404, detail="Finding or scan not found")
        
        result = await integration_service.create_jira_issue_from_finding(
            finding.__dict__, scan.__dict__, current_user
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create Jira issue: {str(e)}")


@app.post("/api/integrations/notifications/scan")
async def send_scan_notification(
    scan_id: int,
    integrations: str = Form(...),  # JSON string of integration names
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Send scan completion notification to external systems"""
    try:
        integration_list = json.loads(integrations)
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        result = await integration_service.send_scan_notification(
            scan.__dict__, [f.__dict__ for f in findings], integration_list
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to send notification: {str(e)}")


# Enhanced cloud connector endpoints
@app.post("/api/cloud/connect/aws")
async def connect_aws(
    access_key: str = Form(...),
    secret_key: str = Form(...),
    region: str = Form("us-east-1"),
    profile: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
):
    """Connect to AWS with enhanced security"""
    try:
        result = await cloud_connector.connect_aws(access_key, secret_key, region, profile)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"AWS connection failed: {str(e)}")


@app.post("/api/cloud/connect/azure")
async def connect_azure(
    tenant_id: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    subscription_id: str = Form(...),
    current_user: User = Depends(get_current_active_user),
):
    """Connect to Azure with enhanced security"""
    try:
        result = await cloud_connector.connect_azure(tenant_id, client_id, client_secret, subscription_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Azure connection failed: {str(e)}")


@app.post("/api/cloud/connect/gcp")
async def connect_gcp(
    project_id: str = Form(...),
    service_account_key: str = Form(...),
    current_user: User = Depends(get_current_active_user)
):
    """Connect to GCP with enhanced security"""
    try:
        result = await cloud_connector.connect_gcp(project_id, service_account_key)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"GCP connection failed: {str(e)}")


@app.post("/api/cloud/scan")
async def run_cloud_scan(
    provider: str = Form(...),
    config: str = Form(...),  # JSON string of cloud config
    scan_name: str = Form(...),
    description: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Run cloud infrastructure scan with enhanced reporting"""
    try:
        cloud_config = json.loads(config)
        
        # Create scan record
        scan = Scan(
            name=scan_name,
            description=description or f"Cloud scan for {provider}",
            scan_type=f"cloud_{provider}",
            status="RUNNING",
            user_id=current_user.id,
            metadata={"provider": provider, "config": cloud_config}
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        # Run cloud scan
        result = await cloud_connector.run_cloud_scan(db, scan, provider, cloud_config)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Cloud scan failed: {str(e)}")


# Enhanced AI chat endpoints
@app.post("/api/chat/message")
async def send_chat_message(
    message: ChatMessage,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Send chat message with enhanced AI analysis"""
    try:
        result = await ai_chat_service.process_chat_message(db, current_user, message.content, message.scan_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process chat message: {str(e)}")


@app.get("/api/chat/history")
async def get_chat_history(
    limit: int = 50,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get chat history with role-based filtering"""
    try:
        history = await ai_chat_service.get_chat_history(db, current_user, limit)
        return history
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get chat history: {str(e)}")


@app.post("/api/chat/analyze/{scan_id}")
async def analyze_findings_with_ai(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Analyze scan findings with AI"""
    try:
        result = await ai_chat_service.analyze_findings_with_ai(db, scan_id, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to analyze findings: {str(e)}")


@app.post("/api/chat/remediation-plan/{scan_id}")
async def generate_remediation_plan(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generate comprehensive remediation plan"""
    try:
        result = await ai_chat_service.generate_remediation_plan(db, scan_id, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate remediation plan: {str(e)}")


# WebSocket endpoints for real-time updates
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """WebSocket endpoint for real-time user updates"""
    await websocket_service.connect_user(websocket, user_id)


@app.websocket("/ws/scan/{scan_id}")
async def scan_websocket_endpoint(websocket: WebSocket, scan_id: int):
    """WebSocket endpoint for real-time scan updates"""
    await websocket_service.connect_scan(websocket, scan_id)


# Enhanced reporting endpoints
@app.post("/api/reports/generate/{scan_id}")
async def generate_report(
    scan_id: int,
    format: str = "html",
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generate enhanced report with compliance mapping"""
    try:
        result = await reporting_service.generate_enhanced_report(db, scan_id, format, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate report: {str(e)}")


@app.post("/api/reports/organization")
async def generate_organization_report(
    organization_id: Optional[int] = None,
    date_range: Optional[str] = None,  # JSON string
    current_user: User = Depends(require_appsec),
    db: Session = Depends(get_db),
):
    """Generate organization-wide security report"""
    try:
        date_range_dict = json.loads(date_range) if date_range else None
        result = await reporting_service.generate_organization_report(db, organization_id, date_range_dict, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate organization report: {str(e)}")


@app.post("/api/reports/export/{scan_id}")
async def export_scan_data(
    scan_id: int,
    format: str = "json",
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Export scan data in various formats"""
    try:
        result = await reporting_service.export_scan_data(db, scan_id, format, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to export scan data: {str(e)}")


# Enhanced scan management endpoints
@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create scan with enhanced validation"""
    try:
        result = await scan_service.create_scan(db, scan_data, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create scan: {str(e)}")


@app.post("/api/scans/{scan_id}/upload")
async def upload_files(
    scan_id: int,
    files: List[UploadFile] = File(...),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Upload files for scan with enhanced security"""
    try:
        result = await file_service.upload_files(db, scan_id, files, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to upload files: {str(e)}")


@app.post("/api/scans/{scan_id}/run")
async def run_scan(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Run scan with enhanced monitoring"""
    try:
        result = await scan_service.run_scan(db, scan_id, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to run scan: {str(e)}")


@app.get("/api/scans", response_model=List[ScanResponse])
async def get_scans(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get scans with role-based filtering"""
    try:
        scans = await scan_service.get_scans(db, current_user, skip, limit)
        return scans
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get scans: {str(e)}")


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get scan details with role-based access"""
    try:
        scan = await scan_service.get_scan(db, scan_id, current_user)
        return scan
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get scan: {str(e)}")


@app.get("/api/scans/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get scan findings with role-based access"""
    try:
        findings = await scan_service.get_scan_findings(db, scan_id, current_user)
        return findings
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get findings: {str(e)}")


@app.delete("/api/scans/{scan_id}")
async def delete_scan(
    scan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Delete scan with role-based permissions"""
    try:
        result = await scan_service.delete_scan(db, scan_id, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to delete scan: {str(e)}")


# Enhanced admin endpoints
@app.get("/api/admin/users", response_model=List[UserResponse])
async def get_users(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get all users with role-based access"""
    try:
        users = await scan_service.get_users(db, current_user)
        return users
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to get users: {str(e)}")


@app.post("/api/admin/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create user with role assignment"""
    try:
        result = await scan_service.create_user(db, user_data, current_user)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to create user: {str(e)}")


# Health check and system endpoints
@app.get("/api/health")
async def health_check():
    """Enhanced health check with service status"""
    try:
        services_status = {
            "database": "healthy",
            "ai_chat": "healthy" if ai_chat_service.langchain else "limited",
            "cloud_connector": "healthy",
            "compliance_service": "healthy",
            "integration_service": "healthy",
            "rbac_service": "healthy"
        }
        
        return {
            "status": "healthy",
            "version": "3.0.0",
            "services": services_status,
            "timestamp": "2024-01-25T14:30:22Z"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "version": "3.0.0",
            "timestamp": "2024-01-25T14:30:22Z"
        }


@app.get("/")
async def root():
    """Root endpoint with enhanced information"""
    return {
        "message": "DriftBuddy Web Interface - Phase 3",
        "version": "3.0.0",
        "features": [
            "Advanced RBAC with custom roles and permissions",
            "Compliance reporting (SOC2, PCI, HIPAA)",
            "External integrations (Jira, Slack, Teams)",
            "Enhanced cloud connector with Steampipe",
            "AI-powered analysis with LangChain",
            "Real-time WebSocket updates",
            "Comprehensive reporting and export"
        ],
        "endpoints": {
            "api_docs": "/docs",
            "health_check": "/api/health",
            "authentication": "/api/auth",
            "rbac": "/api/rbac",
            "compliance": "/api/compliance",
            "integrations": "/api/integrations",
            "cloud": "/api/cloud",
            "chat": "/api/chat",
            "reports": "/api/reports",
            "scans": "/api/scans",
            "admin": "/api/admin"
        }
    }
