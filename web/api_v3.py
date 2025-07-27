"""
FastAPI application for DriftBuddy Web Interface - Phase 3
Includes SSO, advanced RBAC, compliance reporting, and integration APIs
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
from .sso_integration import SSOIntegration
from .websocket import websocket_service

# Create FastAPI app
app = FastAPI(
    title="DriftBuddy Web Interface - Phase 3",
    description="Enterprise-grade security analysis tool with SSO, advanced RBAC, compliance reporting, and integrations",
    version="3.0.0",
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
sso_integration = SSOIntegration()
advanced_rbac = AdvancedRBAC()
compliance_service = ComplianceReportingService()
integration_service = IntegrationService()


@app.on_event("startup")
async def startup_event():
    """Initialize database and create default admin user"""
    init_db()

    # Create default admin user
    db = next(get_db())
    try:
        create_default_admin(db)
        print("✅ Default admin user created: admin@driftbuddy.com / admin123")

        # Setup default permissions for advanced RBAC
        await advanced_rbac.setup_default_permissions(db)
        print("✅ Default permissions setup completed")

    finally:
        db.close()


# Phase 3: SSO Integration endpoints
@app.get("/api/sso/providers")
async def get_sso_providers():
    """Get available SSO providers"""
    providers = await sso_integration.get_sso_providers()
    return {"providers": providers}


@app.post("/api/sso/saml/login")
async def saml_login(db: Session = Depends(get_db)):
    """Initiate SAML login"""
    result = await sso_integration.handle_saml_login(db)

    if result["success"]:
        return {"success": True, "redirect_url": result["redirect_url"]}
    else:
        raise HTTPException(status_code=400, detail=f"SAML login failed: {result.get('error', 'Unknown error')}")


@app.post("/api/sso/saml/acs")
async def saml_acs(SAMLResponse: str = Form(...), db: Session = Depends(get_db)):
    """Handle SAML Assertion Consumer Service"""
    result = await sso_integration.handle_saml_acs(SAMLResponse, db)

    if result["success"]:
        return {"success": True, "access_token": result["access_token"], "user": result["user"]}
    else:
        raise HTTPException(status_code=400, detail=f"SAML ACS failed: {result.get('error', 'Unknown error')}")


@app.get("/api/sso/saml/metadata")
async def saml_metadata():
    """Get SAML metadata"""
    metadata = sso_integration.get_saml_metadata()
    return {"metadata": metadata}


@app.post("/api/sso/oauth/{provider}/login")
async def oauth_login(provider: str, db: Session = Depends(get_db)):
    """Initiate OAuth login"""
    result = await sso_integration.handle_oauth_login(provider, db)

    if result["success"]:
        return {"success": True, "redirect_url": result["redirect_url"]}
    else:
        raise HTTPException(status_code=400, detail=f"OAuth login failed: {result.get('error', 'Unknown error')}")


@app.get("/api/sso/oauth/{provider}/callback")
async def oauth_callback(provider: str, code: str, state: str, db: Session = Depends(get_db)):
    """Handle OAuth callback"""
    result = await sso_integration.handle_oauth_callback(provider, code, state, db)

    if result["success"]:
        return {"success": True, "access_token": result["access_token"], "user": result["user"]}
    else:
        raise HTTPException(status_code=400, detail=f"OAuth callback failed: {result.get('error', 'Unknown error')}")


@app.post("/api/sso/ldap/login")
async def ldap_login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    """Handle LDAP authentication"""
    result = await sso_integration.handle_ldap_login(username, password, db)

    if result["success"]:
        return {"success": True, "access_token": result["access_token"], "user": result["user"]}
    else:
        raise HTTPException(status_code=401, detail=f"LDAP login failed: {result.get('error', 'Unknown error')}")


# Phase 3: Advanced RBAC endpoints
@app.post("/api/rbac/roles")
async def create_custom_role(
    name: str = Form(...),
    description: str = Form(...),
    organization_id: int = Form(...),
    permissions: str = Form(...),  # JSON string of permissions
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Create a custom role"""
    try:
        permissions_list = json.loads(permissions)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid permissions JSON")

    result = await advanced_rbac.create_custom_role(
        db=db, name=name, description=description, organization_id=organization_id, permissions=permissions_list, created_by=current_user
    )

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=f"Role creation failed: {result.get('error', 'Unknown error')}")


@app.post("/api/rbac/roles/template")
async def create_role_from_template(
    template_name: str = Form(...),
    organization_id: int = Form(...),
    custom_name: Optional[str] = Form(None),
    additional_permissions: Optional[str] = Form(None),  # JSON string
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Create a role from template"""
    additional_perms = None
    if additional_permissions:
        try:
            additional_perms = json.loads(additional_permissions)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid additional permissions JSON")

    result = await advanced_rbac.create_role_from_template(
        db=db, template_name=template_name, organization_id=organization_id, custom_name=custom_name, additional_permissions=additional_perms
    )

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=f"Template role creation failed: {result.get('error', 'Unknown error')}")


@app.post("/api/rbac/users/{user_id}/roles/{role_id}")
async def assign_role_to_user(user_id: int, role_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Assign role to user"""
    result = await advanced_rbac.assign_role_to_user(db=db, user_id=user_id, role_id=role_id, assigned_by=current_user)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=f"Role assignment failed: {result.get('error', 'Unknown error')}")


@app.delete("/api/rbac/users/{user_id}/roles/{role_id}")
async def remove_role_from_user(user_id: int, role_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Remove role from user"""
    result = await advanced_rbac.remove_role_from_user(db=db, user_id=user_id, role_id=role_id, removed_by=current_user)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=f"Role removal failed: {result.get('error', 'Unknown error')}")


@app.get("/api/rbac/users/{user_id}/roles")
async def get_user_roles(user_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Get user's roles"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check permissions
    if current_user.id != user_id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    roles = await advanced_rbac.get_user_roles(db, user)
    return {"roles": roles}


@app.get("/api/rbac/organizations/{org_id}/roles")
async def get_organization_roles(org_id: int, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get organization's roles"""
    roles = await advanced_rbac.get_organization_roles(db, org_id)
    return {"roles": roles}


@app.get("/api/rbac/permissions")
async def get_available_permissions():
    """Get available permissions"""
    permissions = await advanced_rbac.get_available_permissions()
    return {"permissions": permissions}


@app.get("/api/rbac/templates")
async def get_role_templates():
    """Get available role templates"""
    templates = await advanced_rbac.get_role_templates()
    return {"templates": templates}


@app.post("/api/rbac/check-permission")
async def check_permission(
    resource: str = Form(...),
    action: str = Form(...),
    conditions: Optional[str] = Form(None),  # JSON string
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Check if user has permission"""
    conditions_dict = None
    if conditions:
        try:
            conditions_dict = json.loads(conditions)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid conditions JSON")

    has_permission = await advanced_rbac.check_permission(db=db, user=current_user, resource=resource, action=action, conditions=conditions_dict)

    return {"has_permission": has_permission, "resource": resource, "action": action}


# Phase 3: Compliance Reporting endpoints
@app.post("/api/compliance/reports/{framework}")
async def generate_compliance_report(
    framework: str, scan_ids: str = Form(...), current_user: User = Depends(require_appsec), db: Session = Depends(get_db)  # JSON string of scan IDs
):
    """Generate compliance report"""
    try:
        scan_ids_list = json.loads(scan_ids)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid scan IDs JSON")

    result = await compliance_service.generate_compliance_report(db=db, framework=framework, scan_ids=scan_ids_list, user=current_user)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=500, detail=f"Compliance report generation failed: {result.get('error', 'Unknown error')}")


@app.post("/api/compliance/reports/{framework}/html")
async def generate_compliance_html_report(
    framework: str, report_data: str = Form(...), current_user: User = Depends(require_appsec)  # JSON string of report data
):
    """Generate HTML compliance report"""
    try:
        report_data_dict = json.loads(report_data)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid report data JSON")

    result = await compliance_service.generate_html_report(framework=framework, report_data=report_data_dict)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=500, detail=f"HTML report generation failed: {result.get('error', 'Unknown error')}")


@app.get("/api/compliance/frameworks")
async def get_supported_frameworks():
    """Get supported compliance frameworks"""
    frameworks = await compliance_service.get_supported_frameworks()
    return {"frameworks": frameworks}


@app.get("/api/compliance/frameworks/{framework}/controls")
async def get_framework_controls(framework: str):
    """Get controls for a specific framework"""
    result = await compliance_service.get_framework_controls(framework)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=f"Failed to get framework controls: {result.get('error', 'Unknown error')}")


@app.post("/api/compliance/map-finding")
async def map_finding_to_framework(
    framework: str = Form(...),
    finding: str = Form(...),  # JSON string of finding
):
    """Map a finding to framework controls"""
    try:
        finding_dict = json.loads(finding)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid finding JSON")

    controls = await compliance_service.map_finding_to_framework(framework=framework, finding=finding_dict)

    return {"controls": controls}


# Phase 3: Integration APIs endpoints
@app.get("/api/integrations")
async def get_available_integrations():
    """Get available integrations"""
    integrations = await integration_service.get_available_integrations()
    return {"integrations": integrations}


@app.post("/api/integrations/{integration_name}/test")
async def test_integration(integration_name: str):
    """Test integration connection"""
    result = await integration_service.test_integration(integration_name)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=f"Integration test failed: {result.get('error', 'Unknown error')}")


@app.post("/api/integrations/jira/issues")
async def create_jira_issue(
    finding: str = Form(...), scan: str = Form(...), current_user: User = Depends(get_current_active_user)  # JSON string of finding  # JSON string of scan
):
    """Create Jira issue from finding"""
    try:
        finding_dict = json.loads(finding)
        scan_dict = json.loads(scan)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON data")

    result = await integration_service.create_jira_issue_from_finding(finding=finding_dict, scan=scan_dict, user=current_user)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=500, detail=f"Jira issue creation failed: {result.get('error', 'Unknown error')}")


@app.post("/api/integrations/notifications/scan")
async def send_scan_notification(
    scan: str = Form(...),  # JSON string of scan
    findings: str = Form(...),  # JSON string of findings
    integrations: Optional[str] = Form(None),  # JSON string of integration names
    current_user: User = Depends(get_current_active_user),
):
    """Send scan completion notification"""
    try:
        scan_dict = json.loads(scan)
        findings_list = json.loads(findings)
        integrations_list = json.loads(integrations) if integrations else None
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON data")

    result = await integration_service.send_scan_notification(scan=scan_dict, findings=findings_list, integrations=integrations_list)

    return result


@app.post("/api/integrations/notifications/finding")
async def send_finding_alert(
    finding: str = Form(...),  # JSON string of finding
    scan: str = Form(...),  # JSON string of scan
    integrations: Optional[str] = Form(None),  # JSON string of integration names
    current_user: User = Depends(get_current_active_user),
):
    """Send finding alert notification"""
    try:
        finding_dict = json.loads(finding)
        scan_dict = json.loads(scan)
        integrations_list = json.loads(integrations) if integrations else None
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON data")

    result = await integration_service.send_finding_alert(finding=finding_dict, scan=scan_dict, integrations=integrations_list)

    return result


# Enhanced authentication endpoints (Phase 1 + SSO)
@app.post("/api/auth/register", response_model=UserResponse)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    # Create new user
    hashed_password = get_password_hash(user_data.password)
    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=hashed_password,
        role=user_data.role.value,
        organization_id=user_data.organization_id,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return UserResponse.from_orm(user)


@app.post("/api/auth/login")
async def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    """Login and get access token"""
    user = db.query(User).filter(User.email == email).first()

    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Create access token
    access_token = create_access_token(data={"sub": str(user.id)})

    return {"access_token": access_token, "token_type": "bearer", "user": UserResponse.from_orm(user)}


@app.get("/api/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current user information"""
    return UserResponse.from_orm(current_user)


# Enhanced scan management endpoints (Phase 1 + Phase 2 + Phase 3)
@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(scan_data: ScanCreate, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Create a new scan"""
    # Check permission
    has_permission = await advanced_rbac.check_permission(db=db, user=current_user, resource="scan", action="create")

    if not has_permission:
        raise HTTPException(status_code=403, detail="Permission denied")

    scan = await scan_service.create_scan(db=db, user=current_user, name=scan_data.name, description=scan_data.description, scan_type=scan_data.scan_type)

    return ScanResponse.from_orm(scan)


@app.get("/api/scans", response_model=List[ScanResponse])
async def get_scans(skip: int = 0, limit: int = 100, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Get user's scans with pagination"""
    # Check permission
    has_permission = await advanced_rbac.check_permission(db=db, user=current_user, resource="scan", action="read")

    if not has_permission:
        raise HTTPException(status_code=403, detail="Permission denied")

    scans = await scan_service.get_user_scans(db, current_user, skip, limit)

    return [ScanResponse.from_orm(scan) for scan in scans]


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Get specific scan details"""
    # Check permission
    has_permission = await advanced_rbac.check_permission(db=db, user=current_user, resource="scan", action="read")

    if not has_permission:
        raise HTTPException(status_code=403, detail="Permission denied")

    scan = await scan_service.get_scan(db, scan_id, current_user)
    return ScanResponse.from_orm(scan)


@app.get("/api/scans/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(scan_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Get findings for a specific scan"""
    # Check permission
    has_permission = await advanced_rbac.check_permission(db=db, user=current_user, resource="scan", action="read")

    if not has_permission:
        raise HTTPException(status_code=403, detail="Permission denied")

    findings = await scan_service.get_scan_findings(db, scan_id, current_user)
    return [FindingResponse.from_orm(finding) for finding in findings]


# Health check endpoint
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "3.0.0",
        "service": "DriftBuddy Web Interface - Phase 3",
        "features": [
            "authentication",
            "sso_integration",
            "advanced_rbac",
            "compliance_reporting",
            "integration_apis",
            "cloud_connector",
            "ai_chat",
            "websocket",
            "advanced_reporting",
        ],
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "DriftBuddy Web Interface - Phase 3",
        "version": "3.0.0",
        "docs": "/docs",
        "health": "/api/health",
        "features": [
            "🔐 SSO Integration (SAML, OAuth, LDAP)",
            "👥 Advanced RBAC with Custom Roles",
            "📋 Compliance Reporting (SOC2, PCI, HIPAA)",
            "🔗 Integration APIs (Jira, Slack, Teams)",
            "☁️ Cloud Connector (AWS, Azure, GCP)",
            "🤖 AI Chat with LangChain",
            "🔌 Real-time WebSocket updates",
            "📊 Advanced Reporting & Export",
        ],
    }
