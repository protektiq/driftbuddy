"""
FastAPI application for DriftBuddy Web Interface - Phase 2
Includes cloud connector, AI chat, WebSocket, and advanced reporting
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
from .database import create_default_admin, get_db, init_db
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
    title="DriftBuddy Web Interface - Phase 2", description="AI-powered security analysis tool with cloud integration and real-time features", version="2.0.0"
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


# Authentication endpoints (same as Phase 1)
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


# Phase 2: Cloud Connector endpoints
@app.post("/api/cloud/connect/aws")
async def connect_aws(
    access_key: str = Form(...),
    secret_key: str = Form(...),
    region: str = Form("us-east-1"),
    profile: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
):
    """Connect to AWS cloud account"""
    result = await cloud_connector.connect_aws(access_key=access_key, secret_key=secret_key, region=region, profile=profile)

    if result["success"]:
        return {"message": "AWS connection successful", "provider": "aws", "region": region}
    else:
        raise HTTPException(status_code=400, detail=f"AWS connection failed: {result.get('error', 'Unknown error')}")


@app.post("/api/cloud/connect/azure")
async def connect_azure(
    tenant_id: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    subscription_id: str = Form(...),
    current_user: User = Depends(get_current_active_user),
):
    """Connect to Azure cloud account"""
    result = await cloud_connector.connect_azure(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret, subscription_id=subscription_id)

    if result["success"]:
        return {"message": "Azure connection successful", "provider": "azure", "subscription_id": subscription_id}
    else:
        raise HTTPException(status_code=400, detail=f"Azure connection failed: {result.get('error', 'Unknown error')}")


@app.post("/api/cloud/connect/gcp")
async def connect_gcp(project_id: str = Form(...), service_account_key: str = Form(...), current_user: User = Depends(get_current_active_user)):
    """Connect to GCP cloud account"""
    result = await cloud_connector.connect_gcp(project_id=project_id, service_account_key=service_account_key)

    if result["success"]:
        return {"message": "GCP connection successful", "provider": "gcp", "project_id": project_id}
    else:
        raise HTTPException(status_code=400, detail=f"GCP connection failed: {result.get('error', 'Unknown error')}")


@app.post("/api/cloud/scan")
async def run_cloud_scan(
    provider: str = Form(...),
    config: str = Form(...),  # JSON string of cloud config
    scan_name: str = Form(...),
    description: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    """Run cloud infrastructure scan"""
    try:
        # Parse cloud config
        cloud_config = json.loads(config)

        # Create scan
        scan = await scan_service.create_scan(db=db, user=current_user, name=scan_name, description=description, scan_type=f"cloud_{provider}")

        # Run cloud scan
        result = await cloud_connector.run_cloud_scan(db=db, scan=scan, provider=provider, config=cloud_config)

        if result["success"]:
            return {"message": "Cloud scan started successfully", "scan_id": scan.id, "provider": provider, "findings_count": result.get("findings_count", 0)}
        else:
            raise HTTPException(status_code=500, detail=f"Cloud scan failed: {result.get('error', 'Unknown error')}")

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid cloud configuration JSON")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cloud scan failed: {str(e)}")


# Phase 2: AI Chat endpoints
@app.post("/api/chat/message")
async def send_chat_message(message: ChatMessage, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Send a chat message and get AI response"""
    result = await ai_chat_service.process_chat_message(db=db, user=current_user, message=message.prompt, scan_id=message.scan_id, context=message.dict())

    if result["success"]:
        return {"success": True, "response": result["response"], "metadata": result.get("metadata", {}), "chat_id": result.get("chat_id")}
    else:
        raise HTTPException(status_code=500, detail=f"Chat processing failed: {result.get('error', 'Unknown error')}")


@app.get("/api/chat/history")
async def get_chat_history(limit: int = 50, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Get user's chat history"""
    history = await ai_chat_service.get_chat_history(db=db, user=current_user, limit=limit)

    return {"history": history}


@app.post("/api/chat/analyze/{scan_id}")
async def analyze_findings_with_ai(scan_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Analyze scan findings with AI"""
    result = await ai_chat_service.analyze_findings_with_ai(db=db, scan_id=scan_id, user=current_user)

    if result["success"]:
        return {"success": True, "analysis": result["analysis"], "findings_count": result["findings_count"], "scan_name": result["scan_name"]}
    else:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {result.get('error', 'Unknown error')}")


@app.post("/api/chat/remediation-plan/{scan_id}")
async def generate_remediation_plan(scan_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Generate comprehensive remediation plan"""
    result = await ai_chat_service.generate_remediation_plan(db=db, scan_id=scan_id, user=current_user)

    if result["success"]:
        return {"success": True, "plan": result["plan"], "findings_count": result["findings_count"]}
    else:
        raise HTTPException(status_code=500, detail=f"Remediation plan generation failed: {result.get('error', 'Unknown error')}")


# Phase 2: WebSocket endpoints
@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """WebSocket endpoint for real-time updates"""
    await websocket_service.handle_websocket(websocket, user_id)


@app.websocket("/ws/scan/{scan_id}")
async def scan_websocket_endpoint(websocket: WebSocket, scan_id: int):
    """WebSocket endpoint for scan-specific updates"""
    await websocket_service.handle_websocket(websocket, scan_id=scan_id)


# Phase 2: Advanced Reporting endpoints
@app.post("/api/reports/generate/{scan_id}")
async def generate_report(scan_id: int, format: str = "html", current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Generate comprehensive report for a scan"""
    result = await reporting_service.generate_report(db=db, scan_id=scan_id, user=current_user, format=format)

    if result["success"]:
        return {"success": True, "filename": result["filename"], "filepath": result["filepath"], "size": result["size"], "format": result["format"]}
    else:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {result.get('error', 'Unknown error')}")


@app.post("/api/reports/organization")
async def generate_organization_report(
    organization_id: Optional[int] = None,
    date_range: Optional[str] = None,  # JSON string
    current_user: User = Depends(require_appsec),
    db: Session = Depends(get_db),
):
    """Generate organization-wide security report"""
    try:
        date_range_dict = None
        if date_range:
            date_range_dict = json.loads(date_range)

        result = await reporting_service.generate_organization_report(db=db, user=current_user, organization_id=organization_id, date_range=date_range_dict)

        if result["success"]:
            return {"success": True, "filename": result["filename"], "filepath": result["filepath"], "size": result["size"], "statistics": result["statistics"]}
        else:
            raise HTTPException(status_code=500, detail=f"Organization report generation failed: {result.get('error', 'Unknown error')}")

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid date range JSON")


@app.post("/api/reports/export/{scan_id}")
async def export_scan_data(scan_id: int, format: str = "json", current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Export scan data in various formats"""
    result = await reporting_service.export_scan_data(db=db, scan_id=scan_id, user=current_user, format=format)

    if result["success"]:
        return {"success": True, "filename": result["filename"], "filepath": result["filepath"], "size": result["size"], "format": result["format"]}
    else:
        raise HTTPException(status_code=500, detail=f"Export failed: {result.get('error', 'Unknown error')}")


# Enhanced scan management endpoints (Phase 1 + Phase 2 features)
@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(scan_data: ScanCreate, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Create a new scan"""
    scan = await scan_service.create_scan(db=db, user=current_user, name=scan_data.name, description=scan_data.description, scan_type=scan_data.scan_type)

    return ScanResponse.from_orm(scan)


@app.post("/api/scans/{scan_id}/upload")
async def upload_files(scan_id: int, files: List[UploadFile] = File(...), current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Upload files for scanning"""
    # Verify scan access
    scan = await scan_service.get_scan(db, scan_id, current_user)

    if scan.status != "pending":
        raise HTTPException(status_code=400, detail="Can only upload files to pending scans")

    # Upload files
    upload_result = await scan_service.upload_files(scan_id, files)

    return {"message": "Files uploaded successfully", "scan_id": scan_id, "files_uploaded": len(files), "total_size": upload_result["total_size"]}


@app.post("/api/scans/{scan_id}/run")
async def run_scan(scan_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Run a scan with uploaded files"""
    # Verify scan access
    scan = await scan_service.get_scan(db, scan_id, current_user)

    if scan.status != "pending":
        raise HTTPException(status_code=400, detail="Can only run pending scans")

    # Get scan directory
    scan_dir = f"uploads/{scan_id}"
    if not os.path.exists(scan_dir):
        raise HTTPException(status_code=400, detail="No files uploaded for this scan")

    # Run KICS scan
    result = await scan_service.run_kics_scan(db, scan, scan_dir)

    # Send WebSocket notification
    await websocket_service.send_scan_complete(scan_id=scan_id, findings_count=result.get("findings_count", 0), results=result)

    return {"message": "Scan started successfully", "scan_id": scan_id, "status": scan.status, "findings_count": result.get("findings_count", 0)}


@app.get("/api/scans", response_model=List[ScanResponse])
async def get_scans(skip: int = 0, limit: int = 100, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Get user's scans with pagination"""
    scans = await scan_service.get_user_scans(db, current_user, skip, limit)

    return [ScanResponse.from_orm(scan) for scan in scans]


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Get specific scan details"""
    scan = await scan_service.get_scan(db, scan_id, current_user)
    return ScanResponse.from_orm(scan)


@app.get("/api/scans/{scan_id}/findings", response_model=List[FindingResponse])
async def get_scan_findings(scan_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Get findings for a specific scan"""
    findings = await scan_service.get_scan_findings(db, scan_id, current_user)
    return [FindingResponse.from_orm(finding) for finding in findings]


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    """Delete a scan"""
    success = await scan_service.delete_scan(db, scan_id, current_user)

    if success:
        return {"message": "Scan deleted successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to delete scan")


# Admin endpoints
@app.get("/api/admin/users", response_model=List[UserResponse])
async def get_users(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Get all users (admin only)"""
    users = db.query(User).filter(User.organization_id == current_user.organization_id).all()

    return [UserResponse.from_orm(user) for user in users]


@app.post("/api/admin/users", response_model=UserResponse)
async def create_user(user_data: UserCreate, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Create a new user (admin only)"""
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
        organization_id=current_user.organization_id,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return UserResponse.from_orm(user)


# Health check endpoint
@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "service": "DriftBuddy Web Interface - Phase 2",
        "features": ["authentication", "cloud_connector", "ai_chat", "websocket", "advanced_reporting"],
    }


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "DriftBuddy Web Interface - Phase 2",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/api/health",
        "features": [
            "🔐 Authentication & RBAC",
            "☁️ Cloud Connector (AWS, Azure, GCP)",
            "🤖 AI Chat with LangChain",
            "🔌 Real-time WebSocket updates",
            "📊 Advanced Reporting & Export",
        ],
    }
