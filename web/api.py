"""
FastAPI application for DriftBuddy Web Interface
"""

import os
from typing import List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
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
from .services import FileService, ScanService

# Create FastAPI app
app = FastAPI(title="DriftBuddy Web Interface", description="AI-powered security analysis tool with KICS integration", version="1.0.0")

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


# Authentication endpoints
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


# Scan management endpoints
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
    return {"status": "healthy", "version": "1.0.0", "service": "DriftBuddy Web Interface"}


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {"message": "DriftBuddy Web Interface", "version": "1.0.0", "docs": "/docs", "health": "/api/health"}
