"""
Tests for DriftBuddy Web Interface
"""

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from web.api import app
from web.auth import get_password_hash
from web.database import get_db, init_db
from web.models import User, UserRole

# Test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing"""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    """Setup test database before each test"""
    # Create tables
    from web.models import Base

    Base.metadata.create_all(bind=engine)

    # Create test user
    db = TestingSessionLocal()
    test_user = User(
        email="test@example.com",
        username="testuser",
        hashed_password=get_password_hash("testpass"),
        role=UserRole.DEVELOPER.value,
        organization_id=1,
        is_active=True,
    )
    db.add(test_user)
    db.commit()
    db.close()

    yield

    # Cleanup
    Base.metadata.drop_all(bind=engine)


def test_health_check():
    """Test health check endpoint"""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "DriftBuddy Web Interface"


def test_root_endpoint():
    """Test root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "DriftBuddy Web Interface"


def test_login_success():
    """Test successful login"""
    response = client.post("/api/auth/login", data={"email": "admin@driftbuddy.com", "password": "admin123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data


def test_login_failure():
    """Test failed login"""
    response = client.post("/api/auth/login", data={"email": "wrong@example.com", "password": "wrongpass"})
    assert response.status_code == 401


def test_create_scan_authenticated():
    """Test creating a scan with authentication"""
    # First login to get token
    login_response = client.post("/api/auth/login", data={"email": "admin@driftbuddy.com", "password": "admin123"})
    token = login_response.json()["access_token"]

    # Create scan with token
    headers = {"Authorization": f"Bearer {token}"}
    scan_data = {"name": "Test Scan", "description": "Test scan description", "scan_type": "kics"}

    response = client.post("/api/scans", json=scan_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Test Scan"
    assert data["status"] == "pending"


def test_create_scan_unauthenticated():
    """Test creating a scan without authentication"""
    scan_data = {"name": "Test Scan", "description": "Test scan description", "scan_type": "kics"}

    response = client.post("/api/scans", json=scan_data)
    assert response.status_code == 401


def test_get_scans_authenticated():
    """Test getting scans with authentication"""
    # First login to get token
    login_response = client.post("/api/auth/login", data={"email": "admin@driftbuddy.com", "password": "admin123"})
    token = login_response.json()["access_token"]

    # Get scans with token
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/scans", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_admin_endpoints():
    """Test admin-only endpoints"""
    # First login as admin
    login_response = client.post("/api/auth/login", data={"email": "admin@driftbuddy.com", "password": "admin123"})
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Test getting users (admin only)
    response = client.get("/api/admin/users", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_file_upload_endpoint():
    """Test file upload endpoint"""
    # First login to get token
    login_response = client.post("/api/auth/login", data={"email": "admin@driftbuddy.com", "password": "admin123"})
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create a scan first
    scan_data = {"name": "Upload Test Scan", "description": "Test scan for file upload", "scan_type": "kics"}
    scan_response = client.post("/api/scans", json=scan_data, headers=headers)
    scan_id = scan_response.json()["id"]

    # Test file upload (without actual file for now)
    response = client.post(f"/api/scans/{scan_id}/upload", headers=headers)
    # Should fail without files, but endpoint should exist
    assert response.status_code in [400, 422]  # Missing files


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
