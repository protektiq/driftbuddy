#!/usr/bin/env python3
"""
Tests for DriftBuddy Phase 3 Features
Tests advanced RBAC, compliance reporting, external integrations, and enhanced features
"""

import json
import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from web.api_v3 import app
from web.database import get_db
from web.models import User, UserRole, Organization, CustomRole, Permission
from web.advanced_rbac import AdvancedRBAC
from web.compliance_reporting import ComplianceReportingService
from web.integration_apis import IntegrationService


# Test database setup
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


@pytest.fixture
def test_db():
    """Create test database"""
    from web.database import Base
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def admin_user(test_db):
    """Create admin user for testing"""
    db = TestingSessionLocal()
    user = User(
        email="admin@driftbuddy.com",
        username="admin",
        hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iQe",  # admin123
        role=UserRole.ADMIN,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user


@pytest.fixture
def developer_user(test_db):
    """Create developer user for testing"""
    db = TestingSessionLocal()
    user = User(
        email="dev@driftbuddy.com",
        username="developer",
        hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iQe",  # admin123
        role=UserRole.DEVELOPER,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user


@pytest.fixture
def organization(test_db):
    """Create test organization"""
    db = TestingSessionLocal()
    org = Organization(
        name="Test Organization",
        description="Test organization for testing"
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    db.close()
    return org


def get_auth_headers(user):
    """Get authentication headers for user"""
    response = client.post("/api/auth/login", data={
        "email": user.email,
        "password": "admin123"
    })
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestAdvancedRBAC:
    """Test advanced RBAC functionality"""

    def test_create_custom_role(self, admin_user, organization):
        """Test creating a custom role"""
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/rbac/roles", headers=headers, data={
            "name": "security_analyst",
            "description": "Security analyst role",
            "organization_id": organization.id,
            "permissions": json.dumps(["scan:read", "report:create"])
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["role"]["name"] == "security_analyst"

    def test_create_role_from_template(self, admin_user, organization):
        """Test creating a role from template"""
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/rbac/roles/template", headers=headers, data={
            "template_name": "security_analyst",
            "organization_id": organization.id,
            "custom_name": "Custom Security Analyst"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_assign_role_to_user(self, admin_user, developer_user, organization):
        """Test assigning a role to a user"""
        # First create a role
        headers = get_auth_headers(admin_user)
        role_response = client.post("/api/rbac/roles", headers=headers, data={
            "name": "test_role",
            "description": "Test role",
            "organization_id": organization.id,
            "permissions": json.dumps(["scan:read"])
        })
        role_id = role_response.json()["role"]["id"]
        
        # Then assign it to user
        response = client.post(f"/api/rbac/users/{developer_user.id}/roles/{role_id}", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    def test_get_available_permissions(self, admin_user):
        """Test getting available permissions"""
        headers = get_auth_headers(admin_user)
        
        response = client.get("/api/rbac/permissions", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "scan" in data
        assert "report" in data
        assert "user" in data

    def test_get_role_templates(self, admin_user):
        """Test getting role templates"""
        headers = get_auth_headers(admin_user)
        
        response = client.get("/api/rbac/templates", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "security_analyst" in data
        assert "compliance_analyst" in data


class TestComplianceReporting:
    """Test compliance reporting functionality"""

    def test_get_supported_frameworks(self, admin_user):
        """Test getting supported compliance frameworks"""
        headers = get_auth_headers(admin_user)
        
        response = client.get("/api/compliance/frameworks", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "SOC2" in data
        assert "PCI" in data
        assert "HIPAA" in data

    def test_get_framework_controls(self, admin_user):
        """Test getting framework controls"""
        headers = get_auth_headers(admin_user)
        
        response = client.get("/api/compliance/frameworks/SOC2/controls", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "CC6.1" in data
        assert "CC6.2" in data

    @patch('web.compliance_reporting.ComplianceReportingService.generate_compliance_report')
    def test_generate_compliance_report(self, mock_generate, admin_user):
        """Test generating compliance report"""
        mock_generate.return_value = {
            "success": True,
            "report": {"framework": "SOC2", "controls": []}
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/compliance/reports/SOC2", headers=headers, data={
            "scan_ids": json.dumps([1, 2, 3])
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True


class TestExternalIntegrations:
    """Test external integrations functionality"""

    @patch('web.integration_apis.IntegrationService.test_integration')
    def test_test_integration(self, mock_test, admin_user):
        """Test testing external integration"""
        mock_test.return_value = {"success": True, "message": "Connection successful"}
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/integrations/jira/test", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

    @patch('web.integration_apis.IntegrationService.create_jira_issue_from_finding')
    def test_create_jira_issue_from_finding(self, mock_create, admin_user):
        """Test creating Jira issue from finding"""
        mock_create.return_value = {
            "success": True,
            "issue_key": "SEC-123",
            "issue_url": "https://jira.com/browse/SEC-123"
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/integrations/jira/issues", headers=headers, data={
            "finding_id": 1,
            "scan_id": 1
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "issue_key" in data

    @patch('web.integration_apis.IntegrationService.send_scan_notification')
    def test_send_scan_notification(self, mock_send, admin_user):
        """Test sending scan notification"""
        mock_send.return_value = {
            "success": True,
            "notifications_sent": ["slack", "teams"]
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/integrations/notifications/scan", headers=headers, data={
            "scan_id": 1,
            "integrations": json.dumps(["slack", "teams"])
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True


class TestEnhancedCloudConnector:
    """Test enhanced cloud connector functionality"""

    @patch('web.cloud_connector.CloudConnector.connect_aws')
    def test_connect_aws(self, mock_connect, admin_user):
        """Test connecting to AWS"""
        mock_connect.return_value = {
            "success": True,
            "provider": "aws",
            "region": "us-east-1"
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/cloud/connect/aws", headers=headers, data={
            "access_key": "test-key",
            "secret_key": "test-secret",
            "region": "us-east-1"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["provider"] == "aws"

    @patch('web.cloud_connector.CloudConnector.connect_azure')
    def test_connect_azure(self, mock_connect, admin_user):
        """Test connecting to Azure"""
        mock_connect.return_value = {
            "success": True,
            "provider": "azure",
            "subscription_id": "test-sub"
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/cloud/connect/azure", headers=headers, data={
            "tenant_id": "test-tenant",
            "client_id": "test-client",
            "client_secret": "test-secret",
            "subscription_id": "test-sub"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["provider"] == "azure"

    @patch('web.cloud_connector.CloudConnector.connect_gcp')
    def test_connect_gcp(self, mock_connect, admin_user):
        """Test connecting to GCP"""
        mock_connect.return_value = {
            "success": True,
            "provider": "gcp",
            "project_id": "test-project"
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/cloud/connect/gcp", headers=headers, data={
            "project_id": "test-project",
            "service_account_key": "{}"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["provider"] == "gcp"


class TestEnhancedAIChat:
    """Test enhanced AI chat functionality"""

    @patch('web.ai_chat.AIChatService.process_chat_message')
    def test_send_chat_message(self, mock_process, admin_user):
        """Test sending chat message"""
        mock_process.return_value = {
            "success": True,
            "response": "AI response",
            "metadata": {"model": "gpt-4"}
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/chat/message", headers=headers, json={
            "content": "Hello AI",
            "scan_id": None
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "response" in data

    @patch('web.ai_chat.AIChatService.get_chat_history')
    def test_get_chat_history(self, mock_history, admin_user):
        """Test getting chat history"""
        mock_history.return_value = [
            {"id": 1, "prompt": "Hello", "response": "Hi", "created_at": "2024-01-25T14:30:22Z"}
        ]
        
        headers = get_auth_headers(admin_user)
        
        response = client.get("/api/chat/history?limit=10", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) > 0

    @patch('web.ai_chat.AIChatService.analyze_findings_with_ai')
    def test_analyze_findings_with_ai(self, mock_analyze, admin_user):
        """Test analyzing findings with AI"""
        mock_analyze.return_value = {
            "success": True,
            "analysis": "AI analysis of findings",
            "recommendations": ["Fix issue 1", "Fix issue 2"]
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/chat/analyze/1", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "analysis" in data


class TestEnhancedReporting:
    """Test enhanced reporting functionality"""

    @patch('web.reporting.ReportingService.generate_enhanced_report')
    def test_generate_enhanced_report(self, mock_generate, admin_user):
        """Test generating enhanced report"""
        mock_generate.return_value = {
            "success": True,
            "report_path": "/path/to/report.html",
            "report_type": "enhanced"
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/reports/generate/1?format=html", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "report_path" in data

    @patch('web.reporting.ReportingService.generate_organization_report')
    def test_generate_organization_report(self, mock_generate, admin_user):
        """Test generating organization report"""
        mock_generate.return_value = {
            "success": True,
            "report_path": "/path/to/org_report.html",
            "metrics": {"total_scans": 10, "total_findings": 25}
        }
        
        headers = get_auth_headers(admin_user)
        
        response = client.post("/api/reports/organization", headers=headers, data={
            "organization_id": 1,
            "date_range": json.dumps({"start": "2024-01-01", "end": "2024-01-31"})
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "metrics" in data


class TestHealthAndSystem:
    """Test health check and system endpoints"""

    def test_health_check(self):
        """Test health check endpoint"""
        response = client.get("/api/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "unhealthy"]
        assert "version" in data
        assert "services" in data

    def test_root_endpoint(self):
        """Test root endpoint"""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "3.0.0"
        assert "features" in data
        assert "endpoints" in data


class TestAuthentication:
    """Test authentication functionality"""

    def test_register_user(self, test_db):
        """Test user registration"""
        response = client.post("/api/auth/register", json={
            "email": "newuser@driftbuddy.com",
            "username": "newuser",
            "password": "password123"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "newuser@driftbuddy.com"
        assert data["role"] == "developer"

    def test_login_user(self, admin_user):
        """Test user login"""
        response = client.post("/api/auth/login", data={
            "email": admin_user.email,
            "password": "admin123"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "user" in data

    def test_get_current_user(self, admin_user):
        """Test getting current user info"""
        headers = get_auth_headers(admin_user)
        
        response = client.get("/api/auth/me", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == admin_user.email
        assert data["role"] == "admin"


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 