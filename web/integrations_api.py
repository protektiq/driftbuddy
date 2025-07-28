"""
Integrations API endpoints for DriftBuddy
Handles external integrations with cloud providers, development platforms, and communication tools
"""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .auth import get_current_active_user, require_admin
from .database import get_db
from .models import (
    Integration, IntegrationLog, User,
    IntegrationCreate, IntegrationResponse, IntegrationTestRequest, 
    IntegrationTestResponse, IntegrationSyncRequest, IntegrationSyncResponse,
    IntegrationLogResponse
)
from .integrations_service import IntegrationsService

router = APIRouter(prefix="/api/integrations", tags=["Integrations"])
integrations_service = IntegrationsService()


@router.get("/", response_model=List[IntegrationResponse])
async def get_integrations(
    provider: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all integrations, optionally filtered by provider"""
    integrations = integrations_service.get_integrations(db, provider)
    return integrations


@router.post("/", response_model=IntegrationResponse)
async def create_integration(
    integration_data: IntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create a new integration"""
    try:
        integration = integrations_service.create_integration(db, integration_data.dict())
        return integration
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create integration: {str(e)}"
        )


@router.get("/supported", response_model=Dict[str, Any])
async def get_supported_integrations(
    current_user: User = Depends(get_current_active_user)
):
    """Get list of supported integrations and their capabilities"""
    return integrations_service.get_supported_integrations()


@router.post("/test", response_model=IntegrationTestResponse)
async def test_integration(
    test_request: IntegrationTestRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Test an integration configuration"""
    try:
        if test_request.provider == "aws":
            result = integrations_service.test_aws_integration(test_request.config)
        elif test_request.provider == "azure":
            result = integrations_service.test_azure_integration(test_request.config)
        elif test_request.provider == "gcp":
            result = integrations_service.test_gcp_integration(test_request.config)
        elif test_request.provider == "github":
            result = integrations_service.test_github_integration(test_request.config)
        elif test_request.provider == "slack":
            result = integrations_service.test_slack_integration(test_request.config)
        elif test_request.provider == "teams":
            result = integrations_service.test_teams_integration(test_request.config)
        elif test_request.provider == "jira":
            result = integrations_service.test_jira_integration(test_request.config)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported provider: {test_request.provider}"
            )
        
        return IntegrationTestResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Integration test failed: {str(e)}"
        )


@router.post("/{integration_id}/sync", response_model=IntegrationSyncResponse)
async def sync_integration(
    integration_id: int,
    sync_request: IntegrationSyncRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Sync findings from an integration"""
    try:
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
        
        if integration.provider == "aws":
            result = integrations_service.sync_aws_findings(db, integration)
        elif integration.provider == "azure":
            result = integrations_service.sync_azure_findings(db, integration)
        elif integration.provider == "github":
            result = integrations_service.sync_github_findings(db, integration)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Sync not supported for provider: {integration.provider}"
            )
        
        return IntegrationSyncResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Sync failed: {str(e)}"
        )


@router.get("/{integration_id}/logs", response_model=List[IntegrationLogResponse])
async def get_integration_logs(
    integration_id: int,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get logs for a specific integration"""
    logs = integrations_service.get_integration_logs(db, integration_id, limit)
    return logs


@router.post("/{integration_id}/notify")
async def send_notification(
    integration_id: int,
    notification_data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Send notification through an integration"""
    try:
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
        
        message = notification_data.get("message", "")
        severity = notification_data.get("severity", "info")
        findings = notification_data.get("findings", [])
        
        if integration.provider == "slack":
            result = integrations_service.send_slack_notification(
                integration.config, message, severity, findings
            )
        elif integration.provider == "teams":
            result = integrations_service.send_teams_notification(
                integration.config, message, severity, findings
            )
        elif integration.provider == "email":
            recipients = notification_data.get("recipients", [])
            subject = notification_data.get("subject", "DriftBuddy Notification")
            result = integrations_service.send_email_notification(
                integration.config, subject, message, recipients
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Notifications not supported for provider: {integration.provider}"
            )
        
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Notification failed: {str(e)}"
        )


@router.post("/jira/create-ticket")
async def create_jira_ticket(
    integration_id: int,
    finding_data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a JIRA ticket for a finding"""
    try:
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
        
        if integration.provider != "jira":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Integration is not a JIRA integration"
            )
        
        result = integrations_service.create_jira_ticket(integration.config, finding_data)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"JIRA ticket creation failed: {str(e)}"
        )


@router.put("/{integration_id}/toggle")
async def toggle_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Toggle integration active status"""
    try:
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
        
        integration.is_active = not integration.is_active
        db.commit()
        db.refresh(integration)
        
        return {"message": f"Integration {'activated' if integration.is_active else 'deactivated'}"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to toggle integration: {str(e)}"
        )


@router.delete("/{integration_id}")
async def delete_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete an integration"""
    try:
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
        
        db.delete(integration)
        db.commit()
        
        return {"message": "Integration deleted successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to delete integration: {str(e)}"
        )


@router.get("/{integration_id}/status")
async def get_integration_status(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get detailed status of an integration"""
    try:
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Integration not found"
            )
        
        # Get recent logs
        recent_logs = integrations_service.get_integration_logs(db, integration_id, 10)
        
        return {
            "integration": integration,
            "recent_logs": recent_logs,
            "last_sync": integration.last_sync,
            "error_count": integration.error_count,
            "last_error": integration.last_error
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to get integration status: {str(e)}"
        ) 