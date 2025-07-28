"""
Compliance API Router for DriftBuddy
Provides endpoints for compliance framework management, assessments, and reporting
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, Form, status
from sqlalchemy.orm import Session

from .auth import get_current_active_user, require_admin
from .database import get_db
from .models import (
    ComplianceFramework,
    ComplianceControl,
    ComplianceAssessment,
    AssessmentControlResult,
    ComplianceEvidence,
    AuditEvent,
    RemediationTask,
    User,
    ComplianceFrameworkCreate,
    ComplianceFrameworkResponse,
    ComplianceControlResponse,
    ComplianceAssessmentCreate,
    ComplianceAssessmentResponse,
    AssessmentControlResultResponse,
    ComplianceEvidenceCreate,
    ComplianceEvidenceResponse,
    AuditEventResponse,
    RemediationTaskCreate,
    RemediationTaskResponse,
)
from .compliance_service import ComplianceService

router = APIRouter(prefix="/api/compliance", tags=["Compliance"])
compliance_service = ComplianceService()


# Framework Management
@router.get("/frameworks", response_model=List[ComplianceFrameworkResponse], operation_id="get_compliance_frameworks_router")
async def get_compliance_frameworks(
    active_only: bool = True,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all compliance frameworks"""
    try:
        frameworks = compliance_service.get_frameworks(db, active_only)
        return [
            ComplianceFrameworkResponse(
                id=f.id,
                name=f.name,
                version=f.version,
                description=f.description,
                category=f.category,
                is_active=f.is_active,
                control_count=len(f.controls),
                created_at=f.created_at
            )
            for f in frameworks
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get frameworks: {str(e)}")


@router.post("/frameworks", response_model=ComplianceFrameworkResponse, operation_id="create_compliance_framework_router")
async def create_compliance_framework(
    framework_data: ComplianceFrameworkCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create a new compliance framework"""
    try:
        framework = ComplianceFramework(
            name=framework_data.name,
            version=framework_data.version,
            description=framework_data.description,
            category=framework_data.category,
            framework_metadata=framework_data.framework_metadata or {}
        )
        db.add(framework)
        db.commit()
        db.refresh(framework)
        
        return ComplianceFrameworkResponse(
            id=framework.id,
            name=framework.name,
            version=framework.version,
            description=framework.description,
            category=framework.category,
            is_active=framework.is_active,
            control_count=0,
            created_at=framework.created_at
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create framework: {str(e)}")


@router.get("/frameworks/{framework_id}/controls", response_model=List[ComplianceControlResponse])
async def get_framework_controls(
    framework_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all controls for a specific framework"""
    try:
        controls = compliance_service.get_framework_controls(db, framework_id)
        return [
            ComplianceControlResponse(
                id=c.id,
                control_id=c.control_id,
                title=c.title,
                description=c.description,
                category=c.category,
                priority=c.priority,
                implementation_guidance=c.implementation_guidance,
                testing_procedures=c.testing_procedures
            )
            for c in controls
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get controls: {str(e)}")


# Assessment Management
@router.post("/assessments", response_model=ComplianceAssessmentResponse, operation_id="create_compliance_assessment_router")
async def create_compliance_assessment(
    assessment_data: ComplianceAssessmentCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a new compliance assessment"""
    try:
        assessment = compliance_service.create_assessment(db, assessment_data.dict(), current_user)
        
        return ComplianceAssessmentResponse(
            id=assessment.id,
            framework_name=assessment.framework.name,
            name=assessment.name,
            description=assessment.description,
            assessment_type=assessment.assessment_type,
            status=assessment.status,
            start_date=assessment.start_date,
            end_date=assessment.end_date,
            overall_score=assessment.overall_score,
            compliance_percentage=assessment.compliance_percentage,
            control_count=0,
            compliant_count=0,
            non_compliant_count=0,
            created_at=assessment.created_at
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create assessment: {str(e)}")


@router.get("/assessments", response_model=List[ComplianceAssessmentResponse], operation_id="get_compliance_assessments_router")
async def get_compliance_assessments(
    framework_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all assessments for the user's organization"""
    try:
        assessments = compliance_service.get_assessments(db, current_user, framework_id)
        
        result = []
        for assessment in assessments:
            # Calculate metrics
            control_results = db.query(AssessmentControlResult).filter(
                AssessmentControlResult.assessment_id == assessment.id
            ).all()
            
            total_controls = len(control_results)
            compliant_controls = len([cr for cr in control_results if cr.status == "compliant"])
            non_compliant_controls = len([cr for cr in control_results if cr.status == "non_compliant"])
            
            result.append(ComplianceAssessmentResponse(
                id=assessment.id,
                framework_name=assessment.framework.name,
                name=assessment.name,
                description=assessment.description,
                assessment_type=assessment.assessment_type,
                status=assessment.status,
                start_date=assessment.start_date,
                end_date=assessment.end_date,
                overall_score=assessment.overall_score,
                compliance_percentage=assessment.compliance_percentage,
                control_count=total_controls,
                compliant_count=compliant_controls,
                non_compliant_count=non_compliant_controls,
                created_at=assessment.created_at
            ))
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get assessments: {str(e)}")


@router.get("/assessments/{assessment_id}", response_model=ComplianceAssessmentResponse)
async def get_assessment_details(
    assessment_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get detailed assessment information"""
    try:
        assessment = compliance_service.get_assessment_details(db, assessment_id, current_user)
        if not assessment:
            raise HTTPException(status_code=404, detail="Assessment not found")
        
        # Calculate metrics
        control_results = db.query(AssessmentControlResult).filter(
            AssessmentControlResult.assessment_id == assessment_id
        ).all()
        
        total_controls = len(control_results)
        compliant_controls = len([cr for cr in control_results if cr.status == "compliant"])
        non_compliant_controls = len([cr for cr in control_results if cr.status == "non_compliant"])
        
        return ComplianceAssessmentResponse(
            id=assessment.id,
            framework_name=assessment.framework.name,
            name=assessment.name,
            description=assessment.description,
            assessment_type=assessment.assessment_type,
            status=assessment.status,
            start_date=assessment.start_date,
            end_date=assessment.end_date,
            overall_score=assessment.overall_score,
            compliance_percentage=assessment.compliance_percentage,
            control_count=total_controls,
            compliant_count=compliant_controls,
            non_compliant_count=non_compliant_controls,
            created_at=assessment.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get assessment details: {str(e)}")


@router.get("/assessments/{assessment_id}/controls", response_model=List[AssessmentControlResultResponse])
async def get_assessment_controls(
    assessment_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all control results for an assessment"""
    try:
        # Verify assessment belongs to user's organization
        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == assessment_id,
            ComplianceAssessment.organization_id == current_user.organization_id
        ).first()
        
        if not assessment:
            raise HTTPException(status_code=404, detail="Assessment not found")
        
        control_results = db.query(AssessmentControlResult).filter(
            AssessmentControlResult.assessment_id == assessment_id
        ).all()
        
        return [
            AssessmentControlResultResponse(
                id=cr.id,
                control_id=cr.control.control_id,
                control_title=cr.control.title,
                status=cr.status,
                score=cr.score,
                findings=cr.findings,
                remediation_plan=cr.remediation_plan,
                evidence_count=cr.evidence_count,
                last_tested=cr.last_tested
            )
            for cr in control_results
        ]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get control results: {str(e)}")


@router.post("/assessments/{assessment_id}/controls/{control_id}/test")
async def test_control(
    assessment_id: int,
    control_id: int,
    status: str = Form(...),
    findings: Optional[str] = Form(None),
    remediation_plan: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Test a specific control and record results"""
    try:
        result = compliance_service.test_control(
            db, assessment_id, control_id, status, findings, remediation_plan, current_user
        )
        
        return {
            "success": True,
            "message": f"Control {result.control.control_id} tested successfully",
            "result": {
                "id": result.id,
                "status": result.status,
                "last_tested": result.last_tested.isoformat() if result.last_tested else None
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to test control: {str(e)}")


# Evidence Management
@router.post("/assessments/{assessment_id}/evidence")
async def collect_evidence(
    assessment_id: int,
    evidence_type: str = Form(...),
    title: str = Form(...),
    description: Optional[str] = Form(None),
    control_result_id: Optional[int] = Form(None),
    evidence_data: Optional[str] = Form(None),  # JSON string
    file: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Collect evidence for compliance controls"""
    try:
        # Parse evidence data if provided
        parsed_evidence_data = None
        if evidence_data:
            try:
                parsed_evidence_data = json.loads(evidence_data)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid evidence data format")
        
        # Handle file upload if provided
        file_path = None
        file_size = None
        mime_type = None
        
        if file:
            # Create uploads directory if it doesn't exist
            upload_dir = "uploads/evidence"
            os.makedirs(upload_dir, exist_ok=True)
            
            # Generate unique filename
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{file.filename}"
            file_path = os.path.join(upload_dir, filename)
            
            # Save file
            with open(file_path, "wb") as buffer:
                content = file.file.read()
                buffer.write(content)
                file_size = len(content)
            
            mime_type = file.content_type
        
        evidence_data_dict = {
            "evidence_type": evidence_type,
            "title": title,
            "description": description,
            "control_result_id": control_result_id,
            "file_path": file_path,
            "file_size": file_size,
            "mime_type": mime_type,
            "evidence_data": parsed_evidence_data
        }
        
        evidence = compliance_service.collect_evidence(db, assessment_id, evidence_data_dict, current_user)
        
        return {
            "success": True,
            "message": "Evidence collected successfully",
            "evidence": {
                "id": evidence.id,
                "title": evidence.title,
                "evidence_type": evidence.evidence_type,
                "collected_at": evidence.collected_at.isoformat()
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to collect evidence: {str(e)}")


@router.get("/assessments/{assessment_id}/evidence", response_model=List[ComplianceEvidenceResponse])
async def get_assessment_evidence(
    assessment_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get all evidence for an assessment"""
    try:
        # Verify assessment belongs to user's organization
        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == assessment_id,
            ComplianceAssessment.organization_id == current_user.organization_id
        ).first()
        
        if not assessment:
            raise HTTPException(status_code=404, detail="Assessment not found")
        
        evidence_items = db.query(ComplianceEvidence).filter(
            ComplianceEvidence.assessment_id == assessment_id
        ).all()
        
        return [
            ComplianceEvidenceResponse(
                id=e.id,
                evidence_type=e.evidence_type,
                title=e.title,
                description=e.description,
                file_path=e.file_path,
                file_size=e.file_size,
                mime_type=e.mime_type,
                is_verified=e.is_verified,
                collected_at=e.collected_at,
                verified_at=e.verified_at
            )
            for e in evidence_items
        ]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get evidence: {str(e)}")


# Reporting
@router.get("/assessments/{assessment_id}/report")
async def generate_compliance_report(
    assessment_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Generate comprehensive compliance report"""
    try:
        report_data = compliance_service.generate_compliance_report(db, assessment_id, current_user)
        
        return {
            "success": True,
            "report": report_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


# Remediation Tasks
@router.post("/remediation-tasks", response_model=RemediationTaskResponse)
async def create_remediation_task(
    task_data: RemediationTaskCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Create a remediation task for compliance gaps"""
    try:
        # Get assessment_id from control_result
        control_result = db.query(AssessmentControlResult).filter(
            AssessmentControlResult.id == task_data.control_result_id
        ).first()
        
        if not control_result:
            raise HTTPException(status_code=404, detail="Control result not found")
        
        task_dict = task_data.dict()
        task_dict["assessment_id"] = control_result.assessment_id
        
        task = compliance_service.create_remediation_task(db, task_dict, current_user)
        
        return RemediationTaskResponse(
            id=task.id,
            title=task.title,
            description=task.description,
            priority=task.priority,
            status=task.status,
            assigned_to=task.assignee.username if task.assignee else None,
            due_date=task.due_date,
            completed_at=task.completed_at,
            completion_notes=task.completion_notes,
            created_at=task.created_at
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create remediation task: {str(e)}")


@router.get("/remediation-tasks", response_model=List[RemediationTaskResponse])
async def get_remediation_tasks(
    assessment_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get remediation tasks for the user's organization"""
    try:
        tasks = compliance_service.get_remediation_tasks(db, current_user, assessment_id)
        
        return [
            RemediationTaskResponse(
                id=task.id,
                title=task.title,
                description=task.description,
                priority=task.priority,
                status=task.status,
                assigned_to=task.assignee.username if task.assignee else None,
                due_date=task.due_date,
                completed_at=task.completed_at,
                completion_notes=task.completion_notes,
                created_at=task.created_at
            )
            for task in tasks
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get remediation tasks: {str(e)}")


@router.put("/remediation-tasks/{task_id}")
async def update_remediation_task(
    task_id: int,
    status: Optional[str] = Form(None),
    completion_notes: Optional[str] = Form(None),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Update a remediation task"""
    try:
        task_data = {}
        if status is not None:
            task_data["status"] = status
        if completion_notes is not None:
            task_data["completion_notes"] = completion_notes
        
        task = compliance_service.update_remediation_task(db, task_id, task_data, current_user)
        
        return {
            "success": True,
            "message": "Remediation task updated successfully",
            "task": {
                "id": task.id,
                "title": task.title,
                "status": task.status,
                "updated_at": task.updated_at.isoformat()
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update remediation task: {str(e)}")


# Audit Events
@router.get("/audit-events", response_model=List[AuditEventResponse], operation_id="get_audit_events_router")
async def get_audit_events(
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get audit events for compliance activities"""
    try:
        events = compliance_service.get_audit_events(db, current_user, limit)
        
        return [
            AuditEventResponse(
                id=e.id,
                event_type=e.event_type,
                event_category=e.event_category,
                description=e.description,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                ip_address=e.ip_address,
                created_at=e.created_at
            )
            for e in events
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get audit events: {str(e)}")


# Setup and Initialization
@router.post("/setup-defaults")
async def setup_default_compliance_frameworks(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Set up default compliance frameworks and controls"""
    try:
        compliance_service.create_default_frameworks(db)
        
        return {
            "success": True,
            "message": "Default compliance frameworks created successfully",
            "frameworks_created": list(compliance_service.default_frameworks.keys())
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to setup default frameworks: {str(e)}")


# Dashboard and Analytics
@router.get("/dashboard/overview")
async def get_compliance_dashboard(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get compliance dashboard overview"""
    try:
        # Get assessments for user's organization
        assessments = compliance_service.get_assessments(db, current_user)
        
        # Calculate overall metrics
        total_assessments = len(assessments)
        active_assessments = len([a for a in assessments if a.status in ["draft", "in_progress"]])
        completed_assessments = len([a for a in assessments if a.status == "completed"])
        
        # Calculate average compliance score
        compliance_scores = [a.compliance_percentage for a in assessments if a.compliance_percentage is not None]
        avg_compliance_score = sum(compliance_scores) / len(compliance_scores) if compliance_scores else 0
        
        # Get recent audit events
        recent_events = compliance_service.get_audit_events(db, current_user, 10)
        
        # Get open remediation tasks
        open_tasks = compliance_service.get_remediation_tasks(db, current_user)
        open_tasks_count = len([t for t in open_tasks if t.status in ["open", "in_progress"]])
        
        return {
            "overview": {
                "total_assessments": total_assessments,
                "active_assessments": active_assessments,
                "completed_assessments": completed_assessments,
                "avg_compliance_score": round(avg_compliance_score, 2),
                "open_remediation_tasks": open_tasks_count
            },
            "recent_activities": [
                {
                    "event_type": e.event_type,
                    "description": e.description,
                    "created_at": e.created_at.isoformat()
                }
                for e in recent_events
            ],
            "frameworks": [
                {
                    "name": f.name,
                    "version": f.version,
                    "control_count": len(f.controls)
                }
                for f in compliance_service.get_frameworks(db)
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dashboard: {str(e)}") 