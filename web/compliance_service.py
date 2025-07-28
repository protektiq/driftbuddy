"""
Compliance Service for DriftBuddy
Handles compliance frameworks, assessments, evidence collection, and reporting
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from .models import (
    ComplianceFramework,
    ComplianceControl,
    ComplianceAssessment,
    AssessmentControlResult,
    ComplianceEvidence,
    AuditEvent,
    RemediationTask,
    User,
    Organization,
    Scan,
    Finding,
)


class ComplianceService:
    """Service for managing compliance frameworks and assessments"""

    def __init__(self):
        self.default_frameworks = {
            "SOC 2": {
                "version": "2017",
                "description": "System and Organization Controls 2",
                "category": "security",
                "controls": [
                    {
                        "control_id": "CC1.1",
                        "title": "Control Environment",
                        "description": "The entity demonstrates a commitment to integrity and ethical values.",
                        "category": "Control Environment",
                        "priority": "high"
                    },
                    {
                        "control_id": "CC2.1",
                        "title": "Communication and Information",
                        "description": "The entity communicates information to support the functioning of internal control.",
                        "category": "Communication and Information",
                        "priority": "high"
                    },
                    {
                        "control_id": "CC3.1",
                        "title": "Risk Assessment",
                        "description": "The entity demonstrates a commitment to identify and assess risks.",
                        "category": "Risk Assessment",
                        "priority": "high"
                    },
                    {
                        "control_id": "CC4.1",
                        "title": "Monitoring Activities",
                        "description": "The entity demonstrates a commitment to assess the quality of internal control performance.",
                        "category": "Monitoring Activities",
                        "priority": "medium"
                    },
                    {
                        "control_id": "CC5.1",
                        "title": "Control Activities",
                        "description": "The entity demonstrates a commitment to develop and perform control activities.",
                        "category": "Control Activities",
                        "priority": "high"
                    },
                    {
                        "control_id": "CC6.1",
                        "title": "Logical and Physical Access Controls",
                        "description": "The entity implements logical and physical access controls.",
                        "category": "Access Control",
                        "priority": "high"
                    },
                    {
                        "control_id": "CC7.1",
                        "title": "System Operations",
                        "description": "The entity implements security over system operations.",
                        "category": "System Operations",
                        "priority": "medium"
                    },
                    {
                        "control_id": "CC8.1",
                        "title": "Change Management",
                        "description": "The entity implements security over system changes.",
                        "category": "Change Management",
                        "priority": "medium"
                    },
                    {
                        "control_id": "CC9.1",
                        "title": "Risk Mitigation",
                        "description": "The entity implements security over system operations.",
                        "category": "Risk Mitigation",
                        "priority": "medium"
                    }
                ]
            },
            "ISO 27001": {
                "version": "2022",
                "description": "Information Security Management System",
                "category": "security",
                "controls": [
                    {
                        "control_id": "A.5.1.1",
                        "title": "Information Security Policies",
                        "description": "Information security policy and topic-specific policies.",
                        "category": "Organizational Controls",
                        "priority": "high"
                    },
                    {
                        "control_id": "A.5.2.1",
                        "title": "Information Security Roles and Responsibilities",
                        "description": "Define and allocate information security responsibilities.",
                        "category": "Organizational Controls",
                        "priority": "high"
                    },
                    {
                        "control_id": "A.6.1.1",
                        "title": "Screening",
                        "description": "Background verification checks for candidates.",
                        "category": "People Controls",
                        "priority": "medium"
                    },
                    {
                        "control_id": "A.7.1.1",
                        "title": "Physical Security Perimeters",
                        "description": "Define and use security perimeters.",
                        "category": "Physical Controls",
                        "priority": "medium"
                    },
                    {
                        "control_id": "A.8.1.1",
                        "title": "Inventory of Information and Other Associated Assets",
                        "description": "Identify information and other associated assets.",
                        "category": "Technological Controls",
                        "priority": "high"
                    },
                    {
                        "control_id": "A.9.1.1",
                        "title": "Access Control Policy",
                        "description": "Define and apply access control policy.",
                        "category": "Technological Controls",
                        "priority": "high"
                    }
                ]
            },
            "PCI DSS": {
                "version": "4.0",
                "description": "Payment Card Industry Data Security Standard",
                "category": "financial",
                "controls": [
                    {
                        "control_id": "1.1.1",
                        "title": "Network Security Controls",
                        "description": "Implement network security controls.",
                        "category": "Network Security",
                        "priority": "high"
                    },
                    {
                        "control_id": "2.1.1",
                        "title": "Vendor Defaults",
                        "description": "Change vendor defaults and remove unnecessary accounts.",
                        "category": "Access Control",
                        "priority": "high"
                    },
                    {
                        "control_id": "3.1.1",
                        "title": "Cardholder Data Protection",
                        "description": "Protect stored cardholder data.",
                        "category": "Data Protection",
                        "priority": "high"
                    },
                    {
                        "control_id": "4.1.1",
                        "title": "Data Transmission Security",
                        "description": "Encrypt transmission of cardholder data.",
                        "category": "Data Protection",
                        "priority": "high"
                    },
                    {
                        "control_id": "5.1.1",
                        "title": "Malware Protection",
                        "description": "Protect systems against malware.",
                        "category": "Vulnerability Management",
                        "priority": "medium"
                    },
                    {
                        "control_id": "6.1.1",
                        "title": "Security Vulnerabilities",
                        "description": "Identify and address security vulnerabilities.",
                        "category": "Vulnerability Management",
                        "priority": "high"
                    }
                ]
            },
            "NIST CSF": {
                "version": "2.0",
                "description": "NIST Cybersecurity Framework",
                "category": "security",
                "controls": [
                    {
                        "control_id": "ID.AM-1",
                        "title": "Asset Inventory",
                        "description": "Physical devices and systems within the organization.",
                        "category": "Identify",
                        "priority": "high"
                    },
                    {
                        "control_id": "ID.AM-2",
                        "title": "Software Platforms and Applications",
                        "description": "Software platforms and applications within the organization.",
                        "category": "Identify",
                        "priority": "high"
                    },
                    {
                        "control_id": "PR.AC-1",
                        "title": "Identity Management and Access Control",
                        "description": "Identities and credentials are managed.",
                        "category": "Protect",
                        "priority": "high"
                    },
                    {
                        "control_id": "PR.AC-2",
                        "title": "Physical Access Control",
                        "description": "Physical access to assets is controlled.",
                        "category": "Protect",
                        "priority": "medium"
                    },
                    {
                        "control_id": "DE.AE-1",
                        "title": "Baseline Network Operations",
                        "description": "Baseline network operations are established.",
                        "category": "Detect",
                        "priority": "medium"
                    },
                    {
                        "control_id": "RS.RP-1",
                        "title": "Response Planning Process",
                        "description": "Response processes and procedures are executed.",
                        "category": "Respond",
                        "priority": "medium"
                    }
                ]
            }
        }

    def create_default_frameworks(self, db: Session) -> None:
        """Create default compliance frameworks and controls"""
        try:
            for framework_name, framework_data in self.default_frameworks.items():
                # Check if framework already exists
                existing_framework = db.query(ComplianceFramework).filter(
                    ComplianceFramework.name == framework_name
                ).first()
                
                if existing_framework:
                    continue
                
                # Create framework
                framework = ComplianceFramework(
                    name=framework_name,
                    version=framework_data["version"],
                    description=framework_data["description"],
                    category=framework_data["category"],
                    framework_metadata={
                        "source": "default",
                        "controls_count": len(framework_data["controls"])
                    }
                )
                db.add(framework)
                db.flush()  # Get the framework ID
                
                # Create controls for this framework
                for control_data in framework_data["controls"]:
                    control = ComplianceControl(
                        framework_id=framework.id,
                        control_id=control_data["control_id"],
                        title=control_data["title"],
                        description=control_data["description"],
                        category=control_data["category"],
                        priority=control_data["priority"],
                        implementation_guidance=f"Implement {control_data['title']} according to {framework_name} requirements.",
                        testing_procedures=f"Test {control_data['title']} implementation and effectiveness."
                    )
                    db.add(control)
                
                db.commit()
                print(f"✅ Created {framework_name} framework with {len(framework_data['controls'])} controls")
                
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to create default frameworks: {str(e)}")
            raise

    def get_frameworks(self, db: Session, active_only: bool = True) -> List[ComplianceFramework]:
        """Get all compliance frameworks"""
        query = db.query(ComplianceFramework)
        if active_only:
            query = query.filter(ComplianceFramework.is_active == True)
        return query.all()

    def get_framework_controls(self, db: Session, framework_id: int) -> List[ComplianceControl]:
        """Get all controls for a specific framework"""
        return db.query(ComplianceControl).filter(
            ComplianceControl.framework_id == framework_id
        ).all()

    def create_assessment(self, db: Session, assessment_data: Dict[str, Any], user: User) -> ComplianceAssessment:
        """Create a new compliance assessment"""
        try:
            assessment = ComplianceAssessment(
                framework_id=assessment_data["framework_id"],
                organization_id=user.organization_id,
                name=assessment_data["name"],
                description=assessment_data.get("description"),
                assessment_type=assessment_data["assessment_type"],
                start_date=assessment_data.get("start_date"),
                end_date=assessment_data.get("end_date"),
                assessor_id=user.id
            )
            db.add(assessment)
            db.commit()
            db.refresh(assessment)
            
            # Create audit event
            self._create_audit_event(
                db, user, "assessment_created", "compliance",
                f"Created assessment: {assessment.name}",
                "assessment", assessment.id
            )
            
            return assessment
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to create assessment: {str(e)}")
            raise

    def get_assessments(self, db: Session, user: User, framework_id: Optional[int] = None) -> List[ComplianceAssessment]:
        """Get assessments for a user's organization"""
        query = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.organization_id == user.organization_id
        )
        
        if framework_id:
            query = query.filter(ComplianceAssessment.framework_id == framework_id)
            
        return query.all()

    def get_assessment_details(self, db: Session, assessment_id: int, user: User) -> Optional[ComplianceAssessment]:
        """Get detailed assessment information"""
        assessment = db.query(ComplianceAssessment).filter(
            ComplianceAssessment.id == assessment_id,
            ComplianceAssessment.organization_id == user.organization_id
        ).first()
        
        if assessment:
            # Calculate compliance metrics
            control_results = db.query(AssessmentControlResult).filter(
                AssessmentControlResult.assessment_id == assessment_id
            ).all()
            
            total_controls = len(control_results)
            compliant_controls = len([cr for cr in control_results if cr.status == "compliant"])
            non_compliant_controls = len([cr for cr in control_results if cr.status == "non_compliant"])
            
            if total_controls > 0:
                assessment.compliance_percentage = (compliant_controls / total_controls) * 100
                assessment.overall_score = int(assessment.compliance_percentage)
            
        return assessment

    def test_control(self, db: Session, assessment_id: int, control_id: int, 
                    status: str, findings: Optional[str] = None, 
                    remediation_plan: Optional[str] = None, user: User = None) -> AssessmentControlResult:
        """Test a specific control and record results"""
        try:
            # Check if result already exists
            existing_result = db.query(AssessmentControlResult).filter(
                AssessmentControlResult.assessment_id == assessment_id,
                AssessmentControlResult.control_id == control_id
            ).first()
            
            if existing_result:
                # Update existing result
                existing_result.status = status
                existing_result.findings = findings
                existing_result.remediation_plan = remediation_plan
                existing_result.last_tested = datetime.utcnow()
                existing_result.tester_id = user.id if user else None
                existing_result.updated_at = datetime.utcnow()
                result = existing_result
            else:
                # Create new result
                result = AssessmentControlResult(
                    assessment_id=assessment_id,
                    control_id=control_id,
                    status=status,
                    findings=findings,
                    remediation_plan=remediation_plan,
                    last_tested=datetime.utcnow(),
                    tester_id=user.id if user else None
                )
                db.add(result)
            
            db.commit()
            db.refresh(result)
            
            # Create audit event
            if user:
                self._create_audit_event(
                    db, user, "control_tested", "compliance",
                    f"Tested control {result.control.control_id}: {status}",
                    "control_result", result.id
                )
            
            return result
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to test control: {str(e)}")
            raise

    def collect_evidence(self, db: Session, assessment_id: int, evidence_data: Dict[str, Any], user: User) -> ComplianceEvidence:
        """Collect evidence for compliance controls"""
        try:
            evidence = ComplianceEvidence(
                assessment_id=assessment_id,
                control_result_id=evidence_data.get("control_result_id"),
                evidence_type=evidence_data["evidence_type"],
                title=evidence_data["title"],
                description=evidence_data.get("description"),
                file_path=evidence_data.get("file_path"),
                file_size=evidence_data.get("file_size"),
                mime_type=evidence_data.get("mime_type"),
                evidence_data=evidence_data.get("evidence_data"),
                collected_by=user.id
            )
            db.add(evidence)
            db.commit()
            db.refresh(evidence)
            
            # Update evidence count for control result
            if evidence.control_result_id:
                control_result = db.query(AssessmentControlResult).filter(
                    AssessmentControlResult.id == evidence.control_result_id
                ).first()
                if control_result:
                    control_result.evidence_count += 1
                    db.commit()
            
            # Create audit event
            self._create_audit_event(
                db, user, "evidence_collected", "compliance",
                f"Collected evidence: {evidence.title}",
                "evidence", evidence.id
            )
            
            return evidence
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to collect evidence: {str(e)}")
            raise

    def generate_compliance_report(self, db: Session, assessment_id: int, user: User) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        try:
            assessment = self.get_assessment_details(db, assessment_id, user)
            if not assessment:
                raise ValueError("Assessment not found")
            
            # Get framework details
            framework = db.query(ComplianceFramework).filter(
                ComplianceFramework.id == assessment.framework_id
            ).first()
            
            # Get all control results
            control_results = db.query(AssessmentControlResult).filter(
                AssessmentControlResult.assessment_id == assessment_id
            ).all()
            
            # Calculate metrics
            total_controls = len(control_results)
            compliant_controls = len([cr for cr in control_results if cr.status == "compliant"])
            non_compliant_controls = len([cr for cr in control_results if cr.status == "non_compliant"])
            partially_compliant_controls = len([cr for cr in control_results if cr.status == "partially_compliant"])
            not_applicable_controls = len([cr for cr in control_results if cr.status == "not_applicable"])
            
            # Get evidence count
            evidence_count = db.query(ComplianceEvidence).filter(
                ComplianceEvidence.assessment_id == assessment_id
            ).count()
            
            # Generate report data
            report_data = {
                "assessment": {
                    "id": assessment.id,
                    "name": assessment.name,
                    "framework": framework.name,
                    "framework_version": framework.version,
                    "status": assessment.status,
                    "start_date": assessment.start_date,
                    "end_date": assessment.end_date,
                    "assessor": user.username
                },
                "metrics": {
                    "total_controls": total_controls,
                    "compliant_controls": compliant_controls,
                    "non_compliant_controls": non_compliant_controls,
                    "partially_compliant_controls": partially_compliant_controls,
                    "not_applicable_controls": not_applicable_controls,
                    "compliance_percentage": assessment.compliance_percentage,
                    "overall_score": assessment.overall_score,
                    "evidence_count": evidence_count
                },
                "control_results": [
                    {
                        "control_id": cr.control.control_id,
                        "title": cr.control.title,
                        "category": cr.control.category,
                        "priority": cr.control.priority,
                        "status": cr.status,
                        "score": cr.score,
                        "findings": cr.findings,
                        "remediation_plan": cr.remediation_plan,
                        "evidence_count": cr.evidence_count,
                        "last_tested": cr.last_tested
                    }
                    for cr in control_results
                ],
                "recommendations": self._generate_recommendations(control_results),
                "generated_at": datetime.utcnow().isoformat()
            }
            
            return report_data
            
        except Exception as e:
            print(f"❌ Failed to generate compliance report: {str(e)}")
            raise

    def _generate_recommendations(self, control_results: List[AssessmentControlResult]) -> List[Dict[str, str]]:
        """Generate recommendations based on control results"""
        recommendations = []
        
        non_compliant_controls = [cr for cr in control_results if cr.status == "non_compliant"]
        partially_compliant_controls = [cr for cr in control_results if cr.status == "partially_compliant"]
        
        # High priority recommendations for non-compliant controls
        for cr in non_compliant_controls:
            if cr.control.priority == "high":
                recommendations.append({
                    "priority": "high",
                    "type": "remediation",
                    "title": f"Address {cr.control.control_id}",
                    "description": f"Critical control {cr.control.control_id} is non-compliant. {cr.findings or 'No findings provided.'}",
                    "control_id": cr.control.control_id
                })
        
        # Medium priority recommendations
        for cr in non_compliant_controls:
            if cr.control.priority == "medium":
                recommendations.append({
                    "priority": "medium",
                    "type": "remediation",
                    "title": f"Improve {cr.control.control_id}",
                    "description": f"Control {cr.control.control_id} needs attention. {cr.findings or 'No findings provided.'}",
                    "control_id": cr.control.control_id
                })
        
        # Recommendations for partially compliant controls
        for cr in partially_compliant_controls:
            recommendations.append({
                "priority": "medium",
                "type": "improvement",
                "title": f"Enhance {cr.control.control_id}",
                "description": f"Control {cr.control.control_id} is partially compliant and needs improvement.",
                "control_id": cr.control.control_id
            })
        
        return recommendations

    def _create_audit_event(self, db: Session, user: User, event_type: str, event_category: str,
                           description: str, resource_type: Optional[str] = None, 
                           resource_id: Optional[int] = None) -> None:
        """Create an audit event"""
        try:
            audit_event = AuditEvent(
                user_id=user.id,
                event_type=event_type,
                event_category=event_category,
                description=description,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address="127.0.0.1",  # In production, get from request
                user_agent="DriftBuddy Compliance Service"
            )
            db.add(audit_event)
            db.commit()
        except Exception as e:
            print(f"❌ Failed to create audit event: {str(e)}")

    def get_audit_events(self, db: Session, user: User, limit: int = 100) -> List[AuditEvent]:
        """Get audit events for the user's organization"""
        return db.query(AuditEvent).filter(
            AuditEvent.user_id == user.id
        ).order_by(AuditEvent.created_at.desc()).limit(limit).all()

    def create_remediation_task(self, db: Session, task_data: Dict[str, Any], user: User) -> RemediationTask:
        """Create a remediation task for compliance gaps"""
        try:
            task = RemediationTask(
                assessment_id=task_data["assessment_id"],
                control_result_id=task_data["control_result_id"],
                title=task_data["title"],
                description=task_data.get("description"),
                priority=task_data.get("priority", "medium"),
                assigned_to=task_data.get("assigned_to"),
                due_date=task_data.get("due_date")
            )
            db.add(task)
            db.commit()
            db.refresh(task)
            
            # Create audit event
            self._create_audit_event(
                db, user, "remediation_task_created", "compliance",
                f"Created remediation task: {task.title}",
                "remediation_task", task.id
            )
            
            return task
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to create remediation task: {str(e)}")
            raise

    def get_remediation_tasks(self, db: Session, user: User, assessment_id: Optional[int] = None) -> List[RemediationTask]:
        """Get remediation tasks for the user's organization"""
        query = db.query(RemediationTask).join(ComplianceAssessment).filter(
            ComplianceAssessment.organization_id == user.organization_id
        )
        
        if assessment_id:
            query = query.filter(RemediationTask.assessment_id == assessment_id)
            
        return query.all()

    def update_remediation_task(self, db: Session, task_id: int, task_data: Dict[str, Any], user: User) -> RemediationTask:
        """Update a remediation task"""
        try:
            task = db.query(RemediationTask).filter(
                RemediationTask.id == task_id
            ).first()
            
            if not task:
                raise ValueError("Remediation task not found")
            
            # Update fields
            if "status" in task_data:
                task.status = task_data["status"]
            if "completion_notes" in task_data:
                task.completion_notes = task_data["completion_notes"]
            if task.status == "completed" and not task.completed_at:
                task.completed_at = datetime.utcnow()
            
            task.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(task)
            
            # Create audit event
            self._create_audit_event(
                db, user, "remediation_task_updated", "compliance",
                f"Updated remediation task: {task.title}",
                "remediation_task", task.id
            )
            
            return task
            
        except Exception as e:
            db.rollback()
            print(f"❌ Failed to update remediation task: {str(e)}")
            raise 