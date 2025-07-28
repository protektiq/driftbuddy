"""
Advanced Reporting and Export Service for DriftBuddy Web Interface
Provides comprehensive reporting with multiple export formats
"""

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import jinja2
from sqlalchemy.orm import Session

from .auth import get_user_permissions
from .models import Finding, Organization, Scan, User


class ReportingService:
    """Advanced reporting and export service"""

    def __init__(self):
        self.templates_dir = Path("templates")
        self.templates_dir.mkdir(exist_ok=True)
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)

        # Initialize Jinja2 environment
        self.jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(self.templates_dir)), autoescape=True)

        self._create_default_templates()

    def _create_default_templates(self):
        """Create default report templates"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ scan.name }} - Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .high { border-left: 5px solid #dc3545; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #28a745; }
        .severity { font-weight: bold; padding: 5px 10px; border-radius: 3px; }
        .severity.high { background: #dc3545; color: white; }
        .severity.medium { background: #ffc107; color: black; }
        .severity.low { background: #28a745; color: white; }
        .risk-score { font-size: 1.2em; font-weight: bold; }
        .metadata { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 DriftBuddy Security Report</h1>
        <h2>{{ scan.name }}</h2>
        <p class="metadata">
            Generated: {{ generated_at }}<br>
            Scan Type: {{ scan.scan_type }}<br>
            Status: {{ scan.status }}<br>
            Total Findings: {{ findings|length }}
        </p>
    </div>
    
    <div class="summary">
        <h3>📊 Executive Summary</h3>
        <p>
            This security scan identified <strong>{{ findings|length }}</strong> security findings
            across your infrastructure. The findings are categorized by severity level to help
            prioritize remediation efforts.
        </p>
        
        <div style="display: flex; gap: 20px; margin: 20px 0;">
            <div style="text-align: center;">
                <div style="font-size: 2em; color: #dc3545;">{{ high_count }}</div>
                <div>High Severity</div>
            </div>
            <div style="text-align: center;">
                <div style="font-size: 2em; color: #ffc107;">{{ medium_count }}</div>
                <div>Medium Severity</div>
            </div>
            <div style="text-align: center;">
                <div style="font-size: 2em; color: #28a745;">{{ low_count }}</div>
                <div>Low Severity</div>
            </div>
        </div>
    </div>
    
    <div class="findings">
        <h3>🔍 Detailed Findings</h3>
        {% for finding in findings %}
        <div class="finding {{ finding.severity.lower() }}">
            <h4>{{ finding.query_name }}</h4>
            <span class="severity {{ finding.severity.lower() }}">{{ finding.severity }}</span>
            <span class="risk-score">Risk Score: {{ finding.risk_score }}/25</span>
            <p><strong>Description:</strong> {{ finding.description }}</p>
            {% if finding.file_path %}
            <p><strong>File:</strong> {{ finding.file_path }}{% if finding.line_number %}:{{ finding.line_number }}{% endif %}</p>
            {% endif %}
            {% if finding.remediation %}
            <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
            {% endif %}
            {% if finding.ai_explanation %}
            <p><strong>AI Analysis:</strong> {{ finding.ai_explanation }}</p>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    
    <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 5px;">
        <h3>📋 Recommendations</h3>
        <ul>
            <li>Prioritize fixing high severity findings first</li>
            <li>Review medium severity findings for business impact</li>
            <li>Implement automated security scanning in your CI/CD pipeline</li>
            <li>Regular security reviews are recommended</li>
            <li>Consider implementing security training for development teams</li>
        </ul>
    </div>
</body>
</html>
        """

        with open(self.templates_dir / "report.html", "w") as f:
            f.write(html_template)

    async def generate_report(self, db: Session, scan_id: int, user: User, format: str = "html") -> Dict[str, Any]:
        """Generate comprehensive report for a scan"""
        try:
            # Get scan and findings
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return {"success": False, "error": "Scan not found"}

            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

            # Check permissions
            permissions = get_user_permissions(user)
            if not permissions.get("view_all_scans", False) and scan.user_id != user.id:
                return {"success": False, "error": "Access denied"}

            # Generate report based on format
            if format == "html":
                return await self._generate_html_report(scan, findings, user)
            elif format == "json":
                return await self._generate_json_report(scan, findings, user)
            elif format == "csv":
                return await self._generate_csv_report(scan, findings, user)
            elif format == "pdf":
                return await self._generate_pdf_report(scan, findings, user)
            else:
                return {"success": False, "error": f"Unsupported format: {format}"}

        except Exception as e:
            return {"success": False, "error": f"Report generation failed: {str(e)}"}

    async def _generate_html_report(self, scan: Scan, findings: List[Finding], user: User) -> Dict[str, Any]:
        """Generate HTML report"""
        try:
            # Prepare template data
            high_count = len([f for f in findings if f.severity == "HIGH"])
            medium_count = len([f for f in findings if f.severity == "MEDIUM"])
            low_count = len([f for f in findings if f.severity == "LOW"])

            template_data = {
                "scan": {"name": scan.name, "scan_type": scan.scan_type, "status": scan.status, "created_at": scan.created_at.isoformat()},
                "findings": [
                    {
                        "query_name": f.query_name,
                        "severity": f.severity,
                        "description": f.description,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "remediation": f.remediation,
                        "ai_explanation": f.ai_explanation,
                        "risk_score": f.risk_score,
                    }
                    for f in findings
                ],
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "generated_at": datetime.utcnow().isoformat(),
            }

            # Render template
            template = self.jinja_env.get_template("report.html")
            html_content = template.render(**template_data)

            # Save report
            filename = f"report_{scan.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
            filepath = self.reports_dir / filename

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)

            return {"success": True, "format": "html", "filename": filename, "filepath": str(filepath), "size": filepath.stat().st_size}

        except Exception as e:
            return {"success": False, "error": f"HTML report generation failed: {str(e)}"}

    async def _generate_json_report(self, scan: Scan, findings: List[Finding], user: User) -> Dict[str, Any]:
        """Generate JSON report"""
        try:
            report_data = {
                "report_metadata": {
                    "generated_at": datetime.utcnow().isoformat(),
                    "generated_by": user.username,
                    "scan_id": scan.id,
                    "scan_name": scan.name,
                    "scan_type": scan.scan_type,
                    "scan_status": scan.status,
                    "total_findings": len(findings),
                },
                "scan_summary": {
                    "created_at": scan.created_at.isoformat(),
                    "updated_at": scan.updated_at.isoformat(),
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "metadata": scan.scan_metadata,
                },
                "findings": [
                    {
                        "id": f.id,
                        "query_name": f.query_name,
                        "severity": f.severity,
                        "description": f.description,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "remediation": f.remediation,
                        "ai_explanation": f.ai_explanation,
                        "risk_score": f.risk_score,
                        "business_impact": f.business_impact,
                        "created_at": f.created_at.isoformat(),
                    }
                    for f in findings
                ],
                "statistics": {
                    "high_severity": len([f for f in findings if f.severity == "HIGH"]),
                    "medium_severity": len([f for f in findings if f.severity == "MEDIUM"]),
                    "low_severity": len([f for f in findings if f.severity == "LOW"]),
                    "average_risk_score": sum(f.risk_score or 0 for f in findings) / len(findings) if findings else 0,
                },
            }

            # Save report
            filename = f"report_{scan.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = self.reports_dir / filename

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            return {"success": True, "format": "json", "filename": filename, "filepath": str(filepath), "size": filepath.stat().st_size}

        except Exception as e:
            return {"success": False, "error": f"JSON report generation failed: {str(e)}"}

    async def _generate_csv_report(self, scan: Scan, findings: List[Finding], user: User) -> Dict[str, Any]:
        """Generate CSV report"""
        try:
            filename = f"report_{scan.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            filepath = self.reports_dir / filename

            with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
                fieldnames = ["id", "query_name", "severity", "description", "file_path", "line_number", "remediation", "risk_score", "created_at"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for finding in findings:
                    writer.writerow(
                        {
                            "id": finding.id,
                            "query_name": finding.query_name,
                            "severity": finding.severity,
                            "description": finding.description,
                            "file_path": finding.file_path or "",
                            "line_number": finding.line_number or "",
                            "remediation": finding.remediation or "",
                            "risk_score": finding.risk_score or 0,
                            "created_at": finding.created_at.isoformat(),
                        }
                    )

            return {"success": True, "format": "csv", "filename": filename, "filepath": str(filepath), "size": filepath.stat().st_size}

        except Exception as e:
            return {"success": False, "error": f"CSV report generation failed: {str(e)}"}

    async def _generate_pdf_report(self, scan: Scan, findings: List[Finding], user: User) -> Dict[str, Any]:
        """Generate PDF report (placeholder for future implementation)"""
        return {"success": False, "error": "PDF generation not yet implemented"}

    async def generate_organization_report(
        self, db: Session, user: User, organization_id: Optional[int] = None, date_range: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Generate organization-wide security report"""
        try:
            # Determine organization
            org_id = organization_id or user.organization_id

            # Get all scans for organization
            scans_query = db.query(Scan).filter(Scan.organization_id == org_id)

            if date_range:
                start_date = datetime.fromisoformat(date_range["start"])
                end_date = datetime.fromisoformat(date_range["end"])
                scans_query = scans_query.filter(Scan.created_at >= start_date, Scan.created_at <= end_date)

            scans = scans_query.all()

            # Get all findings
            scan_ids = [scan.id for scan in scans]
            findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).all()

            # Generate statistics
            total_scans = len(scans)
            total_findings = len(findings)
            high_findings = len([f for f in findings if f.severity == "HIGH"])
            medium_findings = len([f for f in findings if f.severity == "MEDIUM"])
            low_findings = len([f for f in findings if f.severity == "LOW"])

            avg_risk_score = sum(f.risk_score or 0 for f in findings) / total_findings if total_findings > 0 else 0

            # Generate report data
            report_data = {
                "organization_id": org_id,
                "generated_at": datetime.utcnow().isoformat(),
                "generated_by": user.username,
                "date_range": date_range,
                "statistics": {
                    "total_scans": total_scans,
                    "total_findings": total_findings,
                    "high_severity": high_findings,
                    "medium_severity": medium_findings,
                    "low_severity": low_findings,
                    "average_risk_score": round(avg_risk_score, 2),
                },
                "scans": [
                    {
                        "id": scan.id,
                        "name": scan.name,
                        "type": scan.scan_type,
                        "status": scan.status,
                        "created_at": scan.created_at.isoformat(),
                        "findings_count": len(scan.findings),
                    }
                    for scan in scans
                ],
                "top_findings": self._get_top_findings(findings, limit=10),
            }

            # Save report
            filename = f"org_report_{org_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            filepath = self.reports_dir / filename

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            return {"success": True, "filename": filename, "filepath": str(filepath), "size": filepath.stat().st_size, "statistics": report_data["statistics"]}

        except Exception as e:
            return {"success": False, "error": f"Organization report generation failed: {str(e)}"}

    def _get_top_findings(self, findings: List[Finding], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top findings by risk score"""
        # Sort by risk score (descending) and severity
        sorted_findings = sorted(findings, key=lambda f: (f.risk_score or 0, {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(f.severity, 0)), reverse=True)

        return [
            {
                "query_name": f.query_name,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "description": f.description,
                "occurrence_count": len([f2 for f2 in findings if f2.query_name == f.query_name]),
            }
            for f in sorted_findings[:limit]
        ]

    async def export_scan_data(self, db: Session, scan_id: int, user: User, format: str = "json") -> Dict[str, Any]:
        """Export scan data in various formats"""
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return {"success": False, "error": "Scan not found"}

            findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

            # Check permissions
            permissions = get_user_permissions(user)
            if not permissions.get("view_all_scans", False) and scan.user_id != user.id:
                return {"success": False, "error": "Access denied"}

            if format == "json":
                return await self._export_json_data(scan, findings)
            elif format == "csv":
                return await self._export_csv_data(scan, findings)
            else:
                return {"success": False, "error": f"Unsupported export format: {format}"}

        except Exception as e:
            return {"success": False, "error": f"Export failed: {str(e)}"}

    async def _export_json_data(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Export scan data as JSON"""
        export_data = {
            "scan": {
                "id": scan.id,
                "name": scan.name,
                "description": scan.description,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "created_at": scan.created_at.isoformat(),
                "updated_at": scan.updated_at.isoformat(),
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "metadata": scan.scan_metadata,
                "results": scan.results,
            },
            "findings": [
                {
                    "id": f.id,
                    "query_name": f.query_name,
                    "severity": f.severity,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "remediation": f.remediation,
                    "ai_explanation": f.ai_explanation,
                    "risk_score": f.risk_score,
                    "business_impact": f.business_impact,
                    "created_at": f.created_at.isoformat(),
                }
                for f in findings
            ],
        }

        filename = f"export_{scan.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.reports_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        return {"success": True, "format": "json", "filename": filename, "filepath": str(filepath), "size": filepath.stat().st_size}

    async def _export_csv_data(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Export scan data as CSV"""
        filename = f"export_{scan.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = self.reports_dir / filename

        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "scan_id",
                "scan_name",
                "scan_type",
                "status",
                "query_name",
                "severity",
                "description",
                "file_path",
                "line_number",
                "remediation",
                "risk_score",
                "created_at",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        "scan_id": scan.id,
                        "scan_name": scan.name,
                        "scan_type": scan.scan_type,
                        "status": scan.status,
                        "query_name": finding.query_name,
                        "severity": finding.severity,
                        "description": finding.description,
                        "file_path": finding.file_path or "",
                        "line_number": finding.line_number or "",
                        "remediation": finding.remediation or "",
                        "risk_score": finding.risk_score or 0,
                        "created_at": finding.created_at.isoformat(),
                    }
                )

        return {"success": True, "format": "csv", "filename": filename, "filepath": str(filepath), "size": filepath.stat().st_size}
