#!/usr/bin/env python3
"""
Enhanced Reporting Service for DriftBuddy
Generates comprehensive PDF and HTML reports with risk scoring
"""

import os
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from jinja2 import Template
import matplotlib.pyplot as plt
import seaborn as sns
import io
import uuid

@dataclass
class RiskScore:
    """Risk scoring model"""
    severity_weight: float
    business_impact: float
    exploitability: float
    remediation_effort: float
    
    @property
    def total_score(self) -> float:
        """Calculate total risk score (0-100)"""
        return (
            self.severity_weight * 0.4 +
            self.business_impact * 0.3 +
            self.exploitability * 0.2 +
            self.remediation_effort * 0.1
        )

class EnhancedReportingService:
    """Enhanced reporting service with risk scoring and executive dashboards"""
    
    def __init__(self):
        self.reports_dir = "outputs/reports"
        os.makedirs(self.reports_dir, exist_ok=True)
        
    def calculate_risk_score(self, finding: Dict[str, Any]) -> RiskScore:
        """Calculate comprehensive risk score for a finding"""
        severity_map = {
            "HIGH": 1.0,
            "MEDIUM": 0.6,
            "LOW": 0.3,
            "INFO": 0.1
        }
        
        # Base severity weight
        severity_weight = severity_map.get(finding.get("severity", "MEDIUM"), 0.5)
        
        # Business impact assessment
        business_impact = self._assess_business_impact(finding)
        
        # Exploitability assessment
        exploitability = self._assess_exploitability(finding)
        
        # Remediation effort assessment
        remediation_effort = self._assess_remediation_effort(finding)
        
        return RiskScore(
            severity_weight=severity_weight,
            business_impact=business_impact,
            exploitability=exploitability,
            remediation_effort=remediation_effort
        )
    
    def _assess_business_impact(self, finding: Dict[str, Any]) -> float:
        """Assess business impact of a finding (0-1)"""
        impact_keywords = {
            "data": 0.9,
            "customer": 0.8,
            "financial": 0.7,
            "compliance": 0.6,
            "reputation": 0.5
        }
        
        description = finding.get("description", "").lower()
        max_impact = 0.3  # Base impact
        
        for keyword, impact in impact_keywords.items():
            if keyword in description:
                max_impact = max(max_impact, impact)
        
        return max_impact
    
    def _assess_exploitability(self, finding: Dict[str, Any]) -> float:
        """Assess exploitability of a finding (0-1)"""
        exploitability_keywords = {
            "public": 0.9,
            "unrestricted": 0.8,
            "default": 0.7,
            "weak": 0.6,
            "missing": 0.5
        }
        
        description = finding.get("description", "").lower()
        max_exploitability = 0.3  # Base exploitability
        
        for keyword, exploit in exploitability_keywords.items():
            if keyword in description:
                max_exploitability = max(max_exploitability, exploit)
        
        return max_exploitability
    
    def _assess_remediation_effort(self, finding: Dict[str, Any]) -> float:
        """Assess remediation effort (0-1, lower is easier)"""
        effort_keywords = {
            "simple": 0.2,
            "basic": 0.3,
            "standard": 0.5,
            "complex": 0.7,
            "major": 0.9
        }
        
        description = finding.get("description", "").lower()
        effort = 0.5  # Default effort
        
        for keyword, effort_level in effort_keywords.items():
            if keyword in description:
                effort = effort_level
                break
        
        return effort
    
    def generate_executive_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary with key metrics"""
        findings = scan_data.get("findings", [])
        
        # Calculate metrics
        total_findings = len(findings)
        high_severity = len([f for f in findings if f.get("severity") == "HIGH"])
        medium_severity = len([f for f in findings if f.get("severity") == "MEDIUM"])
        low_severity = len([f for f in findings if f.get("severity") == "LOW"])
        
        # Calculate risk scores
        risk_scores = [self.calculate_risk_score(f) for f in findings]
        avg_risk_score = sum(rs.total_score for rs in risk_scores) / len(risk_scores) if risk_scores else 0
        max_risk_score = max(rs.total_score for rs in risk_scores) if risk_scores else 0
        
        # Risk level assessment
        if avg_risk_score >= 70:
            risk_level = "CRITICAL"
        elif avg_risk_score >= 50:
            risk_level = "HIGH"
        elif avg_risk_score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "total_findings": total_findings,
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "low_severity": low_severity,
            "average_risk_score": round(avg_risk_score, 2),
            "max_risk_score": round(max_risk_score, 2),
            "risk_level": risk_level,
            "scan_date": scan_data.get("scan_date", datetime.now().isoformat()),
            "scan_duration": scan_data.get("scan_duration", "Unknown"),
            "files_scanned": scan_data.get("files_scanned", 0)
        }
    
    def generate_charts(self, scan_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate charts for the report"""
        findings = scan_data.get("findings", [])
        
        # Severity distribution chart
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Create severity pie chart
        plt.figure(figsize=(10, 6))
        plt.subplot(1, 2, 1)
        if severity_counts:
            plt.pie(severity_counts.values(), labels=severity_counts.keys(), autopct='%1.1f%%')
            plt.title('Findings by Severity')
        
        # Risk score distribution
        risk_scores = [self.calculate_risk_score(f).total_score for f in findings]
        plt.subplot(1, 2, 2)
        if risk_scores:
            plt.hist(risk_scores, bins=10, alpha=0.7, color='red')
            plt.title('Risk Score Distribution')
            plt.xlabel('Risk Score')
            plt.ylabel('Number of Findings')
        
        # Save chart to base64
        chart_buffer = io.BytesIO()
        plt.tight_layout()
        plt.savefig(chart_buffer, format='png', dpi=300, bbox_inches='tight')
        plt.close()
        
        chart_base64 = base64.b64encode(chart_buffer.getvalue()).decode()
        
        return {
            "severity_chart": chart_base64
        }
    
    def generate_html_report(self, scan_data: Dict[str, Any], report_id: str) -> str:
        """Generate comprehensive HTML report"""
        executive_summary = self.generate_executive_summary(scan_data)
        charts = self.generate_charts(scan_data)
        
        # Enhanced findings with risk scores
        enhanced_findings = []
        for finding in scan_data.get("findings", []):
            risk_score = self.calculate_risk_score(finding)
            enhanced_finding = {
                **finding,
                "risk_score": round(risk_score.total_score, 2),
                "risk_breakdown": {
                    "severity_weight": round(risk_score.severity_weight * 100, 1),
                    "business_impact": round(risk_score.business_impact * 100, 1),
                    "exploitability": round(risk_score.exploitability * 100, 1),
                    "remediation_effort": round(risk_score.remediation_effort * 100, 1)
                }
            }
            enhanced_findings.append(enhanced_finding)
        
        # Sort findings by risk score (highest first)
        enhanced_findings.sort(key=lambda x: x["risk_score"], reverse=True)
        
        # HTML template
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>DriftBuddy Security Report - {{ scan_name }}</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
                .header h1 { margin: 0; font-size: 2.5em; }
                .header p { margin: 10px 0 0 0; opacity: 0.9; }
                .content { padding: 30px; }
                .executive-summary { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
                .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
                .metric-value { font-size: 2em; font-weight: bold; color: #667eea; }
                .metric-label { color: #666; margin-top: 5px; }
                .risk-level { padding: 8px 16px; border-radius: 20px; font-weight: bold; }
                .risk-critical { background: #dc3545; color: white; }
                .risk-high { background: #fd7e14; color: white; }
                .risk-medium { background: #ffc107; color: black; }
                .risk-low { background: #28a745; color: white; }
                .findings-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                .findings-table th, .findings-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                .findings-table th { background: #f8f9fa; font-weight: bold; }
                .severity-high { color: #dc3545; font-weight: bold; }
                .severity-medium { color: #fd7e14; font-weight: bold; }
                .severity-low { color: #28a745; font-weight: bold; }
                .chart-container { text-align: center; margin: 30px 0; }
                .chart-container img { max-width: 100%; height: auto; }
                .recommendations { background: #e3f2fd; padding: 20px; border-radius: 8px; margin-top: 30px; }
                .recommendations h3 { color: #1976d2; margin-top: 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 DriftBuddy Security Report</h1>
                    <p>Infrastructure as Code Security Analysis</p>
                    <p><strong>Scan:</strong> {{ scan_name }} | <strong>Date:</strong> {{ scan_date }}</p>
                </div>
                
                <div class="content">
                    <div class="executive-summary">
                        <h2>📊 Executive Summary</h2>
                        <div class="metrics-grid">
                            <div class="metric-card">
                                <div class="metric-value">{{ executive_summary.total_findings }}</div>
                                <div class="metric-label">Total Findings</div>
                            </div>
                            <div class="metric-card">
                                <div class="metric-value">{{ executive_summary.high_severity }}</div>
                                <div class="metric-label">High Severity</div>
                            </div>
                            <div class="metric-card">
                                <div class="metric-value">{{ executive_summary.average_risk_score }}</div>
                                <div class="metric-label">Avg Risk Score</div>
                            </div>
                            <div class="metric-card">
                                <div class="risk-level risk-{{ executive_summary.risk_level.lower() }}">
                                    {{ executive_summary.risk_level }}
                                </div>
                                <div class="metric-label">Risk Level</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="chart-container">
                        <h3>📈 Security Analysis Charts</h3>
                        <img src="data:image/png;base64,{{ charts.severity_chart }}" alt="Security Analysis Charts">
                    </div>
                    
                    <h2>🔍 Detailed Findings</h2>
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Risk Score</th>
                                <th>Severity</th>
                                <th>Finding</th>
                                <th>File</th>
                                <th>Line</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for finding in enhanced_findings %}
                            <tr>
                                <td><strong>{{ finding.risk_score }}</strong></td>
                                <td><span class="severity-{{ finding.severity.lower() }}">{{ finding.severity }}</span></td>
                                <td><strong>{{ finding.query_name }}</strong></td>
                                <td><code>{{ finding.file_path }}</code></td>
                                <td>{{ finding.line_number or 'N/A' }}</td>
                                <td>{{ finding.description }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    
                    <div class="recommendations">
                        <h3>💡 Recommendations</h3>
                        <ul>
                            {% if executive_summary.high_severity > 0 %}
                            <li><strong>Immediate Action Required:</strong> Address {{ executive_summary.high_severity }} high-severity findings to reduce security risk.</li>
                            {% endif %}
                            {% if executive_summary.average_risk_score > 50 %}
                            <li><strong>Risk Mitigation:</strong> Implement security controls to reduce the average risk score of {{ executive_summary.average_risk_score }}.</li>
                            {% endif %}
                            <li><strong>Continuous Monitoring:</strong> Set up automated scanning in your CI/CD pipeline to catch issues early.</li>
                            <li><strong>Team Training:</strong> Provide security training to development teams on IaC best practices.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            scan_name=scan_data.get("scan_name", "Unknown Scan"),
            scan_date=executive_summary["scan_date"],
            executive_summary=executive_summary,
            charts=charts,
            enhanced_findings=enhanced_findings
        )
        
        # Save HTML report
        report_path = os.path.join(self.reports_dir, f"report_{report_id}.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return report_path
    
    def generate_pdf_report(self, scan_data: Dict[str, Any], report_id: str) -> str:
        """Generate PDF report (placeholder for now)"""
        # For now, we'll generate HTML and suggest PDF conversion
        html_path = self.generate_html_report(scan_data, report_id)
        
        # In a real implementation, you would use a library like weasyprint or reportlab
        # to convert HTML to PDF. For now, we'll return the HTML path with a note.
        pdf_path = html_path.replace('.html', '.pdf')
        
        # Create a simple PDF placeholder
        pdf_content = f"""
        PDF Report for Scan: {scan_data.get('scan_name', 'Unknown')}
        Generated: {datetime.now().isoformat()}
        
        This is a placeholder for PDF generation.
        In production, use weasyprint or reportlab to convert HTML to PDF.
        
        HTML version available at: {html_path}
        """
        
        with open(pdf_path, 'w') as f:
            f.write(pdf_content)
        
        return pdf_path
    
    def generate_report(self, scan_data: Dict[str, Any], format: str = "html") -> Dict[str, Any]:
        """Generate comprehensive report in specified format"""
        report_id = str(uuid.uuid4())[:8]
        
        try:
            if format.lower() == "html":
                report_path = self.generate_html_report(scan_data, report_id)
            elif format.lower() == "pdf":
                report_path = self.generate_pdf_report(scan_data, report_id)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            executive_summary = self.generate_executive_summary(scan_data)
            
            return {
                "success": True,
                "report_id": report_id,
                "report_path": report_path,
                "format": format,
                "executive_summary": executive_summary,
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "report_id": report_id
            } 