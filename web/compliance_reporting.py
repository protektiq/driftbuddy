"""
Compliance Reporting for DriftBuddy Web Interface - Phase 3
Provides SOC2, PCI, HIPAA, and other compliance framework reporting
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import jinja2
from sqlalchemy.orm import Session

from .auth import get_user_permissions
from .models import Finding, Organization, Scan, User


class ComplianceFramework:
    """Base class for compliance frameworks"""

    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self.controls = {}
        self.mappings = {}

    def map_finding_to_control(self, finding: Dict[str, Any]) -> List[str]:
        """Map a finding to compliance controls"""
        raise NotImplementedError

    def generate_control_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate compliance control report"""
        raise NotImplementedError


class SOC2Framework(ComplianceFramework):
    """SOC2 compliance framework"""

    def __init__(self):
        super().__init__("SOC2", "2017")
        self.trust_services_criteria = {"CC": "Common Criteria", "A": "Availability", "C": "Confidentiality", "P": "Processing Integrity", "PII": "Privacy"}
        self._load_soc2_controls()

    def _load_soc2_controls(self):
        """Load SOC2 controls and mappings"""
        self.controls = {
            "CC6.1": {
                "title": "Logical and Physical Access Controls",
                "description": "The entity implements logical and physical access controls to protect against unauthorized access",
                "category": "CC",
                "mappings": ["unrestricted_access", "weak_authentication", "public_resources"],
            },
            "CC6.2": {
                "title": "Prior Authorization for Access",
                "description": "The entity authorizes, modifies, or removes access to data, software, functions, and other IT resources based on roles, responsibilities, or other criteria as defined by the entity",
                "category": "CC",
                "mappings": ["missing_authorization", "excessive_permissions"],
            },
            "CC6.3": {
                "title": "Access Credentials",
                "description": "The entity protects access credentials through the use of appropriate controls",
                "category": "CC",
                "mappings": ["weak_passwords", "hardcoded_credentials", "unencrypted_secrets"],
            },
            "CC6.4": {
                "title": "Access Removal",
                "description": "The entity removes access to data, software, functions, and other IT resources when access is no longer authorized",
                "category": "CC",
                "mappings": ["orphaned_accounts", "stale_permissions"],
            },
            "CC7.1": {
                "title": "System Operation Monitoring",
                "description": "The entity monitors system components and the operation of technology to identify conditions that may prevent the achievement of the entity's security objectives",
                "category": "CC",
                "mappings": ["missing_monitoring", "inadequate_logging"],
            },
            "CC7.2": {
                "title": "Security Incident Procedures",
                "description": "The entity responds to security incidents by executing a defined incident response program",
                "category": "CC",
                "mappings": ["incident_response", "security_alerts"],
            },
            "CC8.1": {
                "title": "Risk Assessment",
                "description": "The entity performs risk assessments to identify risks to the achievement of its objectives",
                "category": "CC",
                "mappings": ["risk_assessment", "vulnerability_management"],
            },
            "A1.1": {
                "title": "Availability Monitoring",
                "description": "The entity monitors the availability of systems and data to meet its availability commitments",
                "category": "A",
                "mappings": ["availability_monitoring", "backup_verification"],
            },
            "C1.1": {
                "title": "Confidentiality of Information",
                "description": "The entity maintains the confidentiality of information during its collection, use, retention, and disposal",
                "category": "C",
                "mappings": ["data_encryption", "secure_transmission", "access_controls"],
            },
        }

    def map_finding_to_control(self, finding: Dict[str, Any]) -> List[str]:
        """Map a finding to SOC2 controls"""
        mapped_controls = []
        query_name = finding.get("query_name", "").lower()
        description = finding.get("description", "").lower()

        for control_id, control in self.controls.items():
            for mapping in control.get("mappings", []):
                if mapping in query_name or mapping in description:
                    mapped_controls.append(control_id)
                    break

        return mapped_controls

    def generate_control_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate SOC2 compliance report"""
        control_status = {}
        category_status = {}

        # Initialize control status
        for control_id in self.controls:
            control_status[control_id] = {"status": "compliant", "findings": [], "risk_level": "low"}

        # Map findings to controls
        for finding in findings:
            mapped_controls = self.map_finding_to_control(finding)

            for control_id in mapped_controls:
                if control_id in control_status:
                    control_status[control_id]["findings"].append(finding)
                    control_status[control_id]["status"] = "non_compliant"

                    # Determine risk level based on finding severity
                    severity = finding.get("severity", "LOW")
                    if severity == "HIGH":
                        control_status[control_id]["risk_level"] = "high"
                    elif severity == "MEDIUM" and control_status[control_id]["risk_level"] != "high":
                        control_status[control_id]["risk_level"] = "medium"

        # Calculate category status
        for control_id, status in control_status.items():
            category = self.controls[control_id]["category"]
            if category not in category_status:
                category_status[category] = {"total_controls": 0, "compliant_controls": 0, "non_compliant_controls": 0}

            category_status[category]["total_controls"] += 1
            if status["status"] == "compliant":
                category_status[category]["compliant_controls"] += 1
            else:
                category_status[category]["non_compliant_controls"] += 1

        return {
            "framework": "SOC2",
            "version": self.version,
            "report_date": datetime.utcnow().isoformat(),
            "control_status": control_status,
            "category_status": category_status,
            "trust_services_criteria": self.trust_services_criteria,
        }


class PCIFramework(ComplianceFramework):
    """PCI DSS compliance framework"""

    def __init__(self):
        super().__init__("PCI DSS", "4.0")
        self._load_pci_controls()

    def _load_pci_controls(self):
        """Load PCI DSS controls and mappings"""
        self.controls = {
            "PCI_1.1": {
                "title": "Network Security Controls",
                "description": "Implement network security controls to protect cardholder data",
                "category": "Network Security",
                "mappings": ["network_security", "firewall_configuration", "network_segmentation"],
            },
            "PCI_1.2": {
                "title": "Network Security Configuration",
                "description": "Configure network security devices and systems",
                "category": "Network Security",
                "mappings": ["security_configuration", "network_monitoring"],
            },
            "PCI_2.1": {
                "title": "Vendor Default Security",
                "description": "Change vendor defaults and remove unnecessary accounts",
                "category": "Access Control",
                "mappings": ["default_passwords", "vendor_defaults", "unnecessary_accounts"],
            },
            "PCI_2.2": {
                "title": "Security Configuration",
                "description": "Implement security configuration for all system components",
                "category": "Access Control",
                "mappings": ["security_configuration", "hardening", "secure_settings"],
            },
            "PCI_3.1": {
                "title": "Data Protection",
                "description": "Protect stored cardholder data",
                "category": "Data Protection",
                "mappings": ["data_encryption", "secure_storage", "data_protection"],
            },
            "PCI_3.2": {
                "title": "Encryption Keys",
                "description": "Protect encryption keys used for cardholder data",
                "category": "Data Protection",
                "mappings": ["key_management", "encryption_keys", "key_rotation"],
            },
            "PCI_4.1": {
                "title": "Transmission Security",
                "description": "Encrypt transmission of cardholder data across open networks",
                "category": "Data Protection",
                "mappings": ["secure_transmission", "ssl_tls", "encrypted_communication"],
            },
            "PCI_5.1": {
                "title": "Malware Protection",
                "description": "Deploy anti-malware software on all systems",
                "category": "Vulnerability Management",
                "mappings": ["malware_protection", "antivirus", "security_software"],
            },
            "PCI_6.1": {
                "title": "Security Vulnerabilities",
                "description": "Identify and address security vulnerabilities",
                "category": "Vulnerability Management",
                "mappings": ["vulnerability_management", "security_patches", "updates"],
            },
            "PCI_7.1": {
                "title": "Access Control",
                "description": "Implement access control based on business need",
                "category": "Access Control",
                "mappings": ["access_control", "least_privilege", "business_need"],
            },
            "PCI_8.1": {
                "title": "User Identification",
                "description": "Assign unique IDs to each user",
                "category": "Access Control",
                "mappings": ["user_identification", "unique_ids", "user_management"],
            },
            "PCI_9.1": {
                "title": "Physical Access",
                "description": "Control physical access to cardholder data",
                "category": "Physical Security",
                "mappings": ["physical_security", "access_control", "environmental_controls"],
            },
            "PCI_10.1": {
                "title": "Audit Logs",
                "description": "Implement audit logs for all system components",
                "category": "Monitoring",
                "mappings": ["audit_logs", "logging", "monitoring"],
            },
            "PCI_11.1": {
                "title": "Security Testing",
                "description": "Implement security testing procedures",
                "category": "Security Testing",
                "mappings": ["security_testing", "penetration_testing", "vulnerability_assessment"],
            },
            "PCI_12.1": {
                "title": "Security Policy",
                "description": "Establish and maintain security policies",
                "category": "Security Policy",
                "mappings": ["security_policy", "documentation", "procedures"],
            },
        }

    def map_finding_to_control(self, finding: Dict[str, Any]) -> List[str]:
        """Map a finding to PCI DSS controls"""
        mapped_controls = []
        query_name = finding.get("query_name", "").lower()
        description = finding.get("description", "").lower()

        for control_id, control in self.controls.items():
            for mapping in control.get("mappings", []):
                if mapping in query_name or mapping in description:
                    mapped_controls.append(control_id)
                    break

        return mapped_controls

    def generate_control_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate PCI DSS compliance report"""
        control_status = {}
        category_status = {}

        # Initialize control status
        for control_id in self.controls:
            control_status[control_id] = {"status": "compliant", "findings": [], "risk_level": "low"}

        # Map findings to controls
        for finding in findings:
            mapped_controls = self.map_finding_to_control(finding)

            for control_id in mapped_controls:
                if control_id in control_status:
                    control_status[control_id]["findings"].append(finding)
                    control_status[control_id]["status"] = "non_compliant"

                    # Determine risk level based on finding severity
                    severity = finding.get("severity", "LOW")
                    if severity == "HIGH":
                        control_status[control_id]["risk_level"] = "high"
                    elif severity == "MEDIUM" and control_status[control_id]["risk_level"] != "high":
                        control_status[control_id]["risk_level"] = "medium"

        # Calculate category status
        for control_id, status in control_status.items():
            category = self.controls[control_id]["category"]
            if category not in category_status:
                category_status[category] = {"total_controls": 0, "compliant_controls": 0, "non_compliant_controls": 0}

            category_status[category]["total_controls"] += 1
            if status["status"] == "compliant":
                category_status[category]["compliant_controls"] += 1
            else:
                category_status[category]["non_compliant_controls"] += 1

        return {
            "framework": "PCI DSS",
            "version": self.version,
            "report_date": datetime.utcnow().isoformat(),
            "control_status": control_status,
            "category_status": category_status,
        }


class HIPAAFramework(ComplianceFramework):
    """HIPAA compliance framework"""

    def __init__(self):
        super().__init__("HIPAA", "2023")
        self._load_hipaa_controls()

    def _load_hipaa_controls(self):
        """Load HIPAA controls and mappings"""
        self.controls = {
            "HIPAA_164.308(a)(1)": {
                "title": "Security Management Process",
                "description": "Implement policies and procedures to prevent, detect, contain, and correct security violations",
                "category": "Administrative Safeguards",
                "mappings": ["security_policies", "risk_management", "security_procedures"],
            },
            "HIPAA_164.308(a)(2)": {
                "title": "Assigned Security Responsibility",
                "description": "Identify the security official responsible for developing and implementing security policies",
                "category": "Administrative Safeguards",
                "mappings": ["security_officer", "responsibility_assignment"],
            },
            "HIPAA_164.308(a)(3)": {
                "title": "Workforce Security",
                "description": "Implement policies and procedures to ensure all members of the workforce have appropriate access",
                "category": "Administrative Safeguards",
                "mappings": ["workforce_security", "access_management", "user_authorization"],
            },
            "HIPAA_164.308(a)(4)": {
                "title": "Information Access Management",
                "description": "Implement policies and procedures for authorizing access to electronic protected health information",
                "category": "Administrative Safeguards",
                "mappings": ["access_management", "authorization", "access_control"],
            },
            "HIPAA_164.308(a)(5)": {
                "title": "Security Awareness and Training",
                "description": "Implement a security awareness and training program for all workforce members",
                "category": "Administrative Safeguards",
                "mappings": ["security_training", "awareness_program", "education"],
            },
            "HIPAA_164.312(a)(1)": {
                "title": "Access Control",
                "description": "Implement technical policies and procedures for electronic information systems",
                "category": "Technical Safeguards",
                "mappings": ["access_control", "authentication", "authorization"],
            },
            "HIPAA_164.312(a)(2)": {
                "title": "Audit Controls",
                "description": "Implement hardware, software, and/or procedural mechanisms to record and examine access",
                "category": "Technical Safeguards",
                "mappings": ["audit_controls", "logging", "monitoring"],
            },
            "HIPAA_164.312(a)(3)": {
                "title": "Integrity",
                "description": "Implement policies and procedures to protect electronic protected health information from improper alteration or destruction",
                "category": "Technical Safeguards",
                "mappings": ["data_integrity", "integrity_controls", "data_protection"],
            },
            "HIPAA_164.312(a)(4)": {
                "title": "Person or Entity Authentication",
                "description": "Implement procedures to verify that a person or entity seeking access is the one claimed",
                "category": "Technical Safeguards",
                "mappings": ["authentication", "identity_verification", "user_authentication"],
            },
            "HIPAA_164.312(a)(5)": {
                "title": "Transmission Security",
                "description": "Implement technical security measures to guard against unauthorized access to electronic protected health information",
                "category": "Technical Safeguards",
                "mappings": ["transmission_security", "encryption", "secure_communication"],
            },
        }

    def map_finding_to_control(self, finding: Dict[str, Any]) -> List[str]:
        """Map a finding to HIPAA controls"""
        mapped_controls = []
        query_name = finding.get("query_name", "").lower()
        description = finding.get("description", "").lower()

        for control_id, control in self.controls.items():
            for mapping in control.get("mappings", []):
                if mapping in query_name or mapping in description:
                    mapped_controls.append(control_id)
                    break

        return mapped_controls

    def generate_control_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate HIPAA compliance report"""
        control_status = {}
        category_status = {}

        # Initialize control status
        for control_id in self.controls:
            control_status[control_id] = {"status": "compliant", "findings": [], "risk_level": "low"}

        # Map findings to controls
        for finding in findings:
            mapped_controls = self.map_finding_to_control(finding)

            for control_id in mapped_controls:
                if control_id in control_status:
                    control_status[control_id]["findings"].append(finding)
                    control_status[control_id]["status"] = "non_compliant"

                    # Determine risk level based on finding severity
                    severity = finding.get("severity", "LOW")
                    if severity == "HIGH":
                        control_status[control_id]["risk_level"] = "high"
                    elif severity == "MEDIUM" and control_status[control_id]["risk_level"] != "high":
                        control_status[control_id]["risk_level"] = "medium"

        # Calculate category status
        for control_id, status in control_status.items():
            category = self.controls[control_id]["category"]
            if category not in category_status:
                category_status[category] = {"total_controls": 0, "compliant_controls": 0, "non_compliant_controls": 0}

            category_status[category]["total_controls"] += 1
            if status["status"] == "compliant":
                category_status[category]["compliant_controls"] += 1
            else:
                category_status[category]["non_compliant_controls"] += 1

        return {
            "framework": "HIPAA",
            "version": self.version,
            "report_date": datetime.utcnow().isoformat(),
            "control_status": control_status,
            "category_status": category_status,
        }


class ComplianceReportingService:
    """Compliance reporting service for multiple frameworks"""

    def __init__(self):
        self.frameworks = {"soc2": SOC2Framework(), "pci": PCIFramework(), "hipaa": HIPAAFramework()}
        self.templates_dir = Path("templates/compliance")
        self.templates_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Jinja2 environment
        self.jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(self.templates_dir)), autoescape=True)

        self._create_compliance_templates()

    def _create_compliance_templates(self):
        """Create compliance report templates"""
        soc2_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC2 Compliance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; }
        .control { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .compliant { border-left: 5px solid #28a745; }
        .non_compliant { border-left: 5px solid #dc3545; }
        .status { font-weight: bold; padding: 5px 10px; border-radius: 3px; }
        .status.compliant { background: #28a745; color: white; }
        .status.non_compliant { background: #dc3545; color: white; }
        .risk { font-size: 0.9em; color: #666; }
        .category { margin: 20px 0; }
        .summary { background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 SOC2 Compliance Report</h1>
        <p>Generated: {{ report_date }}</p>
        <p>Framework: SOC2 v{{ version }}</p>
    </div>
    
    <div class="summary">
        <h3>📊 Executive Summary</h3>
        {% for category, stats in category_status.items() %}
        <div>
            <strong>{{ category }}:</strong> {{ stats.compliant_controls }}/{{ stats.total_controls }} compliant
            ({{ "%.1f"|format(stats.compliant_controls / stats.total_controls * 100) }}%)
        </div>
        {% endfor %}
    </div>
    
    <div class="controls">
        <h3>🔍 Control Assessment</h3>
        {% for control_id, status in control_status.items() %}
        <div class="control {{ status.status }}">
            <h4>{{ control_id }} - {{ controls[control_id].title }}</h4>
            <span class="status {{ status.status }}">{{ status.status|title }}</span>
            <span class="risk">Risk Level: {{ status.risk_level|title }}</span>
            <p>{{ controls[control_id].description }}</p>
            {% if status.findings %}
            <div>
                <strong>Related Findings:</strong>
                <ul>
                {% for finding in status.findings %}
                <li>{{ finding.description }} ({{ finding.severity }})</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """

        with open(self.templates_dir / "soc2_report.html", "w") as f:
            f.write(soc2_template)

    async def generate_compliance_report(self, db: Session, framework: str, scan_ids: List[int], user: User) -> Dict[str, Any]:
        """Generate compliance report for specified framework"""
        try:
            # Validate framework
            if framework not in self.frameworks:
                return {"success": False, "error": f"Framework {framework} not supported"}

            # Get findings from scans
            findings = []
            for scan_id in scan_ids:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan and (user.role == "admin" or scan.user_id == user.id):
                    scan_findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
                    findings.extend(
                        [
                            {
                                "id": f.id,
                                "query_name": f.query_name,
                                "severity": f.severity,
                                "description": f.description,
                                "risk_score": f.risk_score,
                                "remediation": f.remediation,
                            }
                            for f in scan_findings
                        ]
                    )

            if not findings:
                return {"success": False, "error": "No findings found for specified scans"}

            # Generate compliance report
            framework_obj = self.frameworks[framework]
            report_data = framework_obj.generate_control_report(findings)

            # Add framework-specific data
            if framework == "soc2":
                report_data["controls"] = framework_obj.controls
                report_data["trust_services_criteria"] = framework_obj.trust_services_criteria

            return {"success": True, "framework": framework, "report_data": report_data, "findings_count": len(findings)}

        except Exception as e:
            return {"success": False, "error": f"Compliance report generation failed: {str(e)}"}

    async def generate_html_report(self, framework: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate HTML compliance report"""
        try:
            template_name = f"{framework}_report.html"
            template = self.jinja_env.get_template(template_name)

            html_content = template.render(**report_data)

            # Save report
            filename = f"compliance_{framework}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html"
            filepath = Path("reports") / filename
            filepath.parent.mkdir(exist_ok=True)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)

            return {"success": True, "filename": filename, "filepath": str(filepath), "size": filepath.stat().st_size}

        except Exception as e:
            return {"success": False, "error": f"HTML report generation failed: {str(e)}"}

    async def get_supported_frameworks(self) -> Dict[str, Dict[str, Any]]:
        """Get list of supported compliance frameworks"""
        return {
            framework_name: {"name": framework_obj.name, "version": framework_obj.version, "controls_count": len(framework_obj.controls)}
            for framework_name, framework_obj in self.frameworks.items()
        }

    async def get_framework_controls(self, framework: str) -> Dict[str, Any]:
        """Get controls for a specific framework"""
        if framework not in self.frameworks:
            return {"success": False, "error": f"Framework {framework} not supported"}

        framework_obj = self.frameworks[framework]
        return {"success": True, "framework": framework_obj.name, "version": framework_obj.version, "controls": framework_obj.controls}

    async def map_finding_to_framework(self, framework: str, finding: Dict[str, Any]) -> List[str]:
        """Map a finding to framework controls"""
        if framework not in self.frameworks:
            return []

        framework_obj = self.frameworks[framework]
        return framework_obj.map_finding_to_control(finding)
