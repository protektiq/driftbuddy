"""
Business Risk Assessment Module for DriftBuddy.

Provides comprehensive risk assessment capabilities that consider:
- Impact: How severe the consequences would be
- Likelihood: How probable the vulnerability is to be exploited
- Business Risk Score: Combined assessment for prioritization
"""

from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json
from datetime import datetime

class ImpactLevel(Enum):
    """Impact levels for business risk assessment."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    MINIMAL = "Minimal"

class LikelihoodLevel(Enum):
    """Likelihood levels for business risk assessment."""
    VERY_HIGH = "Very High"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    VERY_LOW = "Very Low"

class BusinessRiskLevel(Enum):
    """Business risk levels based on impact and likelihood."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    MINIMAL = "Minimal"

@dataclass
class RiskAssessment:
    """Risk assessment for a security finding."""
    impact: ImpactLevel
    likelihood: LikelihoodLevel
    business_risk: BusinessRiskLevel
    impact_description: str
    likelihood_description: str
    business_context: str
    remediation_priority: str
    cost_estimate: str
    time_to_fix: str

class RiskMatrix:
    """Risk matrix for determining business risk levels."""
    
    # Risk matrix mapping (Impact, Likelihood) -> Business Risk
    RISK_MATRIX = {
        (ImpactLevel.CRITICAL, LikelihoodLevel.VERY_HIGH): BusinessRiskLevel.CRITICAL,
        (ImpactLevel.CRITICAL, LikelihoodLevel.HIGH): BusinessRiskLevel.CRITICAL,
        (ImpactLevel.CRITICAL, LikelihoodLevel.MEDIUM): BusinessRiskLevel.HIGH,
        (ImpactLevel.CRITICAL, LikelihoodLevel.LOW): BusinessRiskLevel.MEDIUM,
        (ImpactLevel.CRITICAL, LikelihoodLevel.VERY_LOW): BusinessRiskLevel.LOW,
        
        (ImpactLevel.HIGH, LikelihoodLevel.VERY_HIGH): BusinessRiskLevel.CRITICAL,
        (ImpactLevel.HIGH, LikelihoodLevel.HIGH): BusinessRiskLevel.HIGH,
        (ImpactLevel.HIGH, LikelihoodLevel.MEDIUM): BusinessRiskLevel.HIGH,
        (ImpactLevel.HIGH, LikelihoodLevel.LOW): BusinessRiskLevel.MEDIUM,
        (ImpactLevel.HIGH, LikelihoodLevel.VERY_LOW): BusinessRiskLevel.LOW,
        
        (ImpactLevel.MEDIUM, LikelihoodLevel.VERY_HIGH): BusinessRiskLevel.HIGH,
        (ImpactLevel.MEDIUM, LikelihoodLevel.HIGH): BusinessRiskLevel.MEDIUM,
        (ImpactLevel.MEDIUM, LikelihoodLevel.MEDIUM): BusinessRiskLevel.MEDIUM,
        (ImpactLevel.MEDIUM, LikelihoodLevel.LOW): BusinessRiskLevel.LOW,
        (ImpactLevel.MEDIUM, LikelihoodLevel.VERY_LOW): BusinessRiskLevel.MINIMAL,
        
        (ImpactLevel.LOW, LikelihoodLevel.VERY_HIGH): BusinessRiskLevel.MEDIUM,
        (ImpactLevel.LOW, LikelihoodLevel.HIGH): BusinessRiskLevel.LOW,
        (ImpactLevel.LOW, LikelihoodLevel.MEDIUM): BusinessRiskLevel.LOW,
        (ImpactLevel.LOW, LikelihoodLevel.LOW): BusinessRiskLevel.MINIMAL,
        (ImpactLevel.LOW, LikelihoodLevel.VERY_LOW): BusinessRiskLevel.MINIMAL,
        
        (ImpactLevel.MINIMAL, LikelihoodLevel.VERY_HIGH): BusinessRiskLevel.LOW,
        (ImpactLevel.MINIMAL, LikelihoodLevel.HIGH): BusinessRiskLevel.MINIMAL,
        (ImpactLevel.MINIMAL, LikelihoodLevel.MEDIUM): BusinessRiskLevel.MINIMAL,
        (ImpactLevel.MINIMAL, LikelihoodLevel.LOW): BusinessRiskLevel.MINIMAL,
        (ImpactLevel.MINIMAL, LikelihoodLevel.VERY_LOW): BusinessRiskLevel.MINIMAL,
    }
    
    # Business context descriptions
    BUSINESS_CONTEXTS = {
        "aws_s3_bucket_public_access": {
            "impact": "Data breach, regulatory fines, reputation damage",
            "likelihood": "High - public buckets are easily discoverable",
            "context": "Public S3 buckets can lead to data exposure, compliance violations, and significant financial penalties",
            "priority": "Immediate",
            "cost": "$10K-100K+ (fines + incident response)",
            "time": "1-2 hours"
        },
        "aws_iam_user_password_enabled": {
            "impact": "Account compromise, unauthorized access",
            "likelihood": "Medium - depends on password strength and rotation",
            "context": "IAM users with password access increase attack surface and risk of credential compromise",
            "priority": "High",
            "cost": "$5K-50K (incident response + remediation)",
            "time": "4-8 hours"
        },
        "aws_security_group_open_ports": {
            "impact": "Network compromise, lateral movement",
            "likelihood": "High - open ports are easily scanned and exploited",
            "context": "Overly permissive security groups allow unauthorized network access and potential data exfiltration",
            "priority": "High",
            "cost": "$20K-200K (incident response + data recovery)",
            "time": "2-4 hours"
        },
        "aws_ec2_instance_public_ip": {
            "impact": "Direct attack surface, data breach",
            "likelihood": "High - public IPs are constantly scanned",
            "context": "EC2 instances with public IPs are directly accessible from the internet, increasing attack risk",
            "priority": "High",
            "cost": "$15K-150K (incident response + system recovery)",
            "time": "2-6 hours"
        },
        "aws_rds_instance_publicly_accessible": {
            "impact": "Database compromise, data breach, regulatory fines",
            "likelihood": "High - databases are prime targets",
            "context": "Publicly accessible databases are high-value targets for attackers seeking sensitive data",
            "priority": "Critical",
            "cost": "$50K-500K+ (fines + data breach response)",
            "time": "1-4 hours"
        },
        "aws_lambda_function_public": {
            "impact": "Code execution, data access, service disruption",
            "likelihood": "Medium - requires specific knowledge of function",
            "context": "Public Lambda functions can be invoked by unauthorized users, potentially leading to data exposure",
            "priority": "Medium",
            "cost": "$5K-25K (incident response + code review)",
            "time": "4-8 hours"
        },
        "kubernetes_pod_security_context": {
            "impact": "Container escape, host compromise",
            "likelihood": "Medium - requires container escape techniques",
            "context": "Pods without proper security context can lead to container escape and host system compromise",
            "priority": "High",
            "cost": "$25K-100K (incident response + system recovery)",
            "time": "4-12 hours"
        },
        "kubernetes_secret_plaintext": {
            "impact": "Credential exposure, data breach",
            "likelihood": "High - secrets are easily accessible",
            "context": "Secrets stored in plaintext can be easily accessed by unauthorized users or applications",
            "priority": "Critical",
            "cost": "$30K-300K (credential rotation + incident response)",
            "time": "2-8 hours"
        },
        "docker_container_root_user": {
            "impact": "Container escape, host compromise",
            "likelihood": "Medium - requires container escape techniques",
            "context": "Containers running as root have elevated privileges that can lead to host system compromise",
            "priority": "High",
            "cost": "$20K-80K (incident response + system recovery)",
            "time": "4-8 hours"
        },
        "terraform_state_file_public": {
            "impact": "Infrastructure compromise, credential exposure",
            "likelihood": "High - state files contain sensitive information",
            "context": "Public Terraform state files contain infrastructure secrets and can lead to complete infrastructure compromise",
            "priority": "Critical",
            "cost": "$50K-500K+ (infrastructure rebuild + incident response)",
            "time": "8-24 hours"
        }
    }
    
    @classmethod
    def assess_risk(cls, query_name: str, severity: str, description: str) -> RiskAssessment:
        """
        Assess business risk for a security finding.
        
        Args:
            query_name: Name of the security query
            severity: Technical severity level
            description: Security finding description
            
        Returns:
            RiskAssessment object with business risk analysis
        """
        # Determine impact based on severity and query type
        impact = cls._determine_impact(query_name, severity, description)
        
        # Determine likelihood based on query type and context
        likelihood = cls._determine_likelihood(query_name, severity, description)
        
        # Calculate business risk from matrix
        business_risk = cls.RISK_MATRIX.get((impact, likelihood), BusinessRiskLevel.MEDIUM)
        
        # Get business context information
        context_info = cls.BUSINESS_CONTEXTS.get(query_name.lower().replace(" ", "_"), {
            "impact": "Potential security breach and data compromise",
            "likelihood": "Medium - depends on specific circumstances",
            "context": "This vulnerability could lead to security incidents and business disruption",
            "priority": "Medium",
            "cost": "$5K-50K (estimated incident response)",
            "time": "4-8 hours"
        })
        
        return RiskAssessment(
            impact=impact,
            likelihood=likelihood,
            business_risk=business_risk,
            impact_description=context_info["impact"],
            likelihood_description=context_info["likelihood"],
            business_context=context_info["context"],
            remediation_priority=context_info["priority"],
            cost_estimate=context_info["cost"],
            time_to_fix=context_info["time"]
        )
    
    @classmethod
    def _determine_impact(cls, query_name: str, severity: str, description: str) -> ImpactLevel:
        """Determine impact level based on query type and severity."""
        query_lower = query_name.lower()
        
        # Critical impact scenarios
        if any(keyword in query_lower for keyword in [
            "public", "exposed", "unencrypted", "plaintext", "secret", "credential"
        ]):
            return ImpactLevel.CRITICAL
        
        # High impact scenarios
        if any(keyword in query_lower for keyword in [
            "root", "admin", "privilege", "permission", "access"
        ]):
            return ImpactLevel.HIGH
        
        # Medium impact scenarios
        if any(keyword in query_lower for keyword in [
            "logging", "monitoring", "audit", "compliance"
        ]):
            return ImpactLevel.MEDIUM
        
        # Default based on severity
        severity_map = {
            "CRITICAL": ImpactLevel.CRITICAL,
            "HIGH": ImpactLevel.HIGH,
            "MEDIUM": ImpactLevel.MEDIUM,
            "LOW": ImpactLevel.LOW,
            "INFO": ImpactLevel.MINIMAL
        }
        
        return severity_map.get(severity.upper(), ImpactLevel.MEDIUM)
    
    @classmethod
    def _determine_likelihood(cls, query_name: str, severity: str, description: str) -> LikelihoodLevel:
        """Determine likelihood level based on query type and context."""
        query_lower = query_name.lower()
        
        # Very high likelihood scenarios
        if any(keyword in query_lower for keyword in [
            "public", "exposed", "internet", "0.0.0.0"
        ]):
            return LikelihoodLevel.VERY_HIGH
        
        # High likelihood scenarios
        if any(keyword in query_lower for keyword in [
            "default", "weak", "common", "known"
        ]):
            return LikelihoodLevel.HIGH
        
        # Medium likelihood scenarios
        if any(keyword in query_lower for keyword in [
            "privilege", "permission", "access"
        ]):
            return LikelihoodLevel.MEDIUM
        
        # Low likelihood scenarios
        if any(keyword in query_lower for keyword in [
            "logging", "monitoring", "audit"
        ]):
            return LikelihoodLevel.LOW
        
        # Default based on severity
        severity_map = {
            "CRITICAL": LikelihoodLevel.HIGH,
            "HIGH": LikelihoodLevel.HIGH,
            "MEDIUM": LikelihoodLevel.MEDIUM,
            "LOW": LikelihoodLevel.LOW,
            "INFO": LikelihoodLevel.VERY_LOW
        }
        
        return severity_map.get(severity.upper(), LikelihoodLevel.MEDIUM)

def generate_risk_report(findings: List[Dict]) -> Dict[str, Any]:
    """
    Generate a comprehensive risk report with business context.
    
    Args:
        findings: List of security findings
        
    Returns:
        Dictionary containing risk analysis and recommendations
    """
    risk_assessments = []
    risk_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "minimal": 0
    }
    
    total_estimated_cost = 0
    total_estimated_time = 0
    
    for finding in findings:
        query_name = finding.get("query_name", "Unknown")
        severity = finding.get("severity", "MEDIUM")
        description = finding.get("description", "")
        
        # Assess business risk
        risk_assessment = RiskMatrix.assess_risk(query_name, severity, description)
        
        # Add risk assessment to finding
        finding["risk_assessment"] = {
            "impact": risk_assessment.impact.value,
            "likelihood": risk_assessment.likelihood.value,
            "business_risk": risk_assessment.business_risk.value,
            "impact_description": risk_assessment.impact_description,
            "likelihood_description": risk_assessment.likelihood_description,
            "business_context": risk_assessment.business_context,
            "remediation_priority": risk_assessment.remediation_priority,
            "cost_estimate": risk_assessment.cost_estimate,
            "time_to_fix": risk_assessment.time_to_fix
        }
        
        # Update summary
        risk_level = risk_assessment.business_risk.value.lower()
        risk_summary[risk_level] += 1
        
        # Estimate costs (simplified calculation)
        cost_str = risk_assessment.cost_estimate
        if "$" in cost_str:
            try:
                cost_range = cost_str.replace("$", "").replace("K", "000").replace("+", "")
                if "-" in cost_range:
                    min_cost, max_cost = cost_range.split("-")
                    avg_cost = (int(min_cost) + int(max_cost)) / 2
                else:
                    avg_cost = int(cost_range)
                total_estimated_cost += avg_cost
            except:
                pass
        
        risk_assessments.append(risk_assessment)
    
    return {
        "risk_assessments": risk_assessments,
        "risk_summary": risk_summary,
        "total_estimated_cost": f"${total_estimated_cost:,.0f}",
        "total_findings": len(findings),
        "critical_findings": risk_summary["critical"],
        "high_findings": risk_summary["high"],
        "medium_findings": risk_summary["medium"],
        "low_findings": risk_summary["low"],
        "minimal_findings": risk_summary["minimal"]
    } 