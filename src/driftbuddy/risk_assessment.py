"""
Business Risk Assessment Module for DriftBuddy.

Provides comprehensive risk assessment capabilities that consider:
- Impact: How severe the consequences would be (1-5 scale)
- Likelihood: How probable the vulnerability is to be exploited (1-5 scale)
- Business Risk Score: Impact × Likelihood (1-25 scale)
- Business Risk Level: Categorized risk level based on score
"""

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List


class ImpactLevel(Enum):
    """Impact levels for business risk assessment (1-5 scale)."""

    CATASTROPHIC = (5, "Catastrophic")
    MAJOR = (4, "Major")
    MODERATE = (3, "Moderate")
    MINOR = (2, "Minor")
    INSIGNIFICANT = (1, "Insignificant")


class LikelihoodLevel(Enum):
    """Likelihood levels for business risk assessment (1-5 scale)."""

    ALMOST_CERTAIN = (5, "Almost Certain")
    LIKELY = (4, "Likely")
    POSSIBLE = (3, "Possible")
    UNLIKELY = (2, "Unlikely")
    RARE = (1, "Rare")


class BusinessRiskLevel(Enum):
    """Business risk levels based on Impact × Likelihood score."""

    CRITICAL = (20, "Critical")  # Score 20-25
    HIGH = (15, "High")  # Score 15-19
    MEDIUM = (10, "Medium")  # Score 10-14
    LOW = (5, "Low")  # Score 5-9
    MINIMAL = (1, "Minimal")  # Score 1-4


@dataclass
class RiskAssessment:
    """Risk assessment for a security finding."""

    impact: ImpactLevel
    likelihood: LikelihoodLevel
    business_risk_score: int  # Impact × Likelihood
    business_risk: BusinessRiskLevel
    impact_description: str
    likelihood_description: str
    business_context: str
    remediation_priority: str
    cost_estimate: str
    time_to_fix: str


class RiskMatrix:
    """Risk matrix for determining business risk levels using Impact × Likelihood calculation."""

    @classmethod
    def calculate_business_risk_score(cls, impact: ImpactLevel, likelihood: LikelihoodLevel) -> int:
        """
        Calculate business risk score using Impact × Likelihood formula.

        Args:
            impact: Impact level (1-5 scale)
            likelihood: Likelihood level (1-5 scale)

        Returns:
            Business risk score (1-25 scale)
        """
        return impact.value[0] * likelihood.value[0]

    @classmethod
    def determine_business_risk_level(cls, score: int) -> BusinessRiskLevel:
        """
        Determine business risk level based on calculated score.

        Args:
            score: Business risk score (1-25)

        Returns:
            Business risk level
        """
        if score >= 20:
            return BusinessRiskLevel.CRITICAL
        elif score >= 15:
            return BusinessRiskLevel.HIGH
        elif score >= 10:
            return BusinessRiskLevel.MEDIUM
        elif score >= 5:
            return BusinessRiskLevel.LOW
        else:
            return BusinessRiskLevel.MINIMAL

    # Business context descriptions with updated risk calculations
    BUSINESS_CONTEXTS = {
        # S3 Bucket Security Issues
        "s3_bucket_acl_allows_read_or_write_to_all_users": {
            "impact": "Data breach, regulatory fines, reputation damage",
            "likelihood": "High - public buckets are easily discoverable",
            "context": "Public S3 buckets can lead to data exposure, compliance violations, and significant financial penalties",
            "priority": "Immediate",
            "cost": "$10K-100K+ (fines + incident response)",
            "time": "1-2 hours",
            "impact_score": 5,  # Catastrophic
            "likelihood_score": 5,  # Almost Certain
        },
        "s3_bucket_logging_disabled": {
            "impact": "Audit trail loss, compliance violations",
            "likelihood": "Medium - logging is often overlooked",
            "context": "Missing S3 bucket logging makes it difficult to detect unauthorized access and comply with audit requirements",
            "priority": "Medium",
            "cost": "$5K-25K (compliance fines + audit costs)",
            "time": "2-4 hours",
            "impact_score": 3,  # Moderate
            "likelihood_score": 2,  # Unlikely
        },
        "s3_bucket_without_versioning": {
            "impact": "Data loss, ransomware recovery issues",
            "likelihood": "Low - requires specific attack scenarios",
            "context": "S3 buckets without versioning are vulnerable to data loss and ransomware attacks",
            "priority": "Low",
            "cost": "$1K-10K (data recovery + business continuity)",
            "time": "4-8 hours",
            "impact_score": 2,  # Minor
            "likelihood_score": 2,  # Unlikely
        },
        "aws_s3_bucket_public_access": {
            "impact": "Data breach, regulatory fines, reputation damage",
            "likelihood": "High - public buckets are easily discoverable",
            "context": "Public S3 buckets can lead to data exposure, compliance violations, and significant financial penalties",
            "priority": "Immediate",
            "cost": "$10K-100K+ (fines + incident response)",
            "time": "1-2 hours",
            "impact_score": 5,  # Catastrophic
            "likelihood_score": 5,  # Almost Certain
        },
        "aws_iam_user_password_enabled": {
            "impact": "Account compromise, unauthorized access",
            "likelihood": "Medium - depends on password strength and rotation",
            "context": "IAM users with password access increase attack surface and risk of credential compromise",
            "priority": "High",
            "cost": "$5K-50K (incident response + remediation)",
            "time": "4-8 hours",
            "impact_score": 4,  # Major
            "likelihood_score": 3,  # Possible
        },
        "aws_security_group_open_ports": {
            "impact": "Network compromise, lateral movement",
            "likelihood": "High - open ports are easily scanned and exploited",
            "context": "Overly permissive security groups allow unauthorized network access and potential data exfiltration",
            "priority": "High",
            "cost": "$20K-200K (incident response + data recovery)",
            "time": "2-4 hours",
            "impact_score": 5,  # Catastrophic
            "likelihood_score": 4,  # Likely
        },
        "aws_ec2_instance_public_ip": {
            "impact": "Direct attack surface, data breach",
            "likelihood": "High - public IPs are constantly scanned",
            "context": "EC2 instances with public IPs are directly accessible from the internet, increasing attack risk",
            "priority": "High",
            "cost": "$15K-150K (incident response + system recovery)",
            "time": "2-6 hours",
            "impact_score": 4,  # Major
            "likelihood_score": 4,  # Likely
        },
        "aws_rds_instance_publicly_accessible": {
            "impact": "Database compromise, data breach, regulatory fines",
            "likelihood": "High - databases are prime targets",
            "context": "Publicly accessible databases are high-value targets for attackers seeking sensitive data",
            "priority": "Critical",
            "cost": "$50K-500K+ (fines + data breach response)",
            "time": "1-4 hours",
            "impact_score": 5,  # Catastrophic
            "likelihood_score": 5,  # Almost Certain
        },
        "aws_lambda_function_public": {
            "impact": "Code execution, data access, service disruption",
            "likelihood": "Medium - requires specific knowledge of function",
            "context": "Public Lambda functions can be invoked by unauthorized users, potentially leading to data exposure",
            "priority": "Medium",
            "cost": "$5K-25K (incident response + code review)",
            "time": "4-8 hours",
            "impact_score": 3,  # Moderate
            "likelihood_score": 3,  # Possible
        },
        "kubernetes_pod_security_context": {
            "impact": "Container escape, host compromise",
            "likelihood": "Medium - requires container escape techniques",
            "context": "Pods without proper security context can lead to container escape and host system compromise",
            "priority": "High",
            "cost": "$25K-100K (incident response + system recovery)",
            "time": "4-12 hours",
            "impact_score": 4,  # Major
            "likelihood_score": 3,  # Possible
        },
        "kubernetes_secret_plaintext": {
            "impact": "Credential exposure, data breach",
            "likelihood": "High - secrets are easily accessible",
            "context": "Secrets stored in plaintext can be easily accessed by unauthorized users or applications",
            "priority": "Critical",
            "cost": "$30K-300K (credential rotation + incident response)",
            "time": "2-8 hours",
            "impact_score": 5,  # Catastrophic
            "likelihood_score": 4,  # Likely
        },
        "docker_container_root_user": {
            "impact": "Container escape, host compromise",
            "likelihood": "Medium - requires container escape techniques",
            "context": "Containers running as root have elevated privileges that can lead to host system compromise",
            "priority": "High",
            "cost": "$20K-80K (incident response + system recovery)",
            "time": "4-8 hours",
            "impact_score": 4,  # Major
            "likelihood_score": 3,  # Possible
        },
        "terraform_state_file_public": {
            "impact": "Infrastructure compromise, credential exposure",
            "likelihood": "High - state files contain sensitive information",
            "context": "Public Terraform state files contain infrastructure secrets and can lead to complete infrastructure compromise",
            "priority": "Critical",
            "cost": "$50K-500K+ (infrastructure rebuild + incident response)",
            "time": "8-24 hours",
            "impact_score": 5,  # Catastrophic
            "likelihood_score": 5,  # Almost Certain
        },
        # IAM Security Issues
        "iam_access_analyzer_not_enabled": {
            "impact": "Unused permissions, privilege escalation risk",
            "likelihood": "Medium - requires access analysis",
            "context": "IAM Access Analyzer helps identify unused permissions and potential privilege escalation paths",
            "priority": "Medium",
            "cost": "$5K-20K (permission audit + cleanup)",
            "time": "8-16 hours",
            "impact_score": 4,  # Major
            "likelihood_score": 3,  # Possible
        },
    }

    @classmethod
    def assess_risk(cls, query_name: str, severity: str, description: str) -> RiskAssessment:
        """
        Assess business risk for a security finding using Impact × Likelihood calculation.

        Args:
            query_name: Name of the security query
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            description: Description of the security issue

        Returns:
            RiskAssessment object with calculated risk metrics
        """
        # Ensure all parameters are strings
        if isinstance(query_name, (tuple, list)):
            query_name = str(query_name[0]) if query_name else "Unknown Query"
        elif not isinstance(query_name, str):
            query_name = str(query_name)

        if not isinstance(severity, str):
            severity = str(severity)

        if not isinstance(description, str):
            description = str(description)

        # Determine impact and likelihood
        impact = cls._determine_impact(query_name, severity, description)
        likelihood = cls._determine_likelihood(query_name, severity, description)

        # Calculate business risk score: Impact × Likelihood
        business_risk_score = cls.calculate_business_risk_score(impact, likelihood)

        # Determine business risk level based on score
        business_risk = cls.determine_business_risk_level(business_risk_score)

        # Get business context information with improved matching
        normalized_query = query_name.lower().replace(" ", "_").replace("-", "_")

        # Try exact match first
        context_info = cls.BUSINESS_CONTEXTS.get(normalized_query, None)

        # If no exact match, try partial matching
        if context_info is None:
            for key, value in cls.BUSINESS_CONTEXTS.items():
                if any(word in normalized_query for word in key.split("_")) or any(word in key for word in normalized_query.split("_")):
                    context_info = value
                    break

        # If still no match, use default
        if context_info is None:
            context_info = {
                "impact": "Potential security breach and data compromise",
                "likelihood": "Medium - depends on specific circumstances",
                "context": "This vulnerability could lead to security incidents and business disruption",
                "priority": "Medium",
                "cost": "$5K-50K (estimated incident response)",
                "time": "4-8 hours",
                "impact_score": 3,  # Default moderate
                "likelihood_score": 3,  # Default possible
            }

        return RiskAssessment(
            impact=impact,
            likelihood=likelihood,
            business_risk_score=business_risk_score,
            business_risk=business_risk,
            impact_description=context_info["impact"],
            likelihood_description=context_info["likelihood"],
            business_context=context_info["context"],
            remediation_priority=context_info["priority"],
            cost_estimate=context_info["cost"],
            time_to_fix=context_info["time"],
        )

    @classmethod
    def _determine_impact(cls, query_name: str, severity: str, description: str) -> ImpactLevel:
        """Determine impact level based on query type and severity."""
        # Ensure query_name is a string
        if isinstance(query_name, (tuple, list)):
            query_name = str(query_name[0]) if query_name else "Unknown Query"
        elif not isinstance(query_name, str):
            query_name = str(query_name)

        query_lower = query_name.lower()

        # Catastrophic impact scenarios (Score 5)
        if any(
            keyword in query_lower
            for keyword in [
                "public",
                "exposed",
                "unencrypted",
                "plaintext",
                "secret",
                "credential",
                "database",
            ]
        ):
            return ImpactLevel.CATASTROPHIC

        # Major impact scenarios (Score 4)
        if any(
            keyword in query_lower
            for keyword in [
                "root",
                "admin",
                "privilege",
                "permission",
                "access",
                "network",
            ]
        ):
            return ImpactLevel.MAJOR

        # Moderate impact scenarios (Score 3)
        if any(keyword in query_lower for keyword in ["logging", "monitoring", "audit", "compliance", "container"]):
            return ImpactLevel.MODERATE

        # Minor impact scenarios (Score 2)
        if any(keyword in query_lower for keyword in ["version", "update", "patch", "configuration"]):
            return ImpactLevel.MINOR

        # Default based on severity
        severity_map = {
            "CRITICAL": ImpactLevel.CATASTROPHIC,
            "HIGH": ImpactLevel.MAJOR,
            "MEDIUM": ImpactLevel.MODERATE,
            "LOW": ImpactLevel.MINOR,
            "INFO": ImpactLevel.INSIGNIFICANT,
        }

        return severity_map.get(severity.upper(), ImpactLevel.MODERATE)

    @classmethod
    def _determine_likelihood(cls, query_name: str, severity: str, description: str) -> LikelihoodLevel:
        """Determine likelihood level based on query type and context."""
        # Ensure query_name is a string
        if isinstance(query_name, (tuple, list)):
            query_name = str(query_name[0]) if query_name else "Unknown Query"
        elif not isinstance(query_name, str):
            query_name = str(query_name)

        query_lower = query_name.lower()

        # Special case for "Unknown Query" - always use severity mapping
        if query_lower == "unknown query":
            severity_map = {
                "CRITICAL": LikelihoodLevel.LIKELY,
                "HIGH": LikelihoodLevel.LIKELY,
                "MEDIUM": LikelihoodLevel.POSSIBLE,
                "LOW": LikelihoodLevel.UNLIKELY,
                "INFO": LikelihoodLevel.RARE,
            }
            return severity_map.get(severity.upper(), LikelihoodLevel.POSSIBLE)

        # Almost certain scenarios (Score 5)
        if any(
            keyword in query_lower
            for keyword in [
                "public",
                "exposed",
                "internet",
                "0.0.0.0",
                "database",  # nosec B104
            ]
        ):
            return LikelihoodLevel.ALMOST_CERTAIN

        # Likely scenarios (Score 4)
        if any(keyword in query_lower for keyword in ["default", "weak", "common", "open"]):
            return LikelihoodLevel.LIKELY

        # Possible scenarios (Score 3)
        if any(keyword in query_lower for keyword in ["privilege", "permission", "access", "container"]):
            return LikelihoodLevel.POSSIBLE

        # Unlikely scenarios (Score 2)
        if any(keyword in query_lower for keyword in ["logging", "monitoring", "audit", "version"]):
            return LikelihoodLevel.UNLIKELY

        # Rare scenarios (Score 1)
        if any(keyword in query_lower for keyword in ["deprecated", "legacy", "obsolete"]):
            return LikelihoodLevel.RARE

        # Default based on severity
        severity_map = {
            "CRITICAL": LikelihoodLevel.LIKELY,
            "HIGH": LikelihoodLevel.LIKELY,
            "MEDIUM": LikelihoodLevel.POSSIBLE,
            "LOW": LikelihoodLevel.UNLIKELY,
            "INFO": LikelihoodLevel.RARE,
        }

        return severity_map.get(severity.upper(), LikelihoodLevel.POSSIBLE)


def generate_risk_report(findings: List[Dict]) -> Dict[str, Any]:
    """
    Generate a comprehensive risk report with business context.

    Args:
        findings: List of security findings

    Returns:
        Dictionary containing risk analysis and recommendations
    """
    risk_assessments = []
    risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "minimal": 0}

    total_estimated_cost = 0

    for finding in findings:
        query_name = finding.get("query_name", "Unknown")
        severity = finding.get("severity", "MEDIUM")
        description = finding.get("description", "")

        # Assess business risk
        risk_assessment = RiskMatrix.assess_risk(query_name, severity, description)

        # Add risk assessment to finding
        finding["risk_assessment"] = {
            "impact": risk_assessment.impact.value[1],
            "likelihood": risk_assessment.likelihood.value[1],
            "business_risk_score": risk_assessment.business_risk_score,
            "business_risk": risk_assessment.business_risk.value[1],
            "impact_description": risk_assessment.impact_description,
            "likelihood_description": risk_assessment.likelihood_description,
            "business_context": risk_assessment.business_context,
            "remediation_priority": risk_assessment.remediation_priority,
            "cost_estimate": risk_assessment.cost_estimate,
            "time_to_fix": risk_assessment.time_to_fix,
        }

        # Update summary
        risk_level_value = risk_assessment.business_risk.value[1]

        print(f"🔍 Debug - risk_level_value type: {type(risk_level_value)}, value: {risk_level_value}")

        # Ensure risk_level_value is a string before calling .lower()
        if isinstance(risk_level_value, (tuple, list)):
            risk_level_value = str(risk_level_value[0]) if risk_level_value else "medium"
        elif not isinstance(risk_level_value, str):
            risk_level_value = str(risk_level_value)

        print(f"🔍 Debug - risk_level_value after conversion: {risk_level_value}")

        risk_level = risk_level_value.lower()
        print(f"🔍 Debug - risk_level: {risk_level}")

        # Map risk levels to expected summary keys
        risk_level_mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "minimal": "minimal",
            # Handle numeric string values
            "1": "minimal",
            "2": "low",
            "3": "medium",
            "4": "high",
            "5": "critical",
        }

        # Use mapped key or default to "medium" if not found
        summary_key = risk_level_mapping.get(risk_level, "medium")
        print(f"🔍 Debug - summary_key: {summary_key}")
        print(f"🔍 Debug - risk_summary keys: {list(risk_summary.keys())}")
        risk_summary[summary_key] += 1

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
            except Exception:
                pass

        risk_assessments.append(risk_assessment)

    return {
        "risk_assessments": risk_assessments,
        "risk_summary": risk_summary,
        "risk_distribution": risk_summary,  # Add the missing key
        "total_estimated_cost": f"${total_estimated_cost:,.0f}",
        "total_findings": len(findings),
        "critical_findings": risk_summary["critical"],
        "high_findings": risk_summary["high"],
        "medium_findings": risk_summary["medium"],
        "low_findings": risk_summary["low"],
        "minimal_findings": risk_summary["minimal"],
    }
