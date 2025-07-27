"""
Tests for the business risk assessment functionality.
"""

import pytest

from src.driftbuddy.risk_assessment import (
    BusinessRiskLevel,
    ImpactLevel,
    LikelihoodLevel,
    RiskMatrix,
    generate_risk_report,
)


class TestRiskAssessment:
    """Test cases for risk assessment functionality."""

    def test_impact_determination(self):
        """Test impact level determination."""
        # Test critical impact scenarios
        assert RiskMatrix._determine_impact("AWS S3 Public Access", "HIGH", "") == ImpactLevel.CRITICAL
        assert RiskMatrix._determine_impact("Database Unencrypted", "MEDIUM", "") == ImpactLevel.CRITICAL
        assert RiskMatrix._determine_impact("Secrets in Plaintext", "LOW", "") == ImpactLevel.CRITICAL

        # Test high impact scenarios
        assert RiskMatrix._determine_impact("Root User Access", "HIGH", "") == ImpactLevel.HIGH
        assert RiskMatrix._determine_impact("Admin Privileges", "MEDIUM", "") == ImpactLevel.HIGH

        # Test medium impact scenarios
        assert RiskMatrix._determine_impact("Missing Logging", "LOW", "") == ImpactLevel.MEDIUM
        assert RiskMatrix._determine_impact("Audit Disabled", "INFO", "") == ImpactLevel.MEDIUM

        # Test default based on severity
        assert RiskMatrix._determine_impact("Unknown Query", "CRITICAL", "") == ImpactLevel.CRITICAL
        assert RiskMatrix._determine_impact("Unknown Query", "HIGH", "") == ImpactLevel.HIGH
        assert RiskMatrix._determine_impact("Unknown Query", "MEDIUM", "") == ImpactLevel.MEDIUM
        assert RiskMatrix._determine_impact("Unknown Query", "LOW", "") == ImpactLevel.LOW
        assert RiskMatrix._determine_impact("Unknown Query", "INFO", "") == ImpactLevel.MINIMAL

    def test_likelihood_determination(self):
        """Test likelihood level determination."""
        # Test very high likelihood scenarios
        assert RiskMatrix._determine_likelihood("Public Access", "HIGH", "") == LikelihoodLevel.VERY_HIGH
        assert RiskMatrix._determine_likelihood("Exposed to Internet", "MEDIUM", "") == LikelihoodLevel.VERY_HIGH

        # Test high likelihood scenarios
        assert RiskMatrix._determine_likelihood("Default Password", "HIGH", "") == LikelihoodLevel.HIGH
        assert RiskMatrix._determine_likelihood("Weak Configuration", "MEDIUM", "") == LikelihoodLevel.HIGH

        # Test medium likelihood scenarios
        assert RiskMatrix._determine_likelihood("Privilege Escalation", "HIGH", "") == LikelihoodLevel.MEDIUM
        assert RiskMatrix._determine_likelihood("Access Control", "MEDIUM", "") == LikelihoodLevel.MEDIUM

        # Test low likelihood scenarios
        assert RiskMatrix._determine_likelihood("Missing Logging", "LOW", "") == LikelihoodLevel.LOW
        assert RiskMatrix._determine_likelihood("Audit Disabled", "INFO", "") == LikelihoodLevel.LOW

        # Test default based on severity
        assert RiskMatrix._determine_likelihood("Unknown Query", "CRITICAL", "") == LikelihoodLevel.HIGH
        assert RiskMatrix._determine_likelihood("Unknown Query", "HIGH", "") == LikelihoodLevel.HIGH
        assert RiskMatrix._determine_likelihood("Unknown Query", "MEDIUM", "") == LikelihoodLevel.MEDIUM
        assert RiskMatrix._determine_likelihood("Unknown Query", "LOW", "") == LikelihoodLevel.LOW
        assert RiskMatrix._determine_likelihood("Unknown Query", "INFO", "") == LikelihoodLevel.VERY_LOW

    def test_risk_matrix(self):
        """Test risk matrix calculations."""
        # Test critical business risk scenarios
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.CRITICAL, LikelihoodLevel.VERY_HIGH)] == BusinessRiskLevel.CRITICAL
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.CRITICAL, LikelihoodLevel.HIGH)] == BusinessRiskLevel.CRITICAL
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.HIGH, LikelihoodLevel.VERY_HIGH)] == BusinessRiskLevel.CRITICAL

        # Test high business risk scenarios
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.CRITICAL, LikelihoodLevel.MEDIUM)] == BusinessRiskLevel.HIGH
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.HIGH, LikelihoodLevel.HIGH)] == BusinessRiskLevel.HIGH
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.MEDIUM, LikelihoodLevel.VERY_HIGH)] == BusinessRiskLevel.HIGH

        # Test medium business risk scenarios
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.CRITICAL, LikelihoodLevel.LOW)] == BusinessRiskLevel.MEDIUM
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.HIGH, LikelihoodLevel.LOW)] == BusinessRiskLevel.MEDIUM
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.MEDIUM, LikelihoodLevel.MEDIUM)] == BusinessRiskLevel.MEDIUM

        # Test low business risk scenarios
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.CRITICAL, LikelihoodLevel.VERY_LOW)] == BusinessRiskLevel.LOW
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.LOW, LikelihoodLevel.MEDIUM)] == BusinessRiskLevel.LOW

        # Test minimal business risk scenarios
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.MEDIUM, LikelihoodLevel.VERY_LOW)] == BusinessRiskLevel.MINIMAL
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.LOW, LikelihoodLevel.LOW)] == BusinessRiskLevel.MINIMAL
        assert RiskMatrix.RISK_MATRIX[(ImpactLevel.MINIMAL, LikelihoodLevel.HIGH)] == BusinessRiskLevel.MINIMAL

    def test_risk_assessment(self):
        """Test complete risk assessment."""
        # Test a critical finding
        assessment = RiskMatrix.assess_risk("AWS S3 Public Access", "HIGH", "S3 bucket has public read access")

        assert assessment.impact == ImpactLevel.CRITICAL
        assert assessment.likelihood == LikelihoodLevel.VERY_HIGH
        assert assessment.business_risk == BusinessRiskLevel.CRITICAL
        assert "Data breach" in assessment.impact_description
        assert "easily discoverable" in assessment.likelihood_description
        assert "Immediate" in assessment.remediation_priority
        assert "$" in assessment.cost_estimate
        assert "hours" in assessment.time_to_fix

    def test_generate_risk_report(self):
        """Test risk report generation."""
        findings = [
            {
                "query_name": "AWS S3 Public Access",
                "severity": "HIGH",
                "description": "S3 bucket has public read access",
                "file_name": "main.tf",
                "line": "45",
                "issue": "Public read access enabled",
            },
            {
                "query_name": "Missing Logging",
                "severity": "LOW",
                "description": "No logging configured",
                "file_name": "main.tf",
                "line": "67",
                "issue": "Logging not enabled",
            },
        ]

        report = generate_risk_report(findings)

        assert report["total_findings"] == 2
        assert report["critical_findings"] >= 1  # S3 public access should be critical
        assert report["low_findings"] >= 1  # Missing logging should be low
        assert "$" in report["total_estimated_cost"]
        assert "risk_assessments" in report
        assert "risk_summary" in report

    def test_business_contexts(self):
        """Test business context information."""
        # Test known contexts
        assert "aws_s3_bucket_public_access" in RiskMatrix.BUSINESS_CONTEXTS
        assert "aws_iam_user_password_enabled" in RiskMatrix.BUSINESS_CONTEXTS
        assert "aws_security_group_open_ports" in RiskMatrix.BUSINESS_CONTEXTS

        # Test context content
        s3_context = RiskMatrix.BUSINESS_CONTEXTS["aws_s3_bucket_public_access"]
        assert "Data breach" in s3_context["impact"]
        assert "easily discoverable" in s3_context["likelihood"]
        assert "Public S3 buckets" in s3_context["context"]
        assert "Immediate" in s3_context["priority"]
        assert "$" in s3_context["cost"]
        assert "hours" in s3_context["time"]

    def test_unknown_query_fallback(self):
        """Test handling of unknown queries."""
        assessment = RiskMatrix.assess_risk("Unknown Security Query", "MEDIUM", "Some security issue")

        # Should still provide a valid assessment
        assert assessment.impact in [
            ImpactLevel.CRITICAL,
            ImpactLevel.HIGH,
            ImpactLevel.MEDIUM,
            ImpactLevel.LOW,
            ImpactLevel.MINIMAL,
        ]
        assert assessment.likelihood in [
            LikelihoodLevel.VERY_HIGH,
            LikelihoodLevel.HIGH,
            LikelihoodLevel.MEDIUM,
            LikelihoodLevel.LOW,
            LikelihoodLevel.VERY_LOW,
        ]
        assert assessment.business_risk in [
            BusinessRiskLevel.CRITICAL,
            BusinessRiskLevel.HIGH,
            BusinessRiskLevel.MEDIUM,
            BusinessRiskLevel.LOW,
            BusinessRiskLevel.MINIMAL,
        ]

        # Should have default context
        assert "Potential security breach" in assessment.impact_description
        assert "depends on specific circumstances" in assessment.likelihood_description
        assert "security incidents" in assessment.business_context


if __name__ == "__main__":
    pytest.main([__file__])
