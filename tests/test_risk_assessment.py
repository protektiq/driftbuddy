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
        # Test catastrophic impact scenarios
        assert RiskMatrix._determine_impact("AWS S3 Public Access", "HIGH", "") == ImpactLevel.CATASTROPHIC
        assert RiskMatrix._determine_impact("Database Unencrypted", "MEDIUM", "") == ImpactLevel.CATASTROPHIC
        assert RiskMatrix._determine_impact("Secrets in Plaintext", "LOW", "") == ImpactLevel.CATASTROPHIC

        # Test major impact scenarios
        assert RiskMatrix._determine_impact("Root User Access", "HIGH", "") == ImpactLevel.MAJOR
        assert RiskMatrix._determine_impact("Admin Privileges", "MEDIUM", "") == ImpactLevel.MAJOR

        # Test moderate impact scenarios
        assert RiskMatrix._determine_impact("Missing Logging", "LOW", "") == ImpactLevel.MODERATE
        assert RiskMatrix._determine_impact("Audit Disabled", "INFO", "") == ImpactLevel.MODERATE

        # Test default based on severity
        assert RiskMatrix._determine_impact("Unknown Query", "CRITICAL", "") == ImpactLevel.CATASTROPHIC
        assert RiskMatrix._determine_impact("Unknown Query", "HIGH", "") == ImpactLevel.MAJOR
        assert RiskMatrix._determine_impact("Unknown Query", "MEDIUM", "") == ImpactLevel.MODERATE
        assert RiskMatrix._determine_impact("Unknown Query", "LOW", "") == ImpactLevel.MINOR
        assert RiskMatrix._determine_impact("Unknown Query", "INFO", "") == ImpactLevel.INSIGNIFICANT

    def test_likelihood_determination(self):
        """Test likelihood level determination."""
        # Test almost certain likelihood scenarios
        assert RiskMatrix._determine_likelihood("Public Access", "HIGH", "") == LikelihoodLevel.ALMOST_CERTAIN
        assert RiskMatrix._determine_likelihood("Exposed to Internet", "MEDIUM", "") == LikelihoodLevel.ALMOST_CERTAIN

        # Test likely scenarios
        assert RiskMatrix._determine_likelihood("Default Password", "HIGH", "") == LikelihoodLevel.LIKELY
        assert RiskMatrix._determine_likelihood("Weak Configuration", "MEDIUM", "") == LikelihoodLevel.LIKELY

        # Test possible scenarios
        assert RiskMatrix._determine_likelihood("Privilege Escalation", "HIGH", "") == LikelihoodLevel.POSSIBLE
        assert RiskMatrix._determine_likelihood("Access Control", "MEDIUM", "") == LikelihoodLevel.POSSIBLE

        # Test unlikely scenarios
        assert RiskMatrix._determine_likelihood("Missing Logging", "LOW", "") == LikelihoodLevel.UNLIKELY
        assert RiskMatrix._determine_likelihood("Audit Disabled", "INFO", "") == LikelihoodLevel.UNLIKELY

        # Test default based on severity
        assert RiskMatrix._determine_likelihood("Unknown Query", "CRITICAL", "") == LikelihoodLevel.LIKELY
        assert RiskMatrix._determine_likelihood("Unknown Query", "HIGH", "") == LikelihoodLevel.LIKELY
        assert RiskMatrix._determine_likelihood("Unknown Query", "MEDIUM", "") == LikelihoodLevel.POSSIBLE
        assert RiskMatrix._determine_likelihood("Unknown Query", "LOW", "") == LikelihoodLevel.UNLIKELY
        assert RiskMatrix._determine_likelihood("Unknown Query", "INFO", "") == LikelihoodLevel.RARE

    def test_risk_matrix(self):
        """Test risk matrix calculations."""
        # Test critical business risk scenarios
        assert RiskMatrix.determine_business_risk_level(25) == BusinessRiskLevel.CRITICAL
        assert RiskMatrix.determine_business_risk_level(20) == BusinessRiskLevel.CRITICAL
        assert RiskMatrix.determine_business_risk_level(19) == BusinessRiskLevel.HIGH

        # Test high business risk scenarios
        assert RiskMatrix.determine_business_risk_level(15) == BusinessRiskLevel.HIGH
        assert RiskMatrix.determine_business_risk_level(14) == BusinessRiskLevel.MEDIUM

        # Test medium business risk scenarios
        assert RiskMatrix.determine_business_risk_level(10) == BusinessRiskLevel.MEDIUM
        assert RiskMatrix.determine_business_risk_level(9) == BusinessRiskLevel.LOW

        # Test low business risk scenarios
        assert RiskMatrix.determine_business_risk_level(5) == BusinessRiskLevel.LOW
        assert RiskMatrix.determine_business_risk_level(4) == BusinessRiskLevel.MINIMAL

        # Test minimal business risk scenarios
        assert RiskMatrix.determine_business_risk_level(1) == BusinessRiskLevel.MINIMAL

    def test_risk_assessment(self):
        """Test complete risk assessment."""
        # Test a critical finding
        assessment = RiskMatrix.assess_risk("AWS S3 Public Access", "HIGH", "S3 bucket has public read access")

        assert assessment.impact == ImpactLevel.CATASTROPHIC
        assert assessment.likelihood == LikelihoodLevel.ALMOST_CERTAIN
        assert assessment.business_risk == BusinessRiskLevel.CRITICAL
        assert "Data breach" in assessment.impact_description

    def test_generate_risk_report(self):
        """Test risk report generation."""
        findings = [
            {
                "query_name": "AWS S3 Public Access",
                "severity": "HIGH",
                "description": "S3 bucket has public read access",
                "files": [
                    {
                        "file_name": "test.tf",
                        "line": 10,
                        "issue": "Public access enabled",
                    }
                ],
            }
        ]

        report = generate_risk_report(findings)
        assert "total_findings" in report
        assert "risk_distribution" in report
        assert "critical_findings" in report

    def test_business_contexts(self):
        """Test business context descriptions."""
        # Test that business contexts are properly defined
        assert hasattr(RiskMatrix, "BUSINESS_CONTEXTS")
        assert isinstance(RiskMatrix.BUSINESS_CONTEXTS, dict)
        assert len(RiskMatrix.BUSINESS_CONTEXTS) > 0

    def test_unknown_query_fallback(self):
        """Test handling of unknown queries."""
        assessment = RiskMatrix.assess_risk("Unknown Security Query", "MEDIUM", "Some security issue")

        # Should still provide a valid assessment
        assert assessment.impact in [
            ImpactLevel.CATASTROPHIC,
            ImpactLevel.MAJOR,
            ImpactLevel.MODERATE,
            ImpactLevel.MINOR,
            ImpactLevel.INSIGNIFICANT,
        ]


if __name__ == "__main__":
    pytest.main([__file__])
