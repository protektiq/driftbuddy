#!/usr/bin/env python3
"""
Test script to demonstrate the new Impact × Likelihood = Business Risk calculation method.
"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.driftbuddy.risk_assessment import ImpactLevel, LikelihoodLevel, RiskMatrix


def test_risk_calculations():
    """Test the new risk calculation method."""
    print("🧮 Testing Impact × Likelihood = Business Risk Calculation")
    print("=" * 60)

    # Test cases with different combinations
    test_cases = [
        (
            "AWS S3 Bucket Public Access",
            "CRITICAL",
            "Public bucket exposed to internet",
        ),
        ("AWS IAM User Password Enabled", "HIGH", "IAM user with password access"),
        ("Kubernetes Secret Plaintext", "CRITICAL", "Secrets stored in plaintext"),
        ("Docker Container Root User", "MEDIUM", "Container running as root"),
        ("AWS Lambda Function Public", "MEDIUM", "Public Lambda function"),
        ("Terraform State File Public", "CRITICAL", "Public Terraform state file"),
    ]

    print(f"{'Query Name':<30} {'Impact':<12} {'Likelihood':<12} {'Score':<6} {'Risk Level':<10}")
    print("-" * 80)

    for query_name, severity, description in test_cases:
        # Assess risk using the new method
        risk_assessment = RiskMatrix.assess_risk(query_name, severity, description)

        # Calculate the score manually to verify
        calculated_score = risk_assessment.impact.value[0] * risk_assessment.likelihood.value[0]

        print(
            f"{query_name:<30} {risk_assessment.impact.value[1]:<12} {risk_assessment.likelihood.value[1]:<12} {calculated_score:<6} {risk_assessment.business_risk.value[1]:<10}"
        )

    print("\n" + "=" * 60)
    print("📊 Risk Level Thresholds:")
    print("• Critical (20-25): Immediate action required")
    print("• High (15-19): High priority remediation")
    print("• Medium (10-14): Moderate priority")
    print("• Low (5-9): Low priority")
    print("• Minimal (1-4): Acceptable risk")

    print("\n" + "=" * 60)
    print("🔍 Example Calculations:")

    # Show some specific examples
    examples = [
        (ImpactLevel.CATASTROPHIC, LikelihoodLevel.ALMOST_CERTAIN, "Public Database"),
        (ImpactLevel.MAJOR, LikelihoodLevel.LIKELY, "Admin Access"),
        (ImpactLevel.MODERATE, LikelihoodLevel.POSSIBLE, "Container Security"),
        (ImpactLevel.MINOR, LikelihoodLevel.UNLIKELY, "Logging Issue"),
        (ImpactLevel.INSIGNIFICANT, LikelihoodLevel.RARE, "Deprecated Feature"),
    ]

    for impact, likelihood, description in examples:
        score = impact.value[0] * likelihood.value[0]
        risk_level = RiskMatrix.determine_business_risk_level(score)
        print(f"• {description}: {impact.value[1]} ({impact.value[0]}) × {likelihood.value[1]} ({likelihood.value[0]}) = {score} → {risk_level.value[1]}")


def test_risk_matrix_methodology():
    """Test the risk matrix methodology."""
    print("\n" + "=" * 60)
    print("📋 Risk Matrix Methodology (Impact × Likelihood)")
    print("=" * 60)

    print("Impact Levels (1-5 scale):")
    print("• 5 - Catastrophic: Complete system compromise, data breach")
    print("• 4 - Major: Significant business impact, regulatory fines")
    print("• 3 - Moderate: Operational disruption, reputation damage")
    print("• 2 - Minor: Limited impact, minor operational issues")
    print("• 1 - Insignificant: Minimal impact, acceptable risk")

    print("\nLikelihood Levels (1-5 scale):")
    print("• 5 - Almost Certain: >90% chance, highly probable")
    print("• 4 - Likely: 65-90% chance, probable")
    print("• 3 - Possible: 35-65% chance, moderate probability")
    print("• 2 - Unlikely: 10-35% chance, low probability")
    print("• 1 - Rare: <10% chance, very unlikely")

    print("\nBusiness Risk Calculation:")
    print("Business Risk Score = Impact Score × Likelihood Score")
    print("Example: Catastrophic Impact (5) × Almost Certain Likelihood (5) = 25 (Critical)")


if __name__ == "__main__":
    test_risk_calculations()
    test_risk_matrix_methodology()
