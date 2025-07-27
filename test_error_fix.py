#!/usr/bin/env python3
"""
Simple test script to isolate and fix the '5' error.
"""

import os
import sys
from pathlib import Path

# Add the src directory to Python path
current_dir = Path(__file__).parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))


def test_risk_assessment():
    """Test the risk assessment logic to identify the '5' error."""
    print("🧮 Testing Risk Assessment Logic")
    print("=" * 50)

    try:
        from src.driftbuddy.risk_assessment import (
            ImpactLevel,
            LikelihoodLevel,
            RiskMatrix,
        )

        # Test case that might be causing the issue
        test_cases = [
            (
                "S3 Bucket ACL Allows Read Or Write to All Users",
                "CRITICAL",
                "Public bucket",
            ),
            ("S3 Bucket Logging Disabled", "MEDIUM", "No logging"),
            ("S3 Bucket Without Versioning", "LOW", "No versioning"),
            ("IAM Access Analyzer Not Enabled", "HIGH", "No analyzer"),
        ]

        for query_name, severity, description in test_cases:
            print(f"\n🔍 Testing: {query_name}")
            print(f"   Severity: {severity}")
            print(f"   Description: {description}")

            # Test the risk assessment
            risk_assessment = RiskMatrix.assess_risk(query_name, severity, description)

            print(f"   Impact: {risk_assessment.impact.value}")
            print(f"   Likelihood: {risk_assessment.likelihood.value}")
            print(f"   Business Risk Score: {risk_assessment.business_risk_score}")
            print(f"   Business Risk: {risk_assessment.business_risk.value}")

            # Test the risk summary logic
            risk_summary = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "minimal": 0,
            }

            risk_level_value = risk_assessment.business_risk.value[1]
            print(f"   Risk Level Value: {risk_level_value} (type: {type(risk_level_value)})")

            # Ensure it's a string
            if isinstance(risk_level_value, (tuple, list)):
                risk_level_value = str(risk_level_value[0]) if risk_level_value else "medium"
            elif not isinstance(risk_level_value, str):
                risk_level_value = str(risk_level_value)

            print(f"   Risk Level Value (converted): {risk_level_value}")

            risk_level = risk_level_value.lower()
            print(f"   Risk Level (lowercase): {risk_level}")

            # Map to summary key
            risk_level_mapping = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "minimal": "minimal",
                "1": "minimal",
                "2": "low",
                "3": "medium",
                "4": "high",
                "5": "critical",
            }

            summary_key = risk_level_mapping.get(risk_level, "medium")
            print(f"   Summary Key: {summary_key}")

            risk_summary[summary_key] += 1
            print(f"   Risk Summary: {risk_summary}")

    except Exception as e:
        print(f"❌ Error during test: {e}")
        import traceback

        traceback.print_exc()


def test_html_generation():
    """Test the HTML generation logic."""
    print("\n" + "=" * 50)
    print("🌐 Testing HTML Generation Logic")
    print("=" * 50)

    try:
        # Simulate the queries data structure
        queries = [
            {
                "query_name": "Test Query",
                "severity": "CRITICAL",
                "description": "Test description",
                "files": [],
                "ai_explanation": "Test explanation",
                "risk_assessment": {
                    "business_risk": "Critical",
                    "impact": "Catastrophic",
                    "likelihood": "Almost Certain",
                    "business_risk_score": 25,
                    "impact_description": "Test impact",
                    "likelihood_description": "Test likelihood",
                    "business_context": "Test context",
                    "remediation_priority": "Immediate",
                    "cost_estimate": "$10K-100K",
                    "time_to_fix": "1-2 hours",
                },
            }
        ]

        # Test the risk summary calculation
        risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "minimal": 0}

        for query in queries:
            risk_assessment = query.get("risk_assessment", {})
            business_risk = risk_assessment.get("business_risk", "Medium")

            print(f"🔍 Business Risk: {business_risk} (type: {type(business_risk)})")

            # Ensure business_risk is a string
            if isinstance(business_risk, (tuple, list)):
                business_risk = str(business_risk[0]) if business_risk else "Medium"
            elif not isinstance(business_risk, str):
                business_risk = str(business_risk)

            print(f"🔍 Business Risk (converted): {business_risk}")

            # Map risk levels
            risk_level_mapping = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "minimal": "minimal",
                "1": "minimal",
                "2": "low",
                "3": "medium",
                "4": "high",
                "5": "critical",
            }

            summary_key = risk_level_mapping.get(business_risk.lower(), "medium")
            print(f"🔍 Summary Key: {summary_key}")

            risk_summary[summary_key] += 1
            print(f"🔍 Risk Summary: {risk_summary}")

            # Test accessing the risk summary
            print(f"🔍 Testing access to risk_summary['critical']: {risk_summary['critical']}")

    except Exception as e:
        print(f"❌ Error during HTML test: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_risk_assessment()
    test_html_generation()
    print("\n✅ Test completed!")
