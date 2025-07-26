#!/usr/bin/env python3
"""
Demo script showing the Impact × Likelihood = Business Risk calculation method.
This script is self-contained and doesn't rely on complex imports.
"""

from enum import Enum
from dataclasses import dataclass

# Define the risk levels with numerical scores
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
    CRITICAL = (20, "Critical")      # Score 20-25
    HIGH = (15, "High")              # Score 15-19
    MEDIUM = (10, "Medium")          # Score 10-14
    LOW = (5, "Low")                 # Score 5-9
    MINIMAL = (1, "Minimal")         # Score 1-4

@dataclass
class RiskAssessment:
    """Risk assessment for a security finding."""
    impact: ImpactLevel
    likelihood: LikelihoodLevel
    business_risk_score: int  # Impact × Likelihood
    business_risk: BusinessRiskLevel

class RiskMatrix:
    """Risk matrix for determining business risk levels using Impact × Likelihood calculation."""
    
    @classmethod
    def calculate_business_risk_score(cls, impact: ImpactLevel, likelihood: LikelihoodLevel) -> int:
        """Calculate business risk score using Impact × Likelihood formula."""
        return impact.value[0] * likelihood.value[0]
    
    @classmethod
    def determine_business_risk_level(cls, score: int) -> BusinessRiskLevel:
        """Determine business risk level based on calculated score."""
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
    
    @classmethod
    def assess_risk(cls, query_name: str, severity: str, description: str) -> RiskAssessment:
        """Assess business risk for a security finding using Impact × Likelihood calculation."""
        # Determine impact based on query type
        query_lower = query_name.lower()
        
        # Catastrophic impact scenarios (Score 5)
        if any(keyword in query_lower for keyword in ["public", "exposed", "unencrypted", "plaintext", "secret", "credential", "database"]):
            impact = ImpactLevel.CATASTROPHIC
        # Major impact scenarios (Score 4)
        elif any(keyword in query_lower for keyword in ["root", "admin", "privilege", "permission", "access", "network"]):
            impact = ImpactLevel.MAJOR
        # Moderate impact scenarios (Score 3)
        elif any(keyword in query_lower for keyword in ["logging", "monitoring", "audit", "compliance", "container"]):
            impact = ImpactLevel.MODERATE
        # Minor impact scenarios (Score 2)
        elif any(keyword in query_lower for keyword in ["version", "update", "patch", "configuration"]):
            impact = ImpactLevel.MINOR
        else:
            impact = ImpactLevel.MODERATE
        
        # Determine likelihood based on query type
        # Almost certain scenarios (Score 5)
        if any(keyword in query_lower for keyword in ["public", "exposed", "internet", "0.0.0.0", "database"]):
            likelihood = LikelihoodLevel.ALMOST_CERTAIN
        # Likely scenarios (Score 4)
        elif any(keyword in query_lower for keyword in ["default", "weak", "common", "known", "open"]):
            likelihood = LikelihoodLevel.LIKELY
        # Possible scenarios (Score 3)
        elif any(keyword in query_lower for keyword in ["privilege", "permission", "access", "container"]):
            likelihood = LikelihoodLevel.POSSIBLE
        # Unlikely scenarios (Score 2)
        elif any(keyword in query_lower for keyword in ["logging", "monitoring", "audit", "version"]):
            likelihood = LikelihoodLevel.UNLIKELY
        # Rare scenarios (Score 1)
        elif any(keyword in query_lower for keyword in ["deprecated", "legacy", "obsolete"]):
            likelihood = LikelihoodLevel.RARE
        else:
            likelihood = LikelihoodLevel.POSSIBLE
        
        # Calculate business risk score: Impact × Likelihood
        business_risk_score = cls.calculate_business_risk_score(impact, likelihood)
        
        # Determine business risk level based on score
        business_risk = cls.determine_business_risk_level(business_risk_score)
        
        return RiskAssessment(
            impact=impact,
            likelihood=likelihood,
            business_risk_score=business_risk_score,
            business_risk=business_risk
        )

def main():
    """Demo the risk calculation method."""
    print("🧮 Impact × Likelihood = Business Risk Calculation Demo")
    print("=" * 60)
    
    # Test cases with different combinations
    test_cases = [
        ("AWS S3 Bucket Public Access", "CRITICAL", "Public bucket exposed to internet"),
        ("AWS IAM User Password Enabled", "HIGH", "IAM user with password access"),
        ("Kubernetes Secret Plaintext", "CRITICAL", "Secrets stored in plaintext"),
        ("Docker Container Root User", "MEDIUM", "Container running as root"),
        ("AWS Lambda Function Public", "MEDIUM", "Public Lambda function"),
        ("Terraform State File Public", "CRITICAL", "Public Terraform state file"),
        ("Logging Configuration Issue", "LOW", "Missing audit logs"),
        ("Deprecated API Usage", "INFO", "Using old API version"),
    ]
    
    print(f"{'Query Name':<30} {'Impact':<12} {'Likelihood':<12} {'Score':<6} {'Risk Level':<10}")
    print("-" * 80)
    
    for query_name, severity, description in test_cases:
        # Assess risk using the new method
        risk_assessment = RiskMatrix.assess_risk(query_name, severity, description)
        
        # Calculate the score manually to verify
        calculated_score = risk_assessment.impact.value[0] * risk_assessment.likelihood.value[0]
        
        print(f"{query_name:<30} {risk_assessment.impact.value[1]:<12} {risk_assessment.likelihood.value[1]:<12} {calculated_score:<6} {risk_assessment.business_risk.value[1]:<10}")
    
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
    main() 