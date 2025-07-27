import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from src.agent.explainer import explain_findings, load_kics_results

from .config import get_config
from .exceptions import DriftBuddyError, handle_exception
from .risk_assessment import RiskMatrix, generate_risk_report

# Load configuration
config = get_config()

# Import Steampipe integration
try:
    from .steampipe_integration import SteampipeIntegration

    STEAMPIPE_AVAILABLE = True
except ImportError:
    STEAMPIPE_AVAILABLE = False
    print("⚠️ Steampipe integration not available. Install steampipe_integration.py for cloud scanning features.")


@handle_exception
def generate_timestamped_filename(base_name: str, extension: str, reports_dir: str = "outputs/reports") -> str:
    """Generate a timestamped filename with driftbuddy prefix in the specified directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"driftbuddy_{base_name}_{timestamp}.{extension}"

    # Ensure the reports directory exists
    Path(reports_dir).mkdir(parents=True, exist_ok=True)

    return os.path.join(reports_dir, filename)


@handle_exception
def check_kics_installation() -> bool:
    """Check if KICS is properly installed and accessible"""
    try:
        # Just try to run KICS with help to see if it's available
        result = subprocess.run(["kics", "--help"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 or result.returncode == 1:  # Help usually exits with 1
            print("✅ KICS found and accessible")
            return True
        else:
            print("❌ KICS is installed but not working properly")
            print(f"Help check failed with exit code: {result.returncode}")
            return False
    except FileNotFoundError:
        print("❌ KICS not found in PATH")
        print("💡 Please install KICS:")
        print("   Windows: Download from https://kics.io/")
        print("   Or use: curl -L https://github.com/Checkmarx/kics/releases/latest/download/kics_windows_amd64.exe -o kics.exe")
        print("   Or use Docker: docker run --rm -v $(pwd):/path checkmarx/kics:latest scan -p /path")
        return False
    except Exception as e:
        print(f"❌ Error checking KICS installation: {str(e)}")
        return False


@handle_exception
def check_docker_kics() -> bool:
    """Check if KICS is available via Docker"""
    try:
        # First check if Docker is available
        docker_check = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=10)
        if docker_check.returncode != 0:
            print("❌ Docker not found")
            return False

        # Try to pull the KICS image if it doesn't exist
        print("🔍 Checking Docker KICS availability...")
        result = subprocess.run(
            ["docker", "run", "--rm", "checkmarx/kics:latest", "kics", "--help"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0 or result.returncode == 1:
            print("✅ KICS available via Docker")
            return True
        else:
            print("❌ KICS Docker image not working properly")
            return False
    except FileNotFoundError:
        print("❌ Docker not found")
        return False
    except Exception as e:
        print(f"❌ Error checking Docker KICS: {str(e)}")
        return False


@handle_exception
def validate_scan_path(scan_path: str) -> bool:
    """Validate that the scan path exists and contains relevant files"""
    if not os.path.exists(scan_path):
        print(f"❌ Scan path does not exist: {scan_path}")
        return False

    if not os.path.isdir(scan_path):
        print(f"❌ Scan path is not a directory: {scan_path}")
        return False

    # Check for common IaC files
    iac_extensions = [
        ".tf",
        ".yaml",
        ".yml",
        ".json",
        ".dockerfile",
        ".dockerfile",
        ".bicep",
    ]
    has_iac_files = False

    for root, dirs, files in os.walk(scan_path):
        for file in files:
            if any(file.lower().endswith(ext) for ext in iac_extensions):
                has_iac_files = True
                break
        if has_iac_files:
            break

    if not has_iac_files:
        print(f"⚠️ Warning: No common IaC files found in {scan_path}")
        print("   Supported extensions: .tf, .yaml, .yml, .json, .dockerfile, .bicep")

    return True


@handle_exception
def run_kics(scan_path: str, output_dir: str = "test_data/output") -> Dict[str, Any]:
    """Run KICS scan with comprehensive error handling"""
    print(f"🔍 Starting KICS scan of: {scan_path}")

    # Validate scan path
    if not validate_scan_path(scan_path):
        return {"success": False, "error": "Invalid scan path"}

    # Create output directory
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"❌ Error creating output directory: {str(e)}")
        return {
            "success": False,
            "error": f"Failed to create output directory: {str(e)}",
        }

    # Check if Docker is preferred or if local KICS is available
    use_docker = not check_kics_installation()

    # If local KICS has issues with queries, try Docker
    if not use_docker:
        # Test if local KICS works by running a quick test
        test_cmd = ["kics", "scan", "--help"]
        try:
            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=10)  # noqa: E501
            if result.returncode != 0:
                print("⚠️ Local KICS has issues, trying Docker...")
                use_docker = True
        except:
            print("⚠️ Local KICS test failed, trying Docker...")
            use_docker = True

    # Skip the test scan and go directly to using local KICS if available
    if not use_docker:
        print("💡 Using local KICS installation")
        return run_kics_local(scan_path, output_dir)
    else:
        if not check_docker_kics():
            return {
                "success": False,
                "error": "Neither local KICS nor Docker KICS is available",
            }
        return run_kics_docker(scan_path, output_dir)


@handle_exception
def run_kics_docker(scan_path: str, output_dir: str) -> Dict[str, Any]:
    """Run KICS scan using Docker"""
    print(f"🔍 Starting KICS Docker scan of: {scan_path}")

    # Ensure output directory exists
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"kics_results_{timestamp}.json")

    # Run KICS via Docker
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{os.path.abspath(scan_path)}:/path",
        "-v",
        f"{os.path.abspath(output_dir)}:/output",
        "checkmarx/kics:latest",
        "scan",
        "-p",
        "/path",
        "-o",
        "/output",
        "--output-name",
        f"kics_results_{timestamp}.json",
    ]

    try:
        print("🚀 Running KICS via Docker...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            print(f"✅ KICS Docker scan completed successfully")
            print(f"📄 Results saved to: {output_file}")
            return {
                "success": True,
                "output_file": output_file,
                "stdout": result.stdout,
            }
        else:
            print(f"❌ KICS Docker scan failed with exit code: {result.returncode}")
            print(f"Error: {result.stderr}")
            return {
                "success": False,
                "error": result.stderr,
                "exit_code": result.returncode,
            }
    except subprocess.TimeoutExpired:
        error_msg = "KICS Docker scan timed out after 5 minutes"
        print(f"❌ {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        error_msg = f"Error running KICS Docker scan: {str(e)}"
        print(f"❌ {error_msg}")
        return {"success": False, "error": error_msg}


@handle_exception
def run_kics_local(scan_path: str, output_dir: str) -> Dict[str, Any]:
    """Run KICS scan using local installation"""
    print(f"🔍 Starting KICS local scan of: {scan_path}")

    # Ensure output directory exists
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"kics_results_{timestamp}.json")

    def run_kics_command(use_queries_path: bool = True) -> subprocess.CompletedProcess:
        """Run KICS command with optional queries path"""
        cmd = [
            "kics",
            "scan",
            "-p",
            scan_path,
            "-o",
            output_dir,
            "--output-name",
            f"kics_results_{timestamp}.json",
        ]

        # Add queries path if available
        config = get_config()
        queries_path = config.get("kics_queries_path")
        if use_queries_path and queries_path and os.path.exists(queries_path):
            cmd.extend(["-q", queries_path])

        return subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    try:
        print("🚀 Running KICS locally...")
        result = run_kics_command()

        if result.returncode == 0:
            print(f"✅ KICS local scan completed successfully")
            print(f"📄 Results saved to: {output_file}")
            return {
                "success": True,
                "output_file": output_file,
                "stdout": result.stdout,
            }
        else:
            # Try without queries path if first attempt failed
            print(f"⚠️ First KICS attempt failed, trying without queries path...")
            result = run_kics_command(use_queries_path=False)

            if result.returncode == 0:
                print(f"✅ KICS local scan completed successfully (without queries path)")
                print(f"📄 Results saved to: {output_file}")
                return {
                    "success": True,
                    "output_file": output_file,
                    "stdout": result.stdout,
                }
            else:
                print(f"❌ KICS local scan failed with exit code: {result.returncode}")
                print(f"Error: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr,
                    "exit_code": result.returncode,
                }
    except subprocess.TimeoutExpired:
        error_msg = "KICS local scan timed out after 5 minutes"
        print(f"❌ {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        error_msg = f"Error running KICS local scan: {str(e)}"
        print(f"❌ {error_msg}")
        return {"success": False, "error": error_msg}


@handle_exception
def load_kics_results_safe(results_path: str) -> Dict[str, Any]:
    """Load KICS results with comprehensive error handling"""
    try:
        if not os.path.exists(results_path):
            print(f"❌ Results file not found: {results_path}")
            return {"error": f"Results file not found: {results_path}"}

        with open(results_path, encoding="utf-8") as f:
            results = json.load(f)

        if not results:
            print("⚠️ Results file is empty")
            return {"error": "Results file is empty"}

        return results
    except json.JSONDecodeError as e:
        error_msg = f"Invalid JSON in results file: {str(e)}"
        print(f"❌ {error_msg}")
        return {"error": error_msg}
    except Exception as e:
        error_msg = f"Error loading results: {str(e)}"
        print(f"❌ {error_msg}")
        return {"error": error_msg}


@handle_exception
def render_markdown_report(queries: List[Dict[str, Any]]) -> str:
    """Render a comprehensive markdown report with business risk assessment"""
    print("📝 Generating markdown report...")

    # Generate risk report
    risk_report = generate_risk_report(queries)

    # Start building the report
    report_content = f"""# DriftBuddy Security Analysis Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Total Findings:** {risk_report['total_findings']}

## Executive Summary

This report provides a comprehensive security analysis of your infrastructure as code (IaC) using the Impact × Likelihood business risk assessment methodology.

### Key Findings
- **Critical Business Risk:** {risk_report['critical_findings']} findings
- **High Business Risk:** {risk_report['high_findings']} findings
- **Medium Business Risk:** {risk_report['medium_findings']} findings
- **Low Business Risk:** {risk_report['low_findings']} findings
- **Minimal Business Risk:** {risk_report['minimal_findings']} findings

### Financial Impact
**Total Estimated Cost of Inaction:** {risk_report['total_estimated_cost']}

## Detailed Analysis by Business Risk Level
"""

    # Group queries by business risk level
    risk_levels = ["Critical", "High", "Medium", "Low", "Minimal"]
    queries_by_risk: Dict[str, List[Dict[str, Any]]] = {}

    for query in queries:
        files = query.get("files", [])
        if files:
            # Get the highest risk level for this query
            max_risk = "Minimal"
            for file_finding in files:
                finding = {
                    "query_name": query.get("query_name", "Unknown Query"),
                    "severity": query.get("severity", "UNKNOWN"),
                    "description": query.get("description", "No description available"),
                }
                risk_assessment = RiskMatrix.assess_risk(finding["query_name"], finding["severity"], finding["description"])
                risk_level = risk_assessment.business_risk.value[1]  # Get the string value

                # Determine priority order
                risk_priority = {
                    "Critical": 0,
                    "High": 1,
                    "Medium": 2,
                    "Low": 3,
                    "Minimal": 4,
                }
                if risk_priority[risk_level] < risk_priority[max_risk]:
                    max_risk = risk_level

            if max_risk not in queries_by_risk:
                queries_by_risk[max_risk] = []
            queries_by_risk[max_risk].append(query)

    # Process queries by business risk level
    for risk_level in risk_levels:
        if risk_level in queries_by_risk:
            queries_in_risk = queries_by_risk[risk_level]
            report_content += f"\n### {risk_level} Business Risk ({len(queries_in_risk)} queries)\n\n"

            for query in queries_in_risk:
                query_name = query.get("query_name", "Unknown Query")
                severity = query.get("severity", "UNKNOWN")
                description = query.get("description", "No description available")
                files = query.get("files", [])

                # Get risk assessment for this query
                risk_assessment = RiskMatrix.assess_risk(query_name, severity, description)

                report_content += f"#### {query_name}\n\n"
                report_content += f"**Technical Severity:** {severity}\n\n"
                report_content += f"**Business Risk Assessment:**\n"
                report_content += f"- **Impact:** {risk_assessment.impact.value} - "
                report_content += f"{risk_assessment.impact_description}\n"
                report_content += f"- **Likelihood:** {risk_assessment.likelihood.value} - "
                report_content += f"{risk_assessment.likelihood_description}\n"
                report_content += f"- **Business Risk:** {risk_assessment.business_risk.value}\n"
                report_content += f"- **Remediation Priority:** {risk_assessment.remediation_priority}\n"
                report_content += f"- **Estimated Cost:** {risk_assessment.cost_estimate}\n"
                report_content += f"- **Time to Fix:** {risk_assessment.time_to_fix}\n\n"
                report_content += f"**Business Context:** {risk_assessment.business_context}\n\n"
                report_content += f"**Description:** {description}\n\n"

                if files:
                    report_content += "**Affected Files:**\n\n"
                    for file_finding in files:
                        file_name = file_finding.get("file_name", "Unknown file")
                        line_number = file_finding.get("line", "Unknown line")
                        issue = file_finding.get("issue", "No issue description")

                        report_content += f"- **{file_name}:{line_number}**\n"
                        report_content += f"  - Issue: {issue}\n\n"
                else:
                    report_content += "✅ No security issues found for this query.\n\n"

    # Add recommendations section
    report_content += f"""
## Remediation Recommendations

### Immediate Action Required (Critical Business Risk)
{risk_report['critical_findings']} findings require immediate attention. These pose the highest business risk and should be addressed within 24 hours.

### High Priority (High Business Risk)
{risk_report['high_findings']} findings should be addressed within 1-3 days. These represent significant business risk.

### Medium Priority (Medium Business Risk)
{risk_report['medium_findings']} findings should be addressed within 1-2 weeks. These represent moderate business risk.

### Low Priority (Low/Minimal Business Risk)
{risk_report['low_findings'] + risk_report['minimal_findings']} findings can be addressed as part of regular maintenance cycles.

## Cost-Benefit Analysis

**Total Estimated Cost of Inaction:** {risk_report['total_estimated_cost']}

**Recommended Action Plan:**
1. **Week 1:** Address all Critical and High business risk findings
2. **Week 2-3:** Address Medium business risk findings
3. **Month 1:** Address remaining Low and Minimal business risk findings
4. **Ongoing:** Implement preventive measures and regular security reviews

## Risk Mitigation Strategies

### For Critical/High Risk Findings:
- Implement immediate fixes
- Add monitoring and alerting
- Conduct post-remediation testing
- Update security policies and procedures

### For Medium Risk Findings:
- Plan fixes within 1-2 weeks
- Add to security backlog
- Consider automated remediation

### For Low/Minimal Risk Findings:
- Address during regular maintenance
- Consider automated scanning and fixing
- Document for future reference
"""

    return report_content


@handle_exception
def run_steampipe_scan(cloud_provider: str = "aws", scan_type: str = "security") -> Dict[str, Any]:
    """Run Steampipe scan for cloud infrastructure"""
    if not STEAMPIPE_AVAILABLE:
        print("❌ Steampipe integration not available")
        return {"error": "Steampipe integration not available"}

    try:
        steampipe = SteampipeIntegration()

        if scan_type == "security":
            return run_steampipe_security_scan(steampipe, cloud_provider)
        elif scan_type == "drift":
            return run_steampipe_drift_scan(steampipe, cloud_provider)
        else:
            print(f"❌ Unknown scan type: {scan_type}")
            return {"error": f"Unknown scan type: {scan_type}"}

    except Exception as e:
        print(f"❌ Error running Steampipe scan: {str(e)}")
        return {"error": f"Steampipe scan failed: {str(e)}"}


@handle_exception
def run_steampipe_security_scan(steampipe: SteampipeIntegration, cloud_provider: str) -> Dict[str, Any]:
    """Run security-focused Steampipe scan"""
    print(f"🔍 Running Steampipe security scan for {cloud_provider}")

    results: Dict[str, Any] = {
        "provider": cloud_provider,
        "scan_type": "security",
        "timestamp": datetime.now().isoformat(),
        "findings": [],
    }

    # Common security queries
    security_queries = [
        "SELECT * FROM aws_iam_user WHERE password_enabled = true",
        "SELECT * FROM aws_s3_bucket WHERE versioning_enabled = false",
        "SELECT * FROM aws_security_group WHERE ingress_rules_cidr = '0.0.0.0/0'",
    ]

    for query in security_queries:
        try:
            success, query_results = steampipe.query_infrastructure(query, cloud_provider)
            if success and isinstance(query_results, list):
                results["findings"].extend(query_results)
        except Exception as e:
            print(f"⚠️ Error running query: {str(e)}")

    return results


@handle_exception
def run_steampipe_drift_scan(steampipe: SteampipeIntegration, cloud_provider: str) -> Dict[str, Any]:
    """Run drift detection Steampipe scan"""
    print(f"🔍 Running Steampipe drift scan for {cloud_provider}")

    results: Dict[str, Any] = {
        "provider": cloud_provider,
        "scan_type": "drift",
        "timestamp": datetime.now().isoformat(),
        "drift_findings": [],
    }

    # Drift detection queries
    drift_queries = [
        "SELECT * FROM aws_ec2_instance WHERE state_name = 'running'",
        "SELECT * FROM aws_s3_bucket",
        "SELECT * FROM aws_iam_role",
    ]

    for query in drift_queries:
        try:
            success, query_results = steampipe.query_infrastructure(query, cloud_provider)
            if success and isinstance(query_results, list):
                results["drift_findings"].extend(query_results)
        except Exception as e:
            print(f"⚠️ Error running drift query: {str(e)}")

    return results


@handle_exception
def generate_steampipe_report(results: Dict[str, Any], reports_dir: str = "outputs/reports") -> str:
    """Generate Steampipe report with timestamped filename"""
    if not STEAMPIPE_AVAILABLE:
        print("❌ Steampipe integration not available")
        return ""

    try:
        steampipe = SteampipeIntegration()
        filename = generate_timestamped_filename("steampipe_report", "md", reports_dir)
        output_path = os.path.join(reports_dir, filename)

        return steampipe.generate_steampipe_report(results, output_path)
    except Exception as e:
        print(f"❌ Error generating Steampipe report: {str(e)}")
        return ""


@handle_exception
def check_steampipe_installation() -> bool:
    """Check if Steampipe is properly installed and accessible"""
    try:
        steampipe = SteampipeIntegration()
        return steampipe.steampipe_installed
    except Exception as e:
        print(f"❌ Error checking Steampipe installation: {str(e)}")
        return False


@handle_exception
def main() -> None:
    """Main function for testing the core functionality."""
    print("🔍 Testing DriftBuddy core functionality...")

    # Test KICS installation
    print("\n📋 Checking KICS installation...")
    kics_available = check_kics_installation()
    print(f"KICS available: {kics_available}")

    # Test Docker KICS
    print("\n🐳 Checking Docker KICS...")
    docker_kics_available = check_docker_kics()
    print(f"Docker KICS available: {docker_kics_available}")

    # Test Steampipe installation
    print("\n🔧 Checking Steampipe installation...")
    steampipe_available = check_steampipe_installation()
    print(f"Steampipe available: {steampipe_available}")

    print("\n✅ Core functionality test completed")


if __name__ == "__main__":
    main()
