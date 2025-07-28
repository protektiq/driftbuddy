import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import markdown

from driftbuddy.agent.explainer import explain_findings, load_kics_results

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

# LangChain integration flag - will be set to True if imports succeed
LANGCHAIN_AVAILABLE = False


def _import_langchain():
    """Lazy import of LangChain modules to avoid circular imports"""
    global LANGCHAIN_AVAILABLE
    try:
        from .agent.enhanced_agent import EnhancedSecurityAgent, create_enhanced_agent
        from .langchain_integration import (
            DriftBuddyLangChain,
            create_langchain_integration,
        )

        LANGCHAIN_AVAILABLE = True
        return DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent
    except ImportError as e:
        LANGCHAIN_AVAILABLE = False
        print("⚠️ LangChain integration not available. Install langchain dependencies for enhanced AI features.")
        return None, None, None, None


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
    print(f"🔍 Starting DriftBuddy scan of: {scan_path}")

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
                print("⚠️ Local DriftBuddy engine has issues, trying Docker...")
                use_docker = True
        except:
            print("⚠️ Local DriftBuddy engine test failed, trying Docker...")
            use_docker = True

    # Skip the test scan and go directly to using local KICS if available
    if not use_docker:
        print("💡 Using local DriftBuddy engine")
        return run_kics_local(scan_path, output_dir)
    else:
        if not check_docker_kics():
            return {
                "success": False,
                "error": "Neither local DriftBuddy engine nor Docker engine is available",
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
    print(f"🔍 Starting DriftBuddy local scan of: {scan_path}")

    # Ensure output directory exists
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Generate output filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"kics_results_{timestamp}.json")

    def run_kics_command(use_queries_path: bool = True) -> subprocess.CompletedProcess:
        """Run DriftBuddy engine command with optional queries path"""
        cmd = [
            "kics",
            "scan",
            "-p",
            scan_path,
            "-o",
            output_dir,
            "--output-name",
            f"kics_results_{timestamp}.json",
            "--report-formats",
            "json",
        ]

        # Add queries path if available
        config = get_config()
        queries_path = config.get("kics_queries_path")
        if use_queries_path and queries_path and os.path.exists(queries_path):
            cmd.extend(["-q", queries_path])

        # Display DriftBuddy ASCII art logo
        driftbuddy_logo = """
  DDDDDDD   RRRRRRRR   IIIIII  FFFFFFF  TTTTTTT   BBBBBBB   UUU   UUU  DDDDDDD   DDDDDDD   YYYYYYY
  DDDDDDDD  RRRRRRRRR   III    FFFFFF   TTTTTTT   BBBBBBBB  UUU   UUU  DDDDDDDD  DDDDDDDD   YYYYY
  DDD  DDD  RRR   RRR   III    FFF        TTT     BBB   BB  UUU   UUU  DDD  DDD  DDD  DDD    YYY
  DDD  DDD  RRRRRRRRR   III    FFFFFF     TTT     BBBBBBBB  UUU   UUU  DDD  DDD  DDD  DDD    YYY
  DDD  DDD  RRR RRR     III    FFFFFF     TTT     BBBBBBB   UUU   UUU  DDD  DDD  DDD  DDD    YYY
  DDDDDDDD  RRR  RRR    III    FFF        TTT     BBB   BB  UUU   UUU  DDDDDDDD  DDDDDDDD    YYY
  DDDDDDD   RRR   RRR  IIIIII  FFFF       TTT     BBBBBBBB   UUUUUUU   DDDDDDD   DDDDDDD     YYY 
                                                                                                        
    🔍 Infrastructure Security Analysis Tool
    🛡️  Keeping Your Infrastructure as Code Secure
    """
        print(driftbuddy_logo)

        print(f"🔧 Running DriftBuddy engine command: {' '.join(cmd)}")

        # Run with output capture to filter KICS branding
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        # Filter out KICS ASCII art and branding from stdout
        if result.stdout:
            lines = result.stdout.split("\n")
            filtered_lines = []
            skip_ascii_art = False

            for line in lines:
                # Skip lines that are part of the KICS ASCII art logo
                if any(char in line for char in ["M", "L", "K"]) and len(line.strip()) > 10:
                    # This looks like ASCII art, skip it
                    continue
                elif "Scanning with Keeping Infrastructure as Code Secure" in line:
                    # Skip the KICS branding line
                    continue
                elif "Preparing Scan Assets:" in line:
                    # Keep the progress indicator but replace with DriftBuddy branding
                    filtered_lines.append("Preparing DriftBuddy scan assets...")
                    continue
                else:
                    filtered_lines.append(line)

            # Reconstruct stdout without the KICS branding
            result.stdout = "\n".join(filtered_lines)

        return result

    try:
        print("🚀 Running DriftBuddy locally...")
        result = run_kics_command()

        # Display filtered output
        if result.stdout:
            print(result.stdout)

        if result.returncode == 0:
            print(f"✅ DriftBuddy local scan completed successfully")
            print(f"📄 Results saved to: {output_file}")
            return {
                "success": True,
                "output_file": output_file,
                "stdout": result.stdout,
            }
        elif result.returncode == 60:
            # Exit code 60 usually means no files found or no issues detected
            print(f"ℹ️ DriftBuddy scan completed with exit code 60 (no issues found)")
            print(f"📄 Results saved to: {output_file}")
            return {
                "success": True,
                "output_file": output_file,
                "stdout": result.stdout,
                "no_issues": True,
            }
        else:
            # Try without queries path if first attempt failed
            print(f"⚠️ First DriftBuddy attempt failed (exit code: {result.returncode}), trying without queries path...")
            result = run_kics_command(use_queries_path=False)

            if result.returncode == 0:
                print(f"✅ DriftBuddy local scan completed successfully (without queries path)")
                print(f"📄 Results saved to: {output_file}")
                return {
                    "success": True,
                    "output_file": output_file,
                    "stdout": result.stdout,
                }
            elif result.returncode == 60:
                print(f"ℹ️ DriftBuddy scan completed with exit code 60 (no issues found)")
                print(f"📄 Results saved to: {output_file}")
                return {
                    "success": True,
                    "output_file": output_file,
                    "stdout": result.stdout,
                    "no_issues": True,
                }
            else:
                print(f"❌ DriftBuddy local scan failed with exit code: {result.returncode}")
                if result.stderr:
                    print(f"Error: {result.stderr}")
                return {
                    "success": False,
                    "error": result.stderr or f"Exit code: {result.returncode}",
                    "exit_code": result.returncode,
                }
    except subprocess.TimeoutExpired:
        error_msg = "DriftBuddy local scan timed out after 5 minutes"
        print(f"❌ {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        error_msg = f"Error running DriftBuddy local scan: {str(e)}"
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

    # Common security queries - Fixed based on actual Steampipe schema
    security_queries = [
        "SELECT name, attached_policy_arns, inline_policies FROM aws_iam_user WHERE name LIKE '%admin%'",
        "SELECT name, versioning_enabled FROM aws_s3_bucket WHERE versioning_enabled = false",
        "SELECT name, description, vpc_id FROM aws_vpc_security_group WHERE description = '' OR description IS NULL",
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

    # Drift detection queries - Fixed based on actual Steampipe schema
    drift_queries = [
        "SELECT instance_id, instance_type, state FROM aws_ec2_instance WHERE state = 'running'",
        "SELECT name, region FROM aws_s3_bucket",
        "SELECT name, attached_policy_arns FROM aws_iam_role",
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
    """Main function for DriftBuddy security scanning."""
    parser = argparse.ArgumentParser(
        description="DriftBuddy - Infrastructure Configuration Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python driftbuddy.py --scan-path ./terraform/ --output-format html
  python driftbuddy.py --scan-path ./k8s/ --enable-ai --output-format md
  python driftbuddy.py --scan-path . --all --reports-dir ./security-reports
        """,
    )

    parser.add_argument(
        "--scan-path",
        default=".",
        help="Path to scan for infrastructure files (default: current directory)",
    )
    parser.add_argument(
        "--output-format",
        choices=["html", "md", "json", "all"],
        default="html",
        help="Output format for reports (default: html)",
    )
    parser.add_argument(
        "--enable-ai",
        action="store_true",
        help="Enable AI-powered analysis and recommendations",
    )
    parser.add_argument(
        "--reports-dir",
        default="outputs/reports",
        help="Directory to save reports (default: outputs/reports)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all available scans (KICS + Steampipe if available)",
    )
    parser.add_argument("--kics-only", action="store_true", help="Run only KICS scan")
    parser.add_argument(
        "--steampipe-only",
        action="store_true",
        help="Run only Steampipe scan (requires cloud credentials)",
    )
    parser.add_argument(
        "--cloud-provider",
        choices=["aws", "azure", "gcp"],
        default="aws",
        help="Cloud provider for Steampipe scans (default: aws)",
    )
    parser.add_argument(
        "--enable-langchain",
        action="store_true",
        help="Enable LangChain-enhanced analysis with advanced AI capabilities",
    )
    parser.add_argument(
        "--langchain-only",
        action="store_true",
        help="Run only LangChain-enhanced analysis (requires previous scan results)",
    )
    parser.add_argument(
        "--knowledge-base",
        action="store_true",
        help="Create and use knowledge base for enhanced analysis",
    )
    parser.add_argument("--test", action="store_true", help="Run functionality test only")

    args = parser.parse_args()

    # If test mode is requested, run the functionality test
    if args.test:
        print("🔍 Testing DriftBuddy - Complete Tool Suite")
        print("=" * 50)
        print("DriftBuddy consists of:")
        print("  🔍 KICS - Infrastructure as Code security scanning")
        print("  ☁️  Steampipe - Cloud infrastructure security scanning")
        print("  🤖 ChatGPT - AI-powered explanations and business risk assessment")
        print("  🔗 LangChain - Advanced AI capabilities with memory and chains")
        print("=" * 50)

        # Test KICS installation
        print("\n📋 Testing KICS (Infrastructure as Code Scanner)...")
        kics_available = check_kics_installation()
        print(f"✅ KICS available: {kics_available}")

        # Test Docker KICS
        print("\n🐳 Testing Docker KICS (Alternative)...")
        docker_kics_available = check_docker_kics()
        print(f"✅ Docker KICS available: {docker_kics_available}")

        # Test Steampipe installation
        print("\n🔧 Testing Steampipe (Cloud Infrastructure Scanner)...")
        steampipe_available = check_steampipe_installation()
        print(f"✅ Steampipe available: {steampipe_available}")

        # Test ChatGPT/OpenAI integration
        print("\n🤖 Testing ChatGPT/OpenAI Integration...")
        try:
            from .config import get_config
            config = get_config()
            openai_key = config.get("openai_api_key")
            if openai_key and openai_key != "your-api-key-here":
                print("✅ OpenAI API key configured")
                print(f"✅ Model: {config.get('openai_model', 'o4-mini')}")
                print(f"✅ Max tokens: {config.get('openai_max_tokens', 1200)}")
            else:
                print("⚠️  OpenAI API key not configured")
                print("💡 Set OPENAI_API_KEY environment variable for AI features")
        except Exception as e:
            print(f"❌ OpenAI configuration error: {str(e)}")

        # Test LangChain integration
        print("\n🔗 Testing LangChain Integration...")
        try:
            langchain_modules = _import_langchain()
            if langchain_modules[0] is not None:  # DriftBuddyLangChain
                print("✅ LangChain integration available")
                print("✅ Enhanced AI capabilities enabled")
                print("✅ Memory and chain features available")
            else:
                print("⚠️  LangChain not available")
                print("💡 Install: pip install langchain>=0.1.0 langchain-openai>=0.1.0 langchain-community>=0.1.0")
        except Exception as e:
            print(f"❌ LangChain integration error: {str(e)}")

        # Test configuration
        print("\n⚙️  Testing Configuration...")
        try:
            from .config import get_config
            config = get_config()
            print(f"✅ Configuration loaded successfully")
            print(f"✅ Output directory: {config.get('output_dir', 'outputs/reports')}")
            print(f"✅ AI explanations: {config.get('enable_ai_explanations', True)}")
            print(f"✅ Business risk assessment: {config.get('enable_business_risk_assessment', True)}")
        except Exception as e:
            print(f"❌ Configuration error: {str(e)}")

        # Test risk assessment
        print("\n📊 Testing Risk Assessment Engine...")
        try:
            from .risk_assessment import RiskMatrix, ImpactLevel, LikelihoodLevel
            test_impact = ImpactLevel.MODERATE
            test_likelihood = LikelihoodLevel.LIKELY
            risk_score = RiskMatrix.calculate_business_risk_score(test_impact, test_likelihood)
            risk_level = RiskMatrix.determine_business_risk_level(risk_score)
            print(f"✅ Risk assessment engine working")
            print(f"✅ Sample calculation: {test_impact.value[0]} × {test_likelihood.value[0]} = {risk_score}")
            print(f"✅ Risk level: {risk_level.value[1]} ({risk_level.value[0]})")
        except Exception as e:
            print(f"❌ Risk assessment error: {str(e)}")

        # Summary
        print("\n" + "=" * 50)
        print("🎯 DriftBuddy Tool Suite Test Results:")
        print(f"  🔍 KICS: {'✅ Available' if kics_available else '❌ Not Available'}")
        print(f"  ☁️  Steampipe: {'✅ Available' if steampipe_available else '❌ Not Available'}")
        print(f"  🤖 ChatGPT: {'✅ Configured' if openai_key and openai_key != 'your-api-key-here' else '⚠️  Not Configured'}")
        print(f"  🔗 LangChain: {'✅ Available' if langchain_modules[0] is not None else '⚠️  Not Available'}")
        print("=" * 50)
        
        if kics_available and steampipe_available:
            print("🎉 All core tools are available! DriftBuddy is ready for comprehensive security scanning.")
        elif kics_available:
            print("✅ KICS is available. DriftBuddy can perform infrastructure security scanning.")
        else:
            print("⚠️  Core scanning tools not available. Please install KICS for basic functionality.")
        
        print("\n✅ Complete DriftBuddy tool suite test completed")
        return

    # Validate scan path
    scan_path = Path(args.scan_path)
    if not scan_path.exists():
        print(f"❌ Error: Scan path '{args.scan_path}' does not exist")
        sys.exit(1)

    print(f"🔍 Starting DriftBuddy security scan...")
    print(f"📁 Scan path: {scan_path.absolute()}")
    print(f"📊 Output format: {args.output_format}")
    print(f"🤖 AI analysis: {'Enabled' if args.enable_ai else 'Disabled'}")
    print(f"🔗 LangChain analysis: {'Enabled' if args.enable_langchain else 'Disabled'}")

    # Ensure reports directory exists
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    all_results = []
    kics_results = None
    steampipe_results = None

    # Run KICS scan
    if args.all or args.kics_only or not args.steampipe_only:
        print("\n🔍 Running DriftBuddy security scan...")
        try:
            kics_results = run_kics(str(scan_path), str(reports_dir))
            if kics_results and kics_results.get("success"):
                # Load the actual results from the file
                output_file = kics_results.get("output_file")
                if output_file and os.path.exists(output_file):
                    loaded_results = load_kics_results_safe(output_file)
                    if "error" not in loaded_results:
                        # Extract queries from the loaded results
                        queries = loaded_results.get("queries", [])
                        if queries:
                            kics_results = {"queries": queries, "source": "kics"}
                            all_results.append(kics_results)
                            print(f"✅ DriftBuddy scan completed - Found {len(queries)} findings")
                        else:
                            print("✅ DriftBuddy scan completed - No security issues found")
                    else:
                        print(f"⚠️ DriftBuddy scan completed but failed to load results: {loaded_results.get('error')}")
                else:
                    print("⚠️ DriftBuddy scan completed but no results file found")
            else:
                error_msg = kics_results.get("error", "Unknown error") if kics_results else "No results returned"
                print(f"❌ DriftBuddy scan failed: {error_msg}")
        except Exception as e:
            print(f"❌ DriftBuddy scan failed: {str(e)}")

    # Run Steampipe scan if available and requested
    if (args.all or args.steampipe_only) and STEAMPIPE_AVAILABLE:
        print(f"\n🔍 Running Steampipe scan for {args.cloud_provider}...")
        try:
            steampipe_results = run_steampipe_scan(args.cloud_provider, "security")
            if steampipe_results and steampipe_results.get("findings"):
                # Convert Steampipe findings to the expected format for report generation
                steampipe_queries = []
                for finding in steampipe_results.get("findings", []):
                    # Convert each finding to a query-like format for consistency
                    # Create a file entry that the AI system expects
                    file_entry = {"file_name": "cloud_infrastructure", "line": 1, "issue": f"Cloud security issue: {finding}", "severity": "HIGH"}

                    # Create a more descriptive query name based on the finding content
                    query_name = "Cloud Security Finding"
                    if "s3" in str(finding).lower():
                        query_name = "S3 Bucket Security Issue"
                    elif "iam" in str(finding).lower():
                        query_name = "IAM Security Issue"
                    elif "security_group" in str(finding).lower():
                        query_name = "Security Group Configuration Issue"
                    elif "ec2" in str(finding).lower():
                        query_name = "EC2 Instance Security Issue"
                    elif "rds" in str(finding).lower():
                        query_name = "RDS Database Security Issue"

                    query_entry = {
                        "query_name": query_name,
                        "severity": "HIGH",  # Default severity for cloud findings
                        "category": "Cloud Infrastructure Security",
                        "description": f"Cloud infrastructure security issue detected in {args.cloud_provider.upper()}: {finding}",
                        "platform": "Cloud",
                        "cloud_provider": args.cloud_provider,
                        "file": "cloud_infrastructure",
                        "line": 1,
                        "issue_type": "CloudSecurityIssue",
                        "key_expected_value": "Secure configuration",
                        "key_actual_value": "Insecure configuration detected",
                        "remediation": "Review and fix cloud security configuration",
                        "remediation_type": "configuration",
                        "cloud_finding": finding,  # Store the original finding
                        "files": [file_entry],  # Add files array for AI explanation compatibility
                    }
                    steampipe_queries.append(query_entry)

                # Add Steampipe results in the expected format
                steampipe_formatted_results = {
                    "scan_type": "steampipe",
                    "provider": args.cloud_provider,
                    "timestamp": datetime.now().isoformat(),
                    "queries": steampipe_queries,
                }
                steampipe_results = steampipe_formatted_results
                all_results.append(steampipe_results)
                print(f"✅ Steampipe scan completed - Found {len(steampipe_results.get('findings', []))} findings")
            else:
                print("⚠️ Steampipe scan completed but no results found")
        except Exception as e:
            print(f"❌ Steampipe scan failed: {str(e)}")

    # Generate reports
    if all_results:
        print(f"\n📊 Generating reports...")

        # Generate markdown report
        if args.output_format in ["md", "all"]:
            try:
                md_report = render_markdown_report(all_results)
                md_filename = generate_timestamped_filename("security_report", "md", str(reports_dir))
                with open(md_filename, "w", encoding="utf-8") as f:
                    f.write(md_report)
                print(f"✅ Markdown report saved: {md_filename}")
            except Exception as e:
                print(f"❌ Failed to generate markdown report: {str(e)}")

        # AI analysis if enabled
        ai_explanations = None
        if args.enable_ai:
            print("\n🤖 Running AI analysis...")
            try:
                # Extract all queries from results
                all_queries = []
                for result in all_results:
                    if "queries" in result:
                        all_queries.extend(result["queries"])

                if all_queries:
                    # Get AI explanations for all findings (returns markdown for each query)
                    ai_explanations_list = explain_findings(all_queries, return_per_query=True)
                    # Attach AI explanation to each query
                    for query, ai_md in zip(all_queries, ai_explanations_list):
                        query["ai_explanation"] = ai_md
                else:
                    print("ℹ️ No security findings to analyze - skipping AI analysis")
            except Exception as e:
                print(f"❌ AI analysis failed: {str(e)}")

        # LangChain enhanced analysis if enabled
        if args.enable_langchain:
            print("\n🔗 Running LangChain enhanced analysis...")
            try:
                # Try to import LangChain modules
                DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent = _import_langchain()

                if all([DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent]):
                    # Run enhanced analysis with LangChain
                    enhanced_results = run_enhanced_analysis_with_langchain(
                        kics_results=kics_results, steampipe_results=steampipe_results, enable_ai=args.enable_ai, reports_dir=str(reports_dir)
                    )

                    if enhanced_results:
                        print("✅ LangChain enhanced analysis completed")

                        # Add enhanced analysis to the results
                        if "enhanced_analysis" in enhanced_results:
                            all_results.append({"source": "langchain_enhanced", "enhanced_analysis": enhanced_results["enhanced_analysis"]})
                    else:
                        print("ℹ️ No enhanced analysis results available")
                else:
                    print("⚠️ LangChain integration not available - skipping enhanced analysis")
            except Exception as e:
                print(f"❌ LangChain enhanced analysis failed: {str(e)}")

        # Generate HTML report
        if args.output_format in ["html", "all"]:
            try:
                # Extract all queries from results
                all_queries = []
                for result in all_results:
                    if "queries" in result:
                        all_queries.extend(result["queries"])

                if all_queries:
                    # Generate comprehensive risk report
                    risk_report = generate_risk_report(all_queries)

                    # Create comprehensive HTML report
                    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>DriftBuddy Security Report</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .executive-summary {{ background: #fff; padding: 20px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .risk-cards {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
        .risk-card {{ 
            flex: 1; min-width: 120px; padding: 15px; border-radius: 8px; text-align: center; color: white; font-weight: bold;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }}
        .critical {{ background: linear-gradient(135deg, #ff6b6b, #ff5252); }}
        .high {{ background: linear-gradient(135deg, #ff8c42, #ff7043); }}
        .medium {{ background: linear-gradient(135deg, #42a5f5, #2196f3); }}
        .low {{ background: linear-gradient(135deg, #66bb6a, #4caf50); }}
        .minimal {{ background: linear-gradient(135deg, #9e9e9e, #757575); }}
        .financial-impact {{ background: #ffebee; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f44336; }}
        .risk-matrix {{ margin: 20px 0; }}
        .risk-matrix table {{ border-collapse: collapse; width: 100%; }}
        .risk-matrix th, .risk-matrix td {{ border: 1px solid #ddd; padding: 8px; text-align: center; }}
        .risk-matrix th {{ background: #f5f5f5; font-weight: bold; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #ff6b6b; background: #fff5f5; border-radius: 4px; }}
        .critical-finding {{ border-left-color: #ff6b6b; }}
        .high-finding {{ border-left-color: #ff8c42; }}
        .medium-finding {{ border-left-color: #42a5f5; }}
        .low-finding {{ border-left-color: #66bb6a; }}
        .minimal-finding {{ border-left-color: #9e9e9e; }}
        .metrics {{ display: flex; gap: 20px; margin: 20px 0; }}
        .metric {{ flex: 1; text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }}
        .metric h3 {{ margin: 0; color: #333; }}
        .metric p {{ margin: 5px 0; font-size: 24px; font-weight: bold; color: #666; }}
        .risk-section {{ background: #fffde7; border-left: 6px solid #ffe082; padding: 16px; margin: 20px 0 10px 0; border-radius: 6px; }}
        .ai-section {{ background: #e3f2fd; border-left: 6px solid #64b5f6; padding: 16px; margin: 10px 0 20px 0; border-radius: 6px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 DriftBuddy Security Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Scan Path:</strong> {scan_path.absolute()}</p>
    </div>
    
    <div class="executive-summary">
        <h2>📊 Executive Summary</h2>
        <p>This report contains AI-powered explanations of security findings with business risk assessment.</p>
        
        <div class="metrics">
            <div class="metric">
                <h3>Total Queries</h3>
                <p>{risk_report.get('total_findings', 0)}</p>
            </div>
            <div class="metric">
                <h3>Findings with Issues</h3>
                <p>{risk_report.get('total_findings', 0)}</p>
            </div>
        </div>
        
        <div class="risk-cards">
            <div class="risk-card critical">
                <h3>Critical</h3>
                <p>{risk_report.get('critical_findings', 0)}</p>
            </div>
            <div class="risk-card high">
                <h3>High</h3>
                <p>{risk_report.get('high_findings', 0)}</p>
            </div>
            <div class="risk-card medium">
                <h3>Medium</h3>
                <p>{risk_report.get('medium_findings', 0)}</p>
            </div>
            <div class="risk-card low">
                <h3>Low</h3>
                <p>{risk_report.get('low_findings', 0)}</p>
            </div>
            <div class="risk-card minimal">
                <h3>Minimal</h3>
                <p>{risk_report.get('minimal_findings', 0)}</p>
            </div>
        </div>
    </div>
    
    <div class="financial-impact">
        <h2>💰 Financial Impact</h2>
        <p><strong>Total Estimated Cost of Inaction:</strong> {risk_report.get('total_estimated_cost', '$0')}</p>
        <p><strong>Priority:</strong> Focus on Critical and High business risk findings first</p>
    </div>
    
    <div class="risk-matrix">
        <h2>📋 Risk Matrix (Impact × Likelihood = Business Risk Score)</h2>
        <table>
            <tr>
                <th>Impact/Likelihood</th>
                <th>Almost Certain (5)</th>
                <th>Likely (4)</th>
                <th>Possible (3)</th>
                <th>Unlikely (2)</th>
                <th>Rare (1)</th>
            </tr>
            <tr>
                <td><strong>Catastrophic (5)</strong></td>
                <td class="critical">Critical (25)</td>
                <td class="critical">Critical (20)</td>
                <td class="high">High (15)</td>
                <td class="medium">Medium (10)</td>
                <td class="low">Low (5)</td>
            </tr>
            <tr>
                <td><strong>Major (4)</strong></td>
                <td class="critical">Critical (20)</td>
                <td class="high">High (16)</td>
                <td class="high">High (12)</td>
                <td class="medium">Medium (8)</td>
                <td class="low">Low (4)</td>
            </tr>
            <tr>
                <td><strong>Moderate (3)</strong></td>
                <td class="high">High (15)</td>
                <td class="medium">Medium (12)</td>
                <td class="medium">Medium (9)</td>
                <td class="low">Low (6)</td>
                <td class="minimal">Minimal (3)</td>
            </tr>
            <tr>
                <td><strong>Minor (2)</strong></td>
                <td class="medium">Medium (10)</td>
                <td class="low">Low (8)</td>
                <td class="low">Low (6)</td>
                <td class="minimal">Minimal (4)</td>
                <td class="minimal">Minimal (2)</td>
            </tr>
            <tr>
                <td><strong>Insignificant (1)</strong></td>
                <td class="low">Low (5)</td>
                <td class="minimal">Minimal (4)</td>
                <td class="minimal">Minimal (3)</td>
                <td class="minimal">Minimal (2)</td>
                <td class="minimal">Minimal (1)</td>
            </tr>
        </table>
    </div>
    
    <h2>🔍 Detailed Findings</h2>
"""

                    # Add detailed findings with risk assessment and AI explanation
                    for query in all_queries:
                        risk_assessment = query.get("risk_assessment", {})
                        severity = query.get("severity", "medium").lower()
                        risk_level = risk_assessment.get("business_risk", "medium").lower()

                        html_content += f"""
    <div class="finding {risk_level}-finding">
        <h3>{query.get('query_name', 'Unknown')}</h3>
        <p><strong>Technical Severity:</strong> {query.get('severity', 'Unknown')}</p>
        <p><strong>Business Risk:</strong> {risk_assessment.get('business_risk', 'Unknown')}</p>
        <p><strong>Description:</strong> {query.get('description', 'No description available')}</p>
        <div class='risk-section'>
            <strong>Business Risk Assessment</strong><br>
            <b>Impact:</b> {risk_assessment.get('impact', 'Unknown')} - {risk_assessment.get('impact_description', 'Unknown')}<br>
            <b>Likelihood:</b> {risk_assessment.get('likelihood', 'Unknown')} - {risk_assessment.get('likelihood_description', 'Unknown')}<br>
            <b>Business Risk Score:</b> {risk_assessment.get('business_risk_score', 'Unknown')} (Impact × Likelihood)<br>
            <b>Business Risk Level:</b> {risk_assessment.get('business_risk', 'Unknown')}<br>
            <b>Remediation Priority:</b> {risk_assessment.get('remediation_priority', 'Unknown')}<br>
            <b>Estimated Cost:</b> {risk_assessment.get('cost_estimate', 'Unknown')}<br>
            <b>Time to Fix:</b> {risk_assessment.get('time_to_fix', 'Unknown')}<br>
            <b>Business Context:</b> {risk_assessment.get('business_context', 'No business context available')}<br>
        </div>
"""

                        # Add file information if available
                        files = query.get("files", [])
                        if files:
                            html_content += f"<p><strong>Affected Files:</strong></p><ul>"
                            for file_info in files:
                                file_name = file_info.get("file_name", "Unknown")
                                line_number = file_info.get("line", "Unknown")
                                html_content += f"<li>{file_name}:{line_number}</li>"
                            html_content += "</ul>"

                        # Add AI explanation if available
                        ai_md = query.get("ai_explanation")
                        if ai_md:
                            html_content += f"<div class='ai-section'><strong>🤖 AI Explanation</strong><br>{markdown.markdown(ai_md)}</div>"

                        # Add cloud-specific information if this is a cloud finding
                        if query.get("cloud_provider"):
                            html_content += f"<div class='ai-section'><strong>☁️ Cloud Provider:</strong> {query.get('cloud_provider').upper()}</div>"

                        # Add remediation code if available
                        remediation_code = query.get("remediation_code")
                        if remediation_code:
                            # Convert markdown code block to HTML
                            html_content += f"<div class='ai-section'><strong>Remediation Code</strong><br>{markdown.markdown(remediation_code)}</div>"

                        html_content += "</div>"

                    # Add LangChain enhanced analysis section if available
                    langchain_results = None
                    for result in all_results:
                        if result.get("source") == "langchain_enhanced":
                            langchain_results = result.get("enhanced_analysis")
                            break

                    if langchain_results:
                        html_content += f"""
    <h2>🤖 LangChain Enhanced Analysis</h2>
    <div class="ai-section">
        <h3>Comprehensive Security Analysis</h3>
        <p><strong>Analysis Summary:</strong></p>
        <ul>
"""

                        # Add KICS analysis if available
                        if langchain_results.get("kics_analysis"):
                            html_content += f"<li><strong>KICS Analysis:</strong> Enhanced analysis of {len(langchain_results.get('kics_analysis', {}).get('original_kics_results', {}).get('queries', []))} KICS findings</li>"

                        # Add Steampipe analysis if available
                        if langchain_results.get("steampipe_analysis"):
                            html_content += f"<li><strong>Steampipe Analysis:</strong> Enhanced analysis of {len(langchain_results.get('steampipe_analysis', {}).get('original_steampipe_results', {}).get('queries', []))} Steampipe findings</li>"

                        # Add comprehensive recommendations
                        if langchain_results.get("comprehensive_recommendations"):
                            recommendations = langchain_results.get("comprehensive_recommendations")
                            if isinstance(recommendations, dict) and "output" in recommendations:
                                recommendations_text = recommendations["output"]
                            else:
                                recommendations_text = str(recommendations)

                            html_content += f"""
        </ul>
        <h4>Comprehensive Security Recommendations</h4>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
            {markdown.markdown(recommendations_text)}
        </div>
    </div>
"""
                        else:
                            html_content += "</ul></div>"

                    html_content += """
</body>
</html>
"""

                    html_filename = generate_timestamped_filename("security_report", "html", str(reports_dir))
                    with open(html_filename, "w", encoding="utf-8") as f:
                        f.write(html_content)
                    print(f"✅ HTML report saved: {html_filename}")
                else:
                    # Create a simple "no issues" report
                    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>DriftBuddy Security Report</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; text-align: center; }}
        .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .success {{ background: #e8f5e8; padding: 40px; border-radius: 8px; border: 2px solid #4caf50; }}
        .success h2 {{ color: #2e7d32; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 DriftBuddy Security Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Scan Path:</strong> {scan_path.absolute()}</p>
    </div>
    
    <div class="success">
        <h2>✅ No Security Issues Found!</h2>
        <p>Your infrastructure appears to follow security best practices. 🛡️</p>
        <p>Total findings: 0</p>
    </div>
</body>
</html>
"""
                    html_filename = generate_timestamped_filename("security_report", "html", str(reports_dir))
                    with open(html_filename, "w", encoding="utf-8") as f:
                        f.write(html_content)
                    print(f"✅ HTML report saved: {html_filename}")
            except Exception as e:
                print(f"❌ Failed to generate HTML report: {str(e)}")

        print(f"\n✅ Scan completed! Reports saved in: {reports_dir.absolute()}")
    else:
        print("\n✅ Scan completed - No security issues found!")
        print("🎉 Your infrastructure appears to follow security best practices!")


# LangChain Integration Functions


@handle_exception
def run_enhanced_analysis_with_langchain(
    kics_results: Optional[Dict[str, Any]] = None,
    steampipe_results: Optional[Dict[str, Any]] = None,
    enable_ai: bool = True,
    reports_dir: str = "outputs/reports",
) -> Dict[str, Any]:
    """Run enhanced analysis using LangChain integration"""
    if not LANGCHAIN_AVAILABLE:
        print("❌ LangChain integration not available")
        return {}

    print("🚀 Running enhanced analysis with LangChain...")

    try:
        # Lazy import LangChain modules
        DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent = _import_langchain()
        if not all([DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent]):
            print("❌ Failed to import LangChain modules")
            return {}

        # Initialize enhanced agent
        agent = create_enhanced_agent()

        # Run comprehensive analysis
        analysis_results = agent.run_comprehensive_analysis(kics_results=kics_results, steampipe_results=steampipe_results)

        # Generate enhanced report
        report_path = agent.generate_security_report(analysis_results)

        print(f"✅ Enhanced analysis completed. Report saved to: {report_path}")
        return analysis_results

    except Exception as e:
        print(f"❌ Error in enhanced analysis: {str(e)}")
        return {}


@handle_exception
def run_langchain_kics_analysis(kics_results: Dict[str, Any], reports_dir: str = "outputs/reports") -> Dict[str, Any]:
    """Run LangChain-enhanced KICS analysis"""
    if not LANGCHAIN_AVAILABLE:
        print("❌ LangChain integration not available")
        return kics_results

    print("🔍 Running LangChain-enhanced KICS analysis...")

    try:
        # Lazy import LangChain modules
        DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent = _import_langchain()
        if not all([DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent]):
            print("❌ Failed to import LangChain modules")
            return kics_results

        langchain_integration = create_langchain_integration()
        enhanced_results = langchain_integration.enhance_kics_analysis(kics_results)

        # Save enhanced results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(reports_dir, f"langchain_kics_analysis_{timestamp}.json")
        langchain_integration.save_analysis_to_file(enhanced_results, output_path)

        return enhanced_results

    except Exception as e:
        print(f"❌ Error in LangChain KICS analysis: {str(e)}")
        return kics_results


@handle_exception
def run_langchain_steampipe_analysis(steampipe_results: Dict[str, Any], reports_dir: str = "outputs/reports") -> Dict[str, Any]:
    """Run LangChain-enhanced Steampipe analysis"""
    if not LANGCHAIN_AVAILABLE:
        print("❌ LangChain integration not available")
        return steampipe_results

    print("🔍 Running LangChain-enhanced Steampipe analysis...")

    try:
        # Lazy import LangChain modules
        DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent = _import_langchain()
        if not all([DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent]):
            print("❌ Failed to import LangChain modules")
            return steampipe_results

        langchain_integration = create_langchain_integration()
        enhanced_results = langchain_integration.enhance_steampipe_analysis(steampipe_results)

        # Save enhanced results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(reports_dir, f"langchain_steampipe_analysis_{timestamp}.json")
        langchain_integration.save_analysis_to_file(enhanced_results, output_path)

        return enhanced_results

    except Exception as e:
        print(f"❌ Error in LangChain Steampipe analysis: {str(e)}")
        return steampipe_results


@handle_exception
def create_knowledge_base_from_documents(documents: List[str], reports_dir: str = "outputs/reports") -> bool:
    """Create a knowledge base from security documents"""
    if not LANGCHAIN_AVAILABLE:
        print("❌ LangChain integration not available")
        return False

    print("📚 Creating knowledge base from documents...")

    try:
        # Lazy import LangChain modules
        DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent = _import_langchain()
        if not all([DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent]):
            print("❌ Failed to import LangChain modules")
            return False

        from langchain.schema import Document

        # Convert strings to Document objects
        docs = [Document(page_content=doc) for doc in documents]

        # Initialize enhanced agent and create knowledge base
        agent = create_enhanced_agent()
        agent.create_knowledge_base(docs)

        print("✅ Knowledge base created successfully")
        return True

    except Exception as e:
        print(f"❌ Error creating knowledge base: {str(e)}")
        return False


@handle_exception
def query_knowledge_base(query: str) -> str:
    """Query the knowledge base for security information"""
    if not LANGCHAIN_AVAILABLE:
        return "LangChain integration not available"

    try:
        # Lazy import LangChain modules
        DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent = _import_langchain()
        if not all([DriftBuddyLangChain, create_langchain_integration, EnhancedSecurityAgent, create_enhanced_agent]):
            return "Failed to import LangChain modules"

        agent = create_enhanced_agent()
        return agent.query_knowledge_base(query)

    except Exception as e:
        return f"Error querying knowledge base: {str(e)}"


if __name__ == "__main__":
    main()
