import subprocess
import os
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime
from agent.explainer import load_kics_results, explain_findings
from typing import Dict
from .config import get_config
from .exceptions import DriftBuddyError, handle_exception
from .risk_assessment import generate_risk_report, RiskMatrix

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
def generate_timestamped_filename(base_name, extension, reports_dir="outputs/reports"):
    """Generate a timestamped filename with driftbuddy prefix in the specified directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"driftbuddy_{base_name}_{timestamp}.{extension}"
    
    # Ensure the reports directory exists
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    
    return os.path.join(reports_dir, filename)

@handle_exception
def check_kics_installation():
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
def check_docker_kics():
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
            capture_output=True, text=True, timeout=60
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
def validate_scan_path(scan_path):
    """Validate that the scan path exists and contains relevant files"""
    if not os.path.exists(scan_path):
        print(f"❌ Scan path does not exist: {scan_path}")
        return False
    
    if not os.path.isdir(scan_path):
        print(f"❌ Scan path is not a directory: {scan_path}")
        return False
    
    # Check for common IaC files
    iac_extensions = ['.tf', '.yaml', '.yml', '.json', '.dockerfile', '.dockerfile', '.bicep']
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
def run_kics(scan_path, output_dir="test_data/output"):
    """Run KICS scan with comprehensive error handling"""
    print(f"🔍 Starting KICS scan of: {scan_path}")
    
    # Validate scan path
    if not validate_scan_path(scan_path):
        return False, "Invalid scan path"
    
    # Create output directory
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"❌ Error creating output directory: {str(e)}")
        return False, f"Failed to create output directory: {str(e)}"
    
    # Check if Docker is preferred or if local KICS is available
    use_docker = not check_kics_installation()
    
    # If local KICS has issues with queries, try Docker
    if not use_docker:
        # Test if local KICS works by running a quick test
        test_cmd = ["kics", "scan", "--help"]
        try:
            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print("⚠️ Local KICS has issues, trying Docker...")
                use_docker = True
        except:
            print("⚠️ Local KICS test failed, trying Docker...")
            use_docker = True
    
    # Force Docker usage if local KICS has query issues
    if not use_docker:
        print("🔍 Testing local KICS query availability...")
        test_scan_cmd = ["kics", "scan", "-p", str(scan_path), "--output-path", str(output_dir), "--output-name", "test", "--report-formats", "json"]
        try:
            result = subprocess.run(test_scan_cmd, capture_output=True, text=True, timeout=30)
            if "unable to find queries" in result.stderr or result.returncode != 0:
                print("⚠️ Local KICS has query issues, switching to Docker...")
                use_docker = True
        except:
            print("⚠️ Local KICS test scan failed, switching to Docker...")
            use_docker = True
    
    if use_docker:
        if not check_docker_kics():
            return False, "Neither local KICS nor Docker KICS is available"
        return run_kics_docker(scan_path, output_dir)
    else:
        return run_kics_local(scan_path, output_dir)

@handle_exception
def run_kics_docker(scan_path, output_dir):
    """Run KICS scan using Docker"""
    print("🐳 Using KICS Docker image")
    
    # Get absolute paths for Docker volume mounting
    scan_path_abs = os.path.abspath(scan_path)
    output_dir_abs = os.path.abspath(output_dir)
    
    # Build Docker command
    kics_cmd = [
        "docker", "run", "--rm",
        "-v", f"{scan_path_abs}:/path",
        "-v", f"{output_dir_abs}:/output",
        "checkmarx/kics:latest",
        "scan",
        "-p", "/path",
        "-o", "/output",
        "--output-name", "results",
        "--report-formats", "json"
    ]
    
    print(f"🚀 Running: {' '.join(kics_cmd)}")
    
    try:
        result = subprocess.run(kics_cmd, capture_output=True, text=True, timeout=config.settings.kics_timeout)
        
        if result.returncode == 0:
            print(f"✅ KICS Docker scan completed. Results saved to: {output_dir}/results.json")
            return True, f"Scan completed successfully. Results: {output_dir}/results.json"
        else:
            print(f"⚠️ KICS Docker scan completed with warnings. Exit code: {result.returncode}")
            print(f"Stderr: {result.stderr}")
            return True, f"Scan completed with warnings. Results: {output_dir}/results.json"
            
    except subprocess.TimeoutExpired:
        print(f"❌ KICS Docker scan timed out after {config.settings.kics_timeout} seconds")
        return False, "Scan timed out"
    except Exception as e:
        print(f"❌ Error running KICS Docker scan: {str(e)}")
        return False, f"Docker scan failed: {str(e)}"

@handle_exception
def run_kics_local(scan_path, output_dir):
    """Run KICS scan using local installation"""
    print("💻 Using local KICS installation")
    
    def run_kics_command(use_queries_path=True):
        """Helper function to run KICS command with different options"""
        kics_cmd = [
            "kics",
            "scan",
            "-p", str(scan_path),
            "--output-path", str(output_dir),
            "--output-name", "results",
            "--report-formats", "json"
        ]
        
            # Use the queries path from the kics directory if it exists
    kics_queries_path = Path("kics/assets/queries")
    if kics_queries_path.exists():
        kics_cmd.extend(["--queries-path", str(kics_queries_path)])
        print(f"📁 Using KICS queries from: {kics_queries_path}")
    elif use_queries_path and config.settings.kics_queries_path and os.path.exists(config.settings.kics_queries_path):
        kics_cmd.extend(["--queries-path", config.settings.kics_queries_path])
        print(f"📁 Using custom queries path: {config.settings.kics_queries_path}")
    else:
        # Try to create a symlink to the kics queries if they exist
        try:
            if Path("kics/assets/queries").exists():
                # Create assets directory if it doesn't exist
                assets_dir = Path("assets")
                assets_dir.mkdir(exist_ok=True)
                
                # Create symlink from assets/queries to kics/assets/queries
                queries_link = assets_dir / "queries"
                if not queries_link.exists():
                    if os.name == 'nt':  # Windows
                        # On Windows, we need to use junction or copy
                        import shutil
                        shutil.copytree("kics/assets/queries", "assets/queries", dirs_exist_ok=True)
                    else:  # Unix/Linux
                        queries_link.symlink_to(Path("kics/assets/queries").resolve())
                
                if queries_link.exists():
                    kics_cmd.extend(["--queries-path", str(queries_link)])
                    print(f"📁 Using KICS queries via symlink: {queries_link}")
                else:
                    print("💡 Using KICS default queries")
            else:
                print("💡 Using KICS default queries")
        except Exception as e:
            print(f"⚠️ Could not create queries symlink: {e}")
            print("💡 Using KICS default queries")
        
        print(f"🚀 Running: {' '.join(kics_cmd)}")
        
        try:
            result = subprocess.run(kics_cmd, capture_output=True, text=True, timeout=config.settings.kics_timeout)
            
            if result.returncode == 0:
                print(f"✅ KICS scan completed successfully. Results saved to: {output_dir}/results.json")
                return True, f"Scan completed successfully. Results: {output_dir}/results.json"
            elif result.returncode == 1:
                # KICS often exits with 1 when it finds issues (which is expected)
                print(f"✅ KICS scan completed with findings. Results saved to: {output_dir}/results.json")
                return True, f"Scan completed with findings. Results: {output_dir}/results.json"
            else:
                print(f"⚠️ KICS scan completed with warnings. Exit code: {result.returncode}")
                print(f"Stderr: {result.stderr}")
                return True, f"Scan completed with warnings. Results: {output_dir}/results.json"
                
        except subprocess.TimeoutExpired:
            print(f"❌ KICS scan timed out after {config.settings.kics_timeout} seconds")
            return False, "Scan timed out"
        except Exception as e:
            print(f"❌ Error running KICS scan: {str(e)}")
            return False, f"Local scan failed: {str(e)}"
    
    # Try with queries path first, then without
    success, message = run_kics_command(use_queries_path=True)
    if not success:
        print("🔄 Retrying without custom queries path...")
        success, message = run_kics_command(use_queries_path=False)
    
    return success, message

@handle_exception
def load_kics_results_safe(results_path):
    """Load KICS results with comprehensive error handling"""
    try:
        if not os.path.exists(results_path):
            print(f"❌ Results file not found: {results_path}")
            return None
        
        with open(results_path, 'r') as f:
            data = json.load(f)
        
        queries = data.get("queries", [])
        if not queries:
            print("⚠️ No queries found in results file")
            return []
        
        print(f"📊 Loaded {len(queries)} queries from results")
        return queries
        
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in results file: {str(e)}")
        return None
    except Exception as e:
        print(f"❌ Error loading results: {str(e)}")
        return None

@handle_exception
def render_markdown_report(queries):
    """Generate a comprehensive markdown report from KICS results with business risk assessment"""
    if not queries:
        print("⚠️ No queries to process for report")
        return None
    
    # Generate risk assessment
    all_findings = []
    for query in queries:
        files = query.get("files", [])
        for file_finding in files:
            finding = {
                "query_name": query.get("query_name", "Unknown Query"),
                "severity": query.get("severity", "UNKNOWN"),
                "description": query.get("description", "No description available"),
                "file_name": file_finding.get("file_name", "Unknown file"),
                "line": file_finding.get("line", "Unknown line"),
                "issue": file_finding.get("issue", "No issue description")
            }
            all_findings.append(finding)
    
    risk_report = generate_risk_report(all_findings)
    
    report_content = f"""# DriftBuddy Security Scan Report

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

This report contains security findings from the KICS (Keeping Infrastructure as Code Secure) scan with **business risk assessment**.

### Security Statistics
- **Total Queries Scanned:** {len(queries)}
- **Queries with Findings:** {sum(1 for q in queries if q.get('files'))}
- **Total Findings:** {sum(len(q.get('files', [])) for q in queries)}

### Business Risk Assessment
- **Critical Business Risk:** {risk_report['critical_findings']} findings
- **High Business Risk:** {risk_report['high_findings']} findings
- **Medium Business Risk:** {risk_report['medium_findings']} findings
- **Low Business Risk:** {risk_report['low_findings']} findings
- **Minimal Business Risk:** {risk_report['minimal_findings']} findings

### Financial Impact
- **Total Estimated Cost:** {risk_report['total_estimated_cost']}
- **Priority:** Focus on Critical and High business risk findings first

## Risk Matrix Legend

| Impact/Likelihood | Very High | High | Medium | Low | Very Low |
|------------------|-----------|------|--------|-----|----------|
| **Critical** | 🔴 Critical | 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low |
| **High** | 🔴 Critical | 🟠 High | 🟠 High | 🟡 Medium | 🟢 Low |
| **Medium** | 🟠 High | 🟡 Medium | 🟡 Medium | 🟢 Low | ⚪ Minimal |
| **Low** | 🟡 Medium | 🟢 Low | 🟢 Low | ⚪ Minimal | ⚪ Minimal |
| **Minimal** | 🟢 Low | ⚪ Minimal | ⚪ Minimal | ⚪ Minimal | ⚪ Minimal |

## Detailed Findings by Business Risk

"""
    
    # Group queries by business risk level
    risk_levels = ["Critical", "High", "Medium", "Low", "Minimal"]
    queries_by_risk = {}
    
    for query in queries:
        files = query.get("files", [])
        if files:
            # Get the highest risk level for this query
            max_risk = "Minimal"
            for file_finding in files:
                finding = {
                    "query_name": query.get("query_name", "Unknown Query"),
                    "severity": query.get("severity", "UNKNOWN"),
                    "description": query.get("description", "No description available")
                }
                risk_assessment = RiskMatrix.assess_risk(
                    finding["query_name"], 
                    finding["severity"], 
                    finding["description"]
                )
                risk_level = risk_assessment.business_risk.value
                
                # Determine priority order
                risk_priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Minimal": 4}
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
                report_content += f"- **Impact:** {risk_assessment.impact.value} - {risk_assessment.impact_description}\n"
                report_content += f"- **Likelihood:** {risk_assessment.likelihood.value} - {risk_assessment.likelihood_description}\n"
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
def run_steampipe_scan(cloud_provider: str = "aws", scan_type: str = "security") -> Dict:
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
def run_steampipe_security_scan(steampipe: SteampipeIntegration, cloud_provider: str) -> Dict:
    """Run security-focused Steampipe scan"""
    print(f"🔍 Running Steampipe security scan for {cloud_provider}")
    
    results = {
        "provider": cloud_provider,
        "scan_type": "security",
        "timestamp": datetime.now().isoformat(),
        "findings": []
    }
    
    # Common security queries
    security_queries = [
        "SELECT * FROM aws_iam_user WHERE password_enabled = true",
        "SELECT * FROM aws_s3_bucket WHERE versioning_enabled = false",
        "SELECT * FROM aws_security_group WHERE ingress_rules_cidr = '0.0.0.0/0'"
    ]
    
    for query in security_queries:
        try:
            success, query_results = steampipe.query_infrastructure(query, cloud_provider)
            if success:
                results["findings"].extend(query_results)
        except Exception as e:
            print(f"⚠️ Error running query: {str(e)}")
    
    return results

@handle_exception
def run_steampipe_drift_scan(steampipe: SteampipeIntegration, cloud_provider: str) -> Dict:
    """Run drift detection Steampipe scan"""
    print(f"🔍 Running Steampipe drift scan for {cloud_provider}")
    
    results = {
        "provider": cloud_provider,
        "scan_type": "drift",
        "timestamp": datetime.now().isoformat(),
        "drift_findings": []
    }
    
    # Drift detection queries
    drift_queries = [
        "SELECT * FROM aws_ec2_instance WHERE state_name = 'running'",
        "SELECT * FROM aws_s3_bucket",
        "SELECT * FROM aws_iam_role"
    ]
    
    for query in drift_queries:
        try:
            success, query_results = steampipe.query_infrastructure(query, cloud_provider)
            if success:
                results["drift_findings"].extend(query_results)
        except Exception as e:
            print(f"⚠️ Error running drift query: {str(e)}")
    
    return results

@handle_exception
def generate_steampipe_report(results: Dict, reports_dir: str = "outputs/reports") -> str:
    """Generate Steampipe report with timestamped filename"""
    if not STEAMPIPE_AVAILABLE:
        print("❌ Steampipe integration not available")
        return None
    
    try:
        steampipe = SteampipeIntegration()
        filename = generate_timestamped_filename("steampipe_report", "md", reports_dir)
        output_path = os.path.join(reports_dir, filename)
        
        return steampipe.generate_steampipe_report(results, output_path)
    except Exception as e:
        print(f"❌ Error generating Steampipe report: {str(e)}")
        return None

@handle_exception
def check_steampipe_installation():
    """Check if Steampipe is properly installed and accessible"""
    if not STEAMPIPE_AVAILABLE:
        print("❌ Steampipe integration not available")
        return False
    
    try:
        steampipe = SteampipeIntegration()
        if steampipe.steampipe_installed:
            print("✅ Steampipe found and accessible")
            return True
        else:
            print("❌ Steampipe not found or not accessible")
            return False
    except Exception as e:
        print(f"❌ Error checking Steampipe installation: {str(e)}")
        return False

@handle_exception
def main():
    """Main entry point for DriftBuddy CLI"""
    parser = argparse.ArgumentParser(
        description="DriftBuddy - Infrastructure Security Scanner with Business Risk Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python driftbuddy.py --scan-path ./terraform
  python driftbuddy.py --scan-path ./k8s --output-format html
  python driftbuddy.py --scan-path ./docker --enable-ai
        """
    )
    
    parser.add_argument(
        "--scan-path",
        required=True,
        help="Path to scan for infrastructure files"
    )
    
    parser.add_argument(
        "--output-format",
        choices=["markdown", "html", "json"],
        default="markdown",
        help="Output format for the report (default: markdown)"
    )
    
    parser.add_argument(
        "--enable-ai",
        action="store_true",
        help="Enable AI-powered explanations and business risk assessment"
    )
    
    parser.add_argument(
        "--output-dir",
        default="outputs/reports",
        help="Directory for output files (default: outputs/reports)"
    )
    
    args = parser.parse_args()
    
    # Validate scan path
    scan_path = Path(args.scan_path)
    if not scan_path.exists():
        print(f"❌ Error: Scan path '{scan_path}' does not exist")
        sys.exit(1)
    
    print("🔍 DriftBuddy - Infrastructure Security Scanner")
    print("=" * 50)
    
    # Check KICS installation
    if not check_kics_installation():
        print("❌ KICS is not installed or not in PATH")
        print("💡 Please install KICS: https://kics.io/")
        sys.exit(1)
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Run KICS scan
    print(f"🔍 Starting KICS infrastructure scan...")
    print(f"📁 Scanning path: {scan_path}")
    
    try:
        # Run KICS scan
        success, message = run_kics(scan_path)
        if not success:
            print(f"❌ KICS scan failed: {message}")
            sys.exit(1)
        
        # Load results from the generated file
        results_path = f"{args.output_dir}/results.json"
        queries = load_kics_results_safe(results_path)
        if not queries:
            print("⚠️ No queries found in KICS results")
            sys.exit(1)
        
        print(f"✅ KICS scan completed successfully")
        print(f"📊 Found {len(queries)} security queries")
        
        # Count findings
        total_findings = sum(len(q.get("files", [])) for q in queries)
        print(f"🔍 Total findings: {total_findings}")
        
        # Generate business risk assessment
        if args.enable_ai:
            print("🤖 Generating AI explanations and business risk assessment...")
            queries = explain_findings(queries)
            
            # Calculate risk summary
            risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "minimal": 0}
            total_cost = 0
            
            for query in queries:
                risk_assessment = query.get("risk_assessment", {})
                business_risk = risk_assessment.get("business_risk", "Medium").lower()
                risk_summary[business_risk] += 1
                
                # Calculate cost
                cost_str = risk_assessment.get("cost_estimate", "$0")
                if "$" in cost_str:
                    try:
                        cost_range = cost_str.replace("$", "").replace("K", "000").replace("+", "")
                        if "-" in cost_range:
                            min_cost, max_cost = cost_range.split("-")
                            avg_cost = (int(min_cost) + int(max_cost)) / 2
                        else:
                            avg_cost = int(cost_range)
                        total_cost += avg_cost
                    except:
                        pass
            
            print("📊 Business Risk Summary:")
            print(f"   🔴 Critical: {risk_summary['critical']}")
            print(f"   🟠 High: {risk_summary['high']}")
            print(f"   🟡 Medium: {risk_summary['medium']}")
            print(f"   🟢 Low: {risk_summary['low']}")
            print(f"   ⚪ Minimal: {risk_summary['minimal']}")
            print(f"💰 Total Estimated Cost: ${total_cost:,.0f}")
        
        # Generate report
        print("📝 Generating report...")
        
        if args.output_format == "markdown":
            report_content = render_markdown_report(queries)
            output_file = output_dir / f"driftbuddy_report_{timestamp}.md"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            print(f"✅ Markdown report generated: {output_file}")
            
        elif args.output_format == "html":
            if args.enable_ai:
                output_file = output_dir / f"driftbuddy_report_{timestamp}.html"
                explain_findings(queries, str(output_file))
                print(f"✅ HTML report generated: {output_file}")
            else:
                print("⚠️ HTML format requires --enable-ai flag")
                sys.exit(1)
                
        elif args.output_format == "json":
            output_file = output_dir / f"driftbuddy_report_{timestamp}.json"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(queries, f, indent=2, ensure_ascii=False)
            
            print(f"✅ JSON report generated: {output_file}")
        
        print("\n🎉 Scan completed successfully!")
        print(f"📁 Report saved to: {output_file}")
        
        if args.enable_ai and risk_summary['critical'] > 0:
            print("\n🚨 CRITICAL BUSINESS RISK DETECTED!")
            print("   Immediate action required for critical findings.")
        
    except DriftBuddyError as e:
        print(f"❌ DriftBuddy error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
