import subprocess
import os
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime
from agent.explainer import load_kics_results, explain_findings

def generate_timestamped_filename(base_name, extension, reports_dir="."):
    """Generate a timestamped filename with driftbuddy prefix in the specified directory"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"driftbuddy_{base_name}_{timestamp}.{extension}"
    
    # Ensure the reports directory exists
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    
    return os.path.join(reports_dir, filename)

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

def check_docker_kics():
    """Check if KICS Docker image is available"""
    try:
        result = subprocess.run(["docker", "run", "--rm", "checkmarx/kics:latest", "--version"], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ KICS Docker image available")
            return True
        else:
            print("❌ KICS Docker image not available")
            return False
    except FileNotFoundError:
        print("❌ Docker not found")
        return False
    except Exception as e:
        print(f"❌ Error checking Docker KICS: {str(e)}")
        return False

def validate_scan_path(scan_path):
    """Validate that the scan path exists and is accessible"""
    try:
        path = Path(scan_path)
        if not path.exists():
            return False, f"❌ Error: Scan path '{scan_path}' does not exist."
        
        if not path.is_dir() and not path.is_file():
            return False, f"❌ Error: '{scan_path}' is not a valid file or directory."
        
        # Check if directory is empty
        if path.is_dir() and not any(path.iterdir()):
            return False, f"❌ Error: Directory '{scan_path}' is empty."
        
        return True, ""
    except Exception as e:
        return False, f"❌ Error validating scan path: {str(e)}"

def run_kics(scan_path, output_dir="test_data/output"):
    """Run KICS scan with enhanced error handling"""
    print(f"🔍 Running KICS scan on: {scan_path}")
    
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"❌ Error creating output directory: {str(e)}")
        return False, f"Failed to create output directory: {str(e)}"

    # Check if we should use Docker KICS
    use_docker = os.getenv("USE_DOCKER_KICS", "false").lower() == "true"
    
    if use_docker:
        return run_kics_docker(scan_path, output_dir)
    else:
        return run_kics_local(scan_path, output_dir)

def run_kics_docker(scan_path, output_dir):
    """Run KICS scan using Docker"""
    try:
        # Get absolute paths for Docker volume mounting
        scan_path_abs = os.path.abspath(scan_path)
        output_dir_abs = os.path.abspath(output_dir)
        
        kics_cmd = [
            "docker", "run", "--rm",
            "-v", f"{scan_path_abs}:/input",
            "-v", f"{output_dir_abs}:/output",
            "checkmarx/kics:latest",
            "scan",
            "-p", "/input",
            "-o", "/output",
            "-n", "results",
            "-f", "json"
        ]
        
        print(f"🔧 Running KICS Docker command: {' '.join(kics_cmd)}")
        
        result = subprocess.run(kics_cmd, capture_output=True, text=True, timeout=300)
        
        print(f"[DEBUG] KICS Docker exited with code: {result.returncode}")
        
        # Handle exit codes
        if result.returncode in [0, 40, 50, 60]:
            print(f"✅ KICS Docker scan completed. Results saved to: {output_dir}/results.json")
            return True, ""
        else:
            error_msg = result.stderr if result.stderr else result.stdout if result.stdout else "Unknown Docker KICS error"
            print(f"❌ KICS Docker scan failed: {error_msg}")
            return False, f"KICS Docker scan failed: {error_msg}"
            
    except subprocess.TimeoutExpired:
        return False, "KICS Docker scan timed out after 5 minutes"
    except FileNotFoundError:
        return False, "Docker not found. Please install Docker."
    except Exception as e:
        return False, f"Unexpected error running KICS Docker: {str(e)}"

def run_kics_local(scan_path, output_dir):
    """Run KICS scan using local installation"""
    # Determine the correct queries path
    queries_path = "kics/assets/queries"
    if not os.path.exists(queries_path):
        # Try alternative paths
        alt_paths = [
            "./kics/assets/queries",
            "../kics/assets/queries",
            "kics/assets/queries"
        ]
        for path in alt_paths:
            if os.path.exists(path):
                queries_path = path
                break
        else:
            print("⚠️ Warning: KICS queries path not found. Using default KICS queries.")
            queries_path = ""  # Let KICS use its default queries

    def run_kics_command(use_queries_path=True):
        """Helper function to run KICS with or without custom queries path"""
        kics_cmd = [
            "kics",
            "scan",
            "--path", scan_path,
            "--output-path", output_dir,
            "--output-name", "results",
            "--report-formats", "json"
        ]
        
        # Only add queries path if it exists and we want to use it
        if queries_path and use_queries_path:
            kics_cmd.extend(["--queries-path", queries_path])
        
        print(f"🔧 Running KICS command: {' '.join(kics_cmd)}")
        
        result = subprocess.run(kics_cmd, capture_output=True, text=True, timeout=300)  # 5 minute timeout
        
        print(f"[DEBUG] KICS exited with code: {result.returncode}")
        
        # Enhanced exit code handling
        if result.returncode in [0, 40, 50, 60]:
            # Clean up the output by removing progress indicators
            stdout_clean = result.stdout.replace("Preparing Scan Assets:", "").replace("Executing queries:", "").replace("Generating Reports:", "").strip()
            stderr_clean = result.stderr.replace("Preparing Scan Assets:", "").replace("Executing queries:", "").replace("Generating Reports:", "").strip()
            
            if result.returncode == 0:
                print(f"✅ KICS scan completed successfully. Results saved to: {output_dir}/results.json")
                return True, ""
            elif result.returncode == 40:
                print("⚠️ KICS found no security issues (exit code 40)")
                return True, "no_findings"
            elif result.returncode == 50:
                print("⚠️ KICS completed with warnings (exit code 50)")
                if "no results found" in stdout_clean.lower() or "no results found" in stderr_clean.lower():
                    return True, "no_findings"
                else:
                    print(f"✅ KICS scan completed with warnings. Results saved to: {output_dir}/results.json")
                    return True, ""
            elif result.returncode == 60:
                print("⚠️ KICS found security issues (exit code 60)")
                print(f"✅ KICS scan completed. Results saved to: {output_dir}/results.json")
                return True, ""
        else:
            # Clean up error messages
            error_msg = stderr_clean if result.stderr else stdout_clean if result.stdout else "Unknown KICS error"
            if not error_msg.strip():
                error_msg = f"KICS failed with exit code {result.returncode}"
            return False, f"KICS scan failed: {error_msg}"

    try:
        # First try with custom queries path
        if queries_path:
            success, result_msg = run_kics_command(use_queries_path=True)
            if success:
                return success, result_msg
            else:
                print("⚠️ KICS failed with custom queries path, trying with default queries...")
        
        # Fallback to default queries
        return run_kics_command(use_queries_path=False)
            
    except subprocess.TimeoutExpired:
        return False, "KICS scan timed out after 5 minutes"
    except FileNotFoundError:
        return False, "KICS executable not found. Please ensure KICS is installed and in your PATH."
    except Exception as e:
        return False, f"Unexpected error running KICS: {str(e)}"

def load_kics_results_safe(results_path):
    """Safely load KICS results with error handling"""
    try:
        if not os.path.exists(results_path):
            return None, "Results file not found"
        
        with open(results_path, 'r') as f:
            data = json.load(f)
        
        queries = data.get("queries", [])
        if not queries:
            return [], "no_findings"
        
        return queries, ""
        
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON in results file: {str(e)}"
    except Exception as e:
        return None, f"Error loading results: {str(e)}"

def render_markdown_report(queries):
    """Render markdown report with enhanced error handling"""
    if not queries:
        return "# 🧾 DriftBuddy Security Scan Report\n\n**Generated:** " + \
               datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n\n" + \
               "## ✅ No Security Issues Found\n\n" + \
               "Great news! No security vulnerabilities were detected in your infrastructure code.\n\n" + \
               "**Scan Summary:**\n" + \
               "- **Total Findings:** 0\n" + \
               "- **Status:** ✅ Secure\n\n" + \
               "Your infrastructure appears to follow security best practices. Keep up the good work! 🛡️"

    markdown = ""
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    # Count findings by severity first
    for query in queries:
        severity = query.get("severity", "UNKNOWN").upper()
        severity_count[severity] = severity_count.get(severity, 0) + 1

    # Add summary table
    summary = "# 🧾 DriftBuddy Security Scan Report\n\n"
    summary += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    summary += "## 📊 Summary\n"
    total_findings = sum(severity_count.values())
    summary += f"**Total Findings:** {total_findings}\n\n"
    
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_count.get(level, 0)
        if count > 0:
            summary += f"- **{level}:** {count}\n"
    
    summary += "\n---\n\n"
    markdown += summary

    # Group findings by severity
    findings_by_severity = {}
    for query in queries:
        severity = query.get("severity", "UNKNOWN").upper()
        if severity not in findings_by_severity:
            findings_by_severity[severity] = []
        findings_by_severity[severity].append(query)

    # Render findings by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity in findings_by_severity and findings_by_severity[severity]:
            markdown += f"## {severity} Findings ({len(findings_by_severity[severity])})\n\n"
            
            for query in findings_by_severity[severity]:
                query_name = query.get("query_name", "Unknown Query")
                file = query['files'][0].get("file_name", "Unknown File") if query.get('files') else "Unknown File"
                line = query['files'][0].get("line", "Unknown Line") if query.get('files') else "Unknown Line"
                explanation = query.get("explanation", "No AI explanation available for this finding.")
                url = query.get("url", "#")
                description = query.get("description", "No description provided.")

                markdown += f"### 🔍 {query_name}\n"
                markdown += f"**Severity:** {severity}\n\n"
                markdown += f"**File:** `{file}`  \n"
                markdown += f"**Line:** `{line}`  \n"
                markdown += f"**Description:** {description}\n\n"
                markdown += f"**Explanation & Fix:**\n{explanation}\n\n"
                markdown += f"[📚 Learn more]({url})\n\n"
                markdown += "---\n\n"

    return markdown

def main():
    parser = argparse.ArgumentParser(
        description="🛡️ DriftBuddy - AI-Powered Infrastructure Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python driftbuddy.py ./terraform-code                    # Basic scan with markdown report
  python driftbuddy.py ./terraform-code --html            # Generate HTML dashboard
  python driftbuddy.py ./terraform-code --md              # Generate enhanced markdown report
  python driftbuddy.py ./terraform-code --all             # Generate all report formats
  python driftbuddy.py ./terraform-code --html --md       # Generate both HTML and markdown
  python driftbuddy.py ./terraform-code --all --reports-dir ./reports  # Save reports to ./reports/
        """
    )
    
    parser.add_argument(
        "scan_path", 
        help="Path to the Terraform/Infrastructure code to scan"
    )
    
    parser.add_argument(
        "--html", 
        action="store_true", 
        help="Generate beautiful HTML dashboard report (kics_explained.html)"
    )
    
    parser.add_argument(
        "--md", 
        action="store_true", 
        help="Generate enhanced markdown report with AI explanations (drift_report.md)"
    )
    
    parser.add_argument(
        "--all", 
        action="store_true", 
        help="Generate all report formats (HTML dashboard + enhanced markdown)"
    )
    
    parser.add_argument(
        "--output-dir", 
        default="test_data/output",
        help="Directory to store KICS scan results (default: test_data/output)"
    )
    
    parser.add_argument(
        "--reports-dir", 
        default=".",
        help="Directory to store generated reports (default: current directory)"
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version="DriftBuddy v1.0.0 - AI-Powered Security Scanner"
    )
    
    args = parser.parse_args()
    
    # Validate scan path
    is_valid, error_msg = validate_scan_path(args.scan_path)
    if not is_valid:
        print(error_msg)
        sys.exit(1)
    
    # Determine which reports to generate
    generate_html = args.html or args.all
    generate_md = args.md or args.all
    
    # If no specific format is requested, default to markdown
    if not (generate_html or generate_md):
        generate_md = True
    
    print("🚀 Starting DriftBuddy Security Scan...")
    print(f"📁 Scanning: {args.scan_path}")
    print(f"📊 Reports: {'HTML' if generate_html else ''}{' + ' if generate_html and generate_md else ''}{'Markdown' if generate_md else ''}")
    print("-" * 50)
    
    # Check KICS installation first
    if not check_kics_installation():
        print("⚠️ Local KICS not working, trying Docker KICS...")
        if check_docker_kics():
            print("✅ Will use KICS via Docker")
            # Set a flag to use Docker KICS
            os.environ["USE_DOCKER_KICS"] = "true"
        else:
            print("❌ Neither local KICS nor Docker KICS is available.")
            print("💡 Please install KICS or Docker and try again.")
            sys.exit(1)
    
    # Run KICS scan with error handling
    kics_success, kics_result = run_kics(args.scan_path, args.output_dir)
    if not kics_success:
        print(f"❌ KICS scan failed: {kics_result}")
        sys.exit(1)
    
    # Handle no findings case
    if kics_result == "no_findings":
        print("✅ No security issues found! Your infrastructure looks secure.")
        
        if generate_md:
            # Create a "no findings" report with timestamped filename
            no_findings_report = render_markdown_report([])
            md_filename = generate_timestamped_filename("security_report", "md", args.reports_dir)
            with open(md_filename, "w") as f:
                f.write(no_findings_report)
            print(f"📄 Markdown report generated: {md_filename}")
        
        if generate_html:
            # Create a "no findings" HTML dashboard with timestamped filename
            from agent.explainer import generate_html_dashboard
            html_filename = generate_timestamped_filename("security_dashboard", "html", args.reports_dir)
            generate_html_dashboard({}, html_filename)
            print(f"📊 HTML dashboard generated: {html_filename}")
        
        print("\n🎉 Scan completed successfully!")
        print("💡 Your infrastructure appears to follow security best practices!")
        
        # Print summary of generated files
        print("\n📁 Generated Files:")
        if generate_html:
            print(f"   📊 HTML Dashboard: {html_filename}")
        if generate_md:
            print(f"   📄 Markdown Report: {md_filename}")
        print(f"   🔍 KICS Results: {args.output_dir}/results.json")
        return

    # Load and process results with error handling
    results_path = f"{args.output_dir}/results.json"
    queries, load_error = load_kics_results_safe(results_path)
    
    if queries is None:
        print(f"❌ Error loading scan results: {load_error}")
        sys.exit(1)
    
    if not queries:
        print("✅ No security issues found! Your infrastructure looks secure.")
        
        if generate_md:
            no_findings_report = render_markdown_report([])
            md_filename = generate_timestamped_filename("security_report", "md", args.reports_dir)
            with open(md_filename, "w") as f:
                f.write(no_findings_report)
            print(f"📄 Markdown report generated: {md_filename}")
        
        if generate_html:
            from agent.explainer import generate_html_dashboard
            html_filename = generate_timestamped_filename("security_dashboard", "html", args.reports_dir)
            generate_html_dashboard({}, html_filename)
            print(f"📊 HTML dashboard generated: {html_filename}")
        
        print("\n🎉 Scan completed successfully!")
        print("💡 Your infrastructure appears to follow security best practices!")
        
        # Print summary of generated files
        print("\n📁 Generated Files:")
        if generate_html:
            print(f"   📊 HTML Dashboard: {html_filename}")
        if generate_md:
            print(f"   📄 Markdown Report: {md_filename}")
        print(f"   🔍 KICS Results: {args.output_dir}/results.json")
        return
    
    print(f"🔍 Found {len(queries)} security issues to analyze...")
    
    # Generate reports based on flags with error handling
    try:
        if generate_html:
            print("🎨 Generating HTML dashboard...")
            html_filename = generate_timestamped_filename("security_dashboard", "html", args.reports_dir)
            explain_findings(queries, output_html=html_filename)
            print(f"📊 HTML dashboard generated: {html_filename}")
        
        if generate_md:
            print("📝 Generating markdown report...")
            enriched_queries = explain_findings(queries, output_html=None)  # Skip HTML generation
            
            markdown_report = render_markdown_report(enriched_queries)
            md_filename = generate_timestamped_filename("security_report", "md", args.reports_dir)
            with open(md_filename, "w") as f:
                f.write(markdown_report)
            print(f"📄 Markdown report generated: {md_filename}")
        
        print("\n🎉 Scan completed successfully!")
        if generate_html:
            print(f"💡 Open {html_filename} in your browser to view the dashboard")
        if generate_md:
            print(f"💡 View {md_filename} for detailed findings")
        
        # Print summary of generated files
        print("\n📁 Generated Files:")
        if generate_html:
            print(f"   📊 HTML Dashboard: {html_filename}")
        if generate_md:
            print(f"   📄 Markdown Report: {md_filename}")
        print(f"   🔍 KICS Results: {args.output_dir}/results.json")
            
    except Exception as e:
        print(f"❌ Error generating reports: {str(e)}")
        print("💡 Check your OpenAI API key and internet connection")
        sys.exit(1)

if __name__ == "__main__":
    main()
