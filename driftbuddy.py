import subprocess
import os
import sys
import argparse
import json
from pathlib import Path
from datetime import datetime
from agent.explainer import load_kics_results, explain_findings

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

    try:
        result = subprocess.run([
            "kics",
            "scan",
            "--path", scan_path,
            "--output-path", output_dir,
            "--output-name", "results",
            "--report-formats", "json",
            "--queries-path", "/mnt/d/driftbuddy/kics/assets/queries"
        ], capture_output=True, text=True, timeout=300)  # 5 minute timeout
        
        print(f"[DEBUG] KICS exited with code: {result.returncode}")
        
        if result.returncode in [0, 40, 60]:
            print(f"✅ KICS scan completed. Results saved to: {output_dir}/results.json")
            return True, ""
        elif result.returncode == 40:
            print("⚠️ KICS found no security issues (exit code 40)")
            return True, "no_findings"
        else:
            error_msg = result.stderr if result.stderr else "Unknown KICS error"
            print(f"❌ KICS scan failed: {error_msg}")
            return False, f"KICS scan failed: {error_msg}"
            
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
    
    # Run KICS scan with error handling
    kics_success, kics_result = run_kics(args.scan_path, args.output_dir)
    if not kics_success:
        print(f"❌ KICS scan failed: {kics_result}")
        sys.exit(1)
    
    # Handle no findings case
    if kics_result == "no_findings":
        print("✅ No security issues found! Your infrastructure looks secure.")
        
        if generate_md:
            # Create a "no findings" report
            no_findings_report = render_markdown_report([])
            with open("drift_report.md", "w") as f:
                f.write(no_findings_report)
            print("📄 Markdown report generated: drift_report.md")
        
        if generate_html:
            # Create a "no findings" HTML dashboard
            from agent.explainer import generate_html_dashboard
            generate_html_dashboard({}, "kics_explained.html")
            print("📊 HTML dashboard generated: kics_explained.html")
        
        print("\n🎉 Scan completed successfully!")
        print("💡 Your infrastructure appears to follow security best practices!")
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
            with open("drift_report.md", "w") as f:
                f.write(no_findings_report)
            print("📄 Markdown report generated: drift_report.md")
        
        if generate_html:
            from agent.explainer import generate_html_dashboard
            generate_html_dashboard({}, "kics_explained.html")
            print("📊 HTML dashboard generated: kics_explained.html")
        
        print("\n🎉 Scan completed successfully!")
        print("💡 Your infrastructure appears to follow security best practices!")
        return
    
    print(f"🔍 Found {len(queries)} security issues to analyze...")
    
    # Generate reports based on flags with error handling
    try:
        if generate_html:
            print("🎨 Generating HTML dashboard...")
            explain_findings(queries, output_html="kics_explained.html")
            print("📊 HTML dashboard generated: kics_explained.html")
        
        if generate_md:
            print("📝 Generating markdown report...")
            enriched_queries = explain_findings(queries, output_html=None)  # Skip HTML generation
            
            markdown_report = render_markdown_report(enriched_queries)
            with open("drift_report.md", "w") as f:
                f.write(markdown_report)
            print("📄 Markdown report generated: drift_report.md")
        
        print("\n🎉 Scan completed successfully!")
        if generate_html:
            print("💡 Open kics_explained.html in your browser to view the dashboard")
        if generate_md:
            print("💡 View drift_report.md for detailed findings")
            
    except Exception as e:
        print(f"❌ Error generating reports: {str(e)}")
        print("💡 Check your OpenAI API key and internet connection")
        sys.exit(1)

if __name__ == "__main__":
    main()
