"""
AI-powered explanation agent for DriftBuddy security findings.
Provides detailed, actionable explanations of security issues with business risk context.
"""

import asyncio
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional

from openai import OpenAI


# Import config lazily to avoid circular imports
def get_config_lazy():
    from driftbuddy.config import get_config

    return get_config()


def get_risk_matrix_lazy():
    from driftbuddy.risk_assessment import RiskMatrix

    return RiskMatrix


def load_kics_results(results_path: str) -> Dict[str, Any]:  # type: ignore[no-any-return]
    """Load KICS results from JSON file."""
    try:
        with open(results_path) as f:
            data = json.load(f)
            return data
    except FileNotFoundError:
        print(f"❌ Results file not found: {results_path}")
        return {}
    except json.JSONDecodeError:
        print(f"❌ Invalid JSON in results file: {results_path}")
        return {}


def batch_generate_explanations(client: OpenAI, queries: List[Dict], max_workers: int = 3) -> List[Dict]:
    """
    Generate AI explanations for multiple queries in parallel batches.
    Args:
        client: OpenAI client instance
        queries: List of query results from KICS
        max_workers: Maximum number of concurrent API calls
    Returns:
        List of queries with AI explanations and business risk assessment added
    """
    enriched_queries = []

    # Filter queries that have findings
    queries_with_findings = [q for q in queries if q.get("files")]
    queries_without_findings = [q for q in queries if not q.get("files")]

    print(f"🚀 Processing {len(queries_with_findings)} queries with findings using {max_workers} workers...")

    def process_single_query(query: Dict) -> Dict:
        """Process a single query with all its findings in one API call."""
        query_name = query.get("query_name", "Unknown Query")
        severity = query.get("severity", "UNKNOWN")
        description = query.get("description", "No description available")
        files = query.get("files", [])

        # Ensure query_name is a string (handle cases where it might be a tuple or other type)
        if isinstance(query_name, (tuple, list)):
            query_name = str(query_name[0]) if query_name else "Unknown Query"
        elif not isinstance(query_name, str):
            query_name = str(query_name)

        # Ensure severity is a string
        if not isinstance(severity, str):
            severity = str(severity)

        # Ensure description is a string
        if not isinstance(description, str):
            description = str(description)

        print(f"🤖 Processing: {query_name} ({len(files)} findings)")

        # Get business risk assessment
        RiskMatrix = get_risk_matrix_lazy()
        risk_assessment = RiskMatrix.assess_risk(query_name, severity, description)

        # Create a comprehensive prompt that includes all findings for this query
        findings_summary = ""
        for i, file_finding in enumerate(files, 1):
            file_name = file_finding.get("file_name", "Unknown file")
            line_number = file_finding.get("line", "Unknown line")
            issue = file_finding.get("issue", "No issue description")
            findings_summary += f"\n{i}. File: {file_name}:{line_number}\n   Issue: {issue}\n"

            # Check if this is a cloud finding
        is_cloud_finding = any("cloud_infrastructure" in file.get("file_name", "") for file in files)

        if is_cloud_finding:
            # Specialized prompt for cloud security findings
            prompt = f"""
            As a cloud security expert and business risk analyst, provide a comprehensive analysis for this cloud security finding:

            Query: {query_name}
            Technical Severity: {severity}
            Description: {description}
            Cloud Provider: {query.get('cloud_provider', 'Unknown')}
            Number of affected resources: {len(files)}

            Provide a comprehensive response with these sections (do not use numbered lists):

            **Technical Explanation:** Explain the cloud security issue and its technical root cause.

            **Business Impact:** List business/operational impacts (data breach, compliance violations, reputation damage, financial loss).

            **Attack Scenarios:** List realistic cloud attack scenarios that could exploit this vulnerability.

            **Remediation Strategy:** Give a step-by-step fix for the cloud infrastructure, including specific AWS/Azure/GCP configuration changes.

            **Business Justification:** Cost-benefit analysis and priority recommendation for cloud security.

            **Risk Mitigation:** Ongoing cloud security controls and monitoring recommendations.

            **Remediation Code:** Provide a cloud infrastructure code snippet or configuration example that would fix this issue. Format the code as a fenced code block (e.g., ```hcl for Terraform, ```yaml for CloudFormation, ```json for AWS CLI, etc). Only include the code block, no extra explanation.

            Cloud Findings:{findings_summary}
            """
        else:
            # Standard prompt for IaC findings
            prompt = f"""
            As a cybersecurity expert and business risk analyst, provide a comprehensive analysis for this security finding:

            Query: {query_name}
            Technical Severity: {severity}
            Description: {description}
            Number of affected files: {len(files)}

            Provide a comprehensive response with these sections (do not use numbered lists):

            **Technical Explanation:** Explain the technical root cause and risk.

            **Business Impact:** List business/operational impacts (operations, compliance, reputation).

            **Attack Scenarios:** List realistic attack scenarios.

            **Remediation Strategy:** Give a step-by-step fix, including specific code/configuration changes.

            **Business Justification:** Cost-benefit analysis and priority recommendation.

            **Risk Mitigation:** Ongoing controls and monitoring.

            **Remediation Code:** Provide a code snippet or configuration example that would fix this issue. Format the code as a fenced code block (e.g., ```hcl for Terraform, ```yaml for YAML, etc). Only include the code block, no extra explanation.

            Findings:{findings_summary}
            """
        try:
            # Single comprehensive prompt for the entire query
            response = client.chat.completions.create(
                model="o4-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert and business risk analyst.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0,  # Deterministic output
                max_tokens=1200,
            )
            ai_response = response.choices[0].message.content.strip()
            print(
                f"✅ {query_name}: API call completed in {getattr(response, 'response_ms', 0)/1000:.2f}s"
                if hasattr(response, "response_ms")
                else f"✅ {query_name}: API call completed"
            )

            # Parse remediation code block from AI response
            import re

            code_block = None
            code_match = re.search(r"```([a-zA-Z0-9]*)\n([\s\S]+?)```", ai_response)
            if code_match:
                code_block = code_match.group(0)  # include the ``` markers
                # Remove the code block from the AI explanation text
                ai_explanation_clean = re.sub(r"```([a-zA-Z0-9]*)\n([\s\S]+?)```", "", ai_response).strip()
            else:
                ai_explanation_clean = ai_response

            # Clean up numbered sections and redundant headings
            ai_explanation_clean = re.sub(r"\d+\.\s*Remediation Code Example:\s*", "", ai_explanation_clean)
            ai_explanation_clean = re.sub(r"\d+\.\s*Example Remediation Code:\s*", "", ai_explanation_clean)
            ai_explanation_clean = re.sub(r"Remediation Code Example:\s*", "", ai_explanation_clean)
            ai_explanation_clean = re.sub(r"Example Remediation Code:\s*", "", ai_explanation_clean)
            ai_explanation_clean = re.sub(r"Remediation Code:\s*", "", ai_explanation_clean)
            ai_explanation_clean = re.sub(r"\*\*Remediation Code:\*\*\s*", "", ai_explanation_clean)
            ai_explanation_clean = re.sub(r"\*\*Remediation Code\*\*:\s*", "", ai_explanation_clean)

            query["ai_explanation"] = ai_explanation_clean
            query["remediation_code"] = code_block

        except Exception as e:
            print(f"❌ Error in AI explanation for {query_name}: {e}")
            query["ai_explanation"] = f"Error: {e}"
            query["remediation_code"] = None

        # Get business risk assessment
        query["risk_assessment"] = {
            "impact": risk_assessment.impact.value[1],
            "likelihood": risk_assessment.likelihood.value[1],
            "business_risk_score": risk_assessment.business_risk_score,
            "business_risk": risk_assessment.business_risk.value[1],
            "impact_description": risk_assessment.impact_description,
            "likelihood_description": risk_assessment.likelihood_description,
            "business_context": risk_assessment.business_context,
            "remediation_priority": risk_assessment.remediation_priority,
            "cost_estimate": risk_assessment.cost_estimate,
            "time_to_fix": risk_assessment.time_to_fix,
        }
        return query

    # Use ThreadPoolExecutor for parallel API calls
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_query = {executor.submit(process_single_query, q): q for q in queries_with_findings}
        for future in as_completed(future_to_query):
            enriched_queries.append(future.result())

    # Add queries without findings back in
    enriched_queries.extend(queries_without_findings)
    # Preserve original order
    enriched_queries.sort(key=lambda q: queries.index(q))
    return enriched_queries


def parse_ai_response_for_fixes(ai_response: str, files: List[Dict]) -> List[str]:
    """
    Parse the AI response to extract specific fixes for each file.

    Args:
        ai_response: The AI-generated explanation
        files: List of file findings

    Returns:
        List of fixes corresponding to each file
    """
    fixes = []

    # Simple parsing logic - look for file-specific sections
    lines = ai_response.split("\n")
    current_fix = ""
    in_fix_section = False

    for line in lines:
        line = line.strip()

        # Look for file-specific headers
        if any(f"File:" in line and file.get("file_name", "") in line for file in files):
            if current_fix:
                fixes.append(current_fix.strip())
            current_fix = line + "\n"
            in_fix_section = True
        elif in_fix_section and line:
            current_fix += line + "\n"
        elif in_fix_section and not line:
            # Empty line might indicate end of fix section
            pass

    # Add the last fix
    if current_fix:
        fixes.append(current_fix.strip())

    # Ensure we have a fix for each file
    while len(fixes) < len(files):
        fixes.append("Specific fix not found in AI response")

    return fixes[: len(files)]  # Ensure we don't have more fixes than files


def explain_findings(
    queries: List[Dict],
    output_html: Optional[str] = None,
    return_per_query: bool = False,
) -> Any:
    """
    Generate AI-powered explanations for security findings with business risk context.
    If return_per_query is True, returns a list of markdown strings (one per query, in order).
    Otherwise, returns a single markdown string as before.
    """
    # Get API key with fallback support
    config = get_config_lazy()
    api_key = config.settings.get_openai_api_key()
    if not api_key:
        print("⚠️ No OpenAI API key available. AI explanations will be disabled.")
        print("💡 Set OPENAI_API_KEY environment variable or use demo mode.")
        if return_per_query:
            return ["# AI Analysis\n\nNo OpenAI API key available. AI explanations are disabled."] * len(queries)
        return "# AI Analysis\n\nNo OpenAI API key available. AI explanations are disabled."

    client = OpenAI(api_key=api_key)

    # Count queries with findings
    queries_with_findings = [q for q in queries if q.get("files")]

    # Use parallel processing with limited concurrency to avoid rate limits
    max_workers = min(
        config.settings.ai_max_concurrent_requests,
        max(1, len(queries_with_findings)),  # Ensure at least 1 worker
    )

    print(f"🚀 Starting AI explanation generation...")
    print(f"📊 Total queries: {len(queries)}")
    print(f"🔍 Queries with findings: {len(queries_with_findings)}")
    print(f"⚡ Using {max_workers} concurrent workers")
    print(f"⏱️ Request timeout: {config.settings.ai_request_timeout}s")

    # If no findings, return early with a success message
    if not queries_with_findings:
        print("✅ No security findings to analyze - skipping AI analysis")
        if return_per_query:
            return ["# AI Analysis\n\n✅ No security findings detected. Your infrastructure appears to follow security best practices! 🛡️"] * len(queries)
        return "# AI Analysis\n\n✅ No security findings detected. Your infrastructure appears to follow security best practices! 🛡️"

    start_time = time.time()

    enriched_queries = batch_generate_explanations(client, queries, max_workers)

    total_time = time.time() - start_time
    print(f"✅ AI explanation generation completed in {total_time:.2f}s")
    print(f"📈 Average time per query: {total_time/max(1, len(queries_with_findings)):.2f}s")

    if return_per_query:
        # Return a list of markdown strings, one per query, in order
        per_query_md = []
        for query in enriched_queries:
            query_name = query.get("query_name", "Unknown")
            severity = query.get("severity", "UNKNOWN")
            description = query.get("description", "No description")
            ai_explanation = query.get("ai_explanation", "No AI explanation available")
            risk_assessment = query.get("risk_assessment", {})
            # Just return the AI explanation markdown (already formatted)
            per_query_md.append(ai_explanation if ai_explanation else "No AI explanation available.")
        return per_query_md

    # Generate markdown report as before
    markdown_content = "# AI-Powered Security Analysis\n\n"
    markdown_content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    if enriched_queries:
        markdown_content += f"## Summary\n\n"
        markdown_content += f"- **Total Findings Analyzed:** {len(enriched_queries)}\n"
        markdown_content += f"- **Analysis Time:** {total_time:.2f} seconds\n\n"

        for query in enriched_queries:
            if query.get("files"):
                query_name = query.get("query_name", "Unknown")
                severity = query.get("severity", "UNKNOWN")
                description = query.get("description", "No description")
                ai_explanation = query.get("ai_explanation", "No AI explanation available")
                risk_assessment = query.get("risk_assessment", {})

                markdown_content += f"## {query_name}\n\n"
                markdown_content += f"**Severity:** {severity}\n\n"
                markdown_content += f"**Description:** {description}\n\n"
                markdown_content += f"**AI Analysis:**\n{ai_explanation}\n\n"

                if risk_assessment:
                    markdown_content += f"**Business Risk Assessment:**\n"
                    markdown_content += f"- **Risk Level:** {risk_assessment.get('risk_level', 'Unknown')}\n"
                    markdown_content += f"- **Potential Cost:** {risk_assessment.get('cost_estimate', 'Unknown')}\n"
                    markdown_content += f"- **Business Impact:** {risk_assessment.get('business_impact', 'Unknown')}\n\n"

                markdown_content += "---\n\n"

    return markdown_content


def generate_html_report(queries: List[Dict], output_path: str, total_cost: float = None) -> None:
    """
    Generate an HTML report with AI explanations and business risk assessment.

    Args:
        queries: List of enriched queries with AI explanations and risk assessment
        output_path: Path for the HTML output file
        total_cost: Pre-calculated total cost (optional)
    """

    # Initialize risk summary with proper keys
    risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "minimal": 0}

    # Use provided total_cost or calculate it
    if total_cost is not None:
        total_estimated_cost = total_cost
        print(f"🔍 Debug - Using provided total cost: {total_estimated_cost}")
    else:
        total_estimated_cost = 0
        print(f"🔍 Debug - No total cost provided, starting at 0")

    print(f"🔍 Debug - Initial risk_summary: {risk_summary}")

    for query in queries:
        risk_assessment = query.get("risk_assessment", {})
        business_risk = risk_assessment.get("business_risk", "Medium")

        # Debug logging to identify the issue
        print(f"🔍 Debug - business_risk type: {type(business_risk)}, value: {business_risk}")

        # Ensure business_risk is a string (handle cases where it might be a tuple or other type)
        if isinstance(business_risk, (tuple, list)):
            business_risk = str(business_risk[0]) if business_risk else "Medium"
        elif not isinstance(business_risk, str):
            business_risk = str(business_risk)

        print(f"🔍 Debug - business_risk after conversion: {business_risk}")

        # Map risk levels to expected summary keys
        # Handle both string numbers and category names
        risk_level_mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "minimal": "minimal",
            # Handle numeric string values
            "1": "minimal",
            "2": "low",
            "3": "medium",
            "4": "high",
            "5": "critical",
        }

        # Use mapped key or default to "medium" if not found
        summary_key = risk_level_mapping.get(business_risk.lower(), "medium")
        print(f"🔍 Debug - summary_key: {summary_key}")
        print(f"🔍 Debug - risk_summary keys before: {list(risk_summary.keys())}")
        risk_summary[summary_key] += 1
        print(f"🔍 Debug - risk_summary after update: {risk_summary}")

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DriftBuddy Security Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-top: 30px;
        }}
        h3 {{
            color: #7f8c8d;
            margin-top: 20px;
        }}
        .risk-matrix {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .risk-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .risk-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
            font-weight: bold;
        }}
        .risk-critical {{ background: #e74c3c; }}
        .risk-high {{ background: #f39c12; }}
        .risk-medium {{ background: #3498db; }}
        .risk-low {{ background: #27ae60; }}
        .risk-minimal {{ background: #95a5a6; }}
        .finding {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }}
        .ai-explanation {{
            background: #e8f4fd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }}
        .ai-fix {{
            background: #f0f8f0;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #27ae60;
        }}
        .risk-assessment {{
            background: #fff3cd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
        }}
        code {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .summary {{
            background: #e8f5e8;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .timestamp {{
            color: #7f8c8d;
            text-align: center;
            font-style: italic;
        }}
        .cost-highlight {{
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 DriftBuddy Security Report</h1>
        <p class="timestamp">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <p>This report contains AI-powered explanations of security findings with business risk assessment.</p>
            <p><strong>Total Queries:</strong> {len(queries)}</p>
            <p><strong>Findings with Issues:</strong> {sum(1 for q in queries if q.get('files'))}</p>
        </div>

        <div class="risk-summary">
            <div class="risk-card risk-critical">
                <h3>🔴 Critical</h3>
                <div class="risk-count">{risk_summary['critical']}</div>
            </div>
            <div class="risk-card risk-high">
                <h3>🟠 High</h3>
                <div class="risk-count">{risk_summary['high']}</div>
            </div>
            <div class="risk-card risk-medium">
                <h3>🟡 Medium</h3>
                <div class="risk-count">{risk_summary['medium']}</div>
            </div>
            <div class="risk-card risk-low">
                <h3>🟢 Low</h3>
                <div class="risk-count">{risk_summary['low']}</div>
            </div>
            <div class="risk-card risk-minimal">
                <h3>⚪ Minimal</h3>
                <div class="risk-count">{risk_summary['minimal']}</div>
            </div>
        </div>

        <div class="cost-highlight">
            <h3>💰 Financial Impact</h3>
            <p><strong>Total Estimated Cost of Inaction:</strong> ${total_estimated_cost:,.0f}</p>
            <p><strong>Priority:</strong> Focus on Critical and High business risk findings first</p>
        </div>

        <div class="risk-matrix">
            <h3>📋 Risk Matrix (Impact × Likelihood = Business Risk Score)</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <th style="border: 1px solid #ddd; padding: 8px;">Impact/Likelihood</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Almost Certain (5)</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Likely (4)</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Possible (3)</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Unlikely (2)</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Rare (1)</th>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">Catastrophic (5)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #e74c3c; color: white;">🔴 Critical (25)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #e74c3c; color: white;">🔴 Critical (20)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #f39c12; color: white;">🟠 High (15)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium (10)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low (5)</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">Major (4)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #e74c3c; color: white;">🔴 Critical (20)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #f39c12; color: white;">🟠 High (16)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #f39c12; color: white;">🟠 High (12)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium (8)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low (4)</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">Moderate (3)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #f39c12; color: white;">🟠 High (15)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium (12)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium (9)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low (6)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal (3)</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">Minor (2)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium (10)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low (8)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low (6)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal (4)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal (2)</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">Insignificant (1)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low (5)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal (4)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal (3)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal (2)</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal (1)</td>
                </tr>
            </table>
            <p><strong>Risk Level Thresholds:</strong></p>
            <ul>
                <li><strong>Critical (20-25):</strong> Immediate action required</li>
                <li><strong>High (15-19):</strong> High priority remediation</li>
                <li><strong>Medium (10-14):</strong> Moderate priority</li>
                <li><strong>Low (5-9):</strong> Low priority</li>
                <li><strong>Minimal (1-4):</strong> Acceptable risk</li>
            </ul>
        </div>
"""

    for query in queries:
        query_name = query.get("query_name", "Unknown Query")
        severity = query.get("severity", "UNKNOWN")
        description = query.get("description", "No description available")
        files = query.get("files", [])
        ai_explanation = query.get("ai_explanation", "No AI explanation available")
        risk_assessment = query.get("risk_assessment", {})

        business_risk = risk_assessment.get("business_risk", "Medium")

        # Ensure business_risk is a string (handle cases where it might be a tuple or other type)
        if isinstance(business_risk, (tuple, list)):
            business_risk = str(business_risk[0]) if business_risk else "Medium"
        elif not isinstance(business_risk, str):
            business_risk = str(business_risk)

        risk_class = f"risk-{business_risk.lower()}"

        html_content += f"""
        <h2 class="{risk_class}">🔍 {query_name}</h2>
        <p><strong>Technical Severity:</strong> {severity}</p>
        <p><strong>Business Risk:</strong> <span class="{risk_class}">{business_risk}</span></p>
        <p><strong>Description:</strong> {description}</p>

        <div class="risk-assessment">
            <h3>📊 Business Risk Assessment</h3>
            <p><strong>Impact:</strong> {risk_assessment.get('impact', 'Unknown')} - {risk_assessment.get('impact_description', '')}</p>
            <p><strong>Likelihood:</strong> {risk_assessment.get('likelihood', 'Unknown')} - {risk_assessment.get('likelihood_description', '')}</p>
            <p><strong>Business Risk Score:</strong> {risk_assessment.get('business_risk_score', 'Unknown')} (Impact × Likelihood)</p>
            <p><strong>Business Risk Level:</strong> {risk_assessment.get('business_risk', 'Unknown')}</p>
            <p><strong>Remediation Priority:</strong> {risk_assessment.get('remediation_priority', 'Medium')}</p>
            <p><strong>Estimated Cost:</strong> {risk_assessment.get('cost_estimate', 'Unknown')}</p>
            <p><strong>Time to Fix:</strong> {risk_assessment.get('time_to_fix', 'Unknown')}</p>
            <p><strong>Business Context:</strong> {risk_assessment.get('business_context', '')}</p>
        </div>

        <div class="ai-explanation">
            <h3>🤖 AI Explanation</h3>
            <p>{ai_explanation.replace(chr(10), '<br>')}</p>
        </div>
"""

        if files:
            html_content += f"""
        <h3>📁 Affected Files ({len(files)})</h3>
"""

            for file_finding in files:
                file_name = file_finding.get("file_name", "Unknown file")
                line_number = file_finding.get("line", "Unknown line")
                issue = file_finding.get("issue", "No issue description")
                ai_fix = file_finding.get("ai_fix", "No AI fix available")

                html_content += f"""
        <div class="finding">
            <h4>📄 {file_name}:{line_number}</h4>
            <p><strong>Issue:</strong> {issue}</p>

            <div class="ai-fix">
                <h5>🔧 AI Suggested Fix</h5>
                <p>{ai_fix.replace(chr(10), '<br>')}</p>
            </div>
        </div>
"""
        else:
            html_content += """
        <p>✅ No security issues found for this query.</p>
"""

    html_content += """
    </div>
</body>
</html>
"""

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"✅ HTML report generated: {output_path}")
    except Exception as e:
        print(f"❌ Error generating HTML report: {e}")


def main() -> None:
    """Main function for testing the explainer."""
    # Example usage
    results_path = "test_data/output/results.json"

    if not os.path.exists(results_path):
        print(f"❌ Results file not found: {results_path}")
        return

    results = load_kics_results(results_path)
    queries = results.get("queries", [])

    if not queries:
        print("No queries found in results.")
        return

    print(f"🔍 Processing {len(queries)} queries...")

    enriched_queries = explain_findings(queries, "outputs/analysis/ai_security_report.html")

    print(f"✅ Processed {len(enriched_queries)} queries with AI explanations")


if __name__ == "__main__":
    main()
