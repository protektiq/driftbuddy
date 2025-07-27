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

from driftbuddy.config import get_config
from driftbuddy.risk_assessment import RiskMatrix

# Load configuration
config = get_config()


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
        risk_assessment = RiskMatrix.assess_risk(query_name, severity, description)

        # Create a comprehensive prompt that includes all findings for this query
        findings_summary = ""
        for i, file_finding in enumerate(files, 1):
            file_name = file_finding.get("file_name", "Unknown file")
            line_number = file_finding.get("line", "Unknown line")
            issue = file_finding.get("issue", "No issue description")
            findings_summary += f"\n{i}. File: {file_name}:{line_number}\n   Issue: {issue}\n"

        try:
            # Single comprehensive prompt for the entire query
            prompt = f"""
            As a cybersecurity expert and business risk analyst, provide a comprehensive analysis for this security finding:

            Query: {query_name}
            Technical Severity: {severity}
            Description: {description}
            Number of affected files: {len(files)}

            Business Risk Assessment:
            - Impact: {risk_assessment.impact.value} - {risk_assessment.impact_description}
            - Likelihood: {risk_assessment.likelihood.value} - {risk_assessment.likelihood_description}
            - Business Risk: {risk_assessment.business_risk.value}
            - Estimated Cost: {risk_assessment.cost_estimate}
            - Time to Fix: {risk_assessment.time_to_fix}

            Affected Files and Issues:
            {findings_summary}

            Provide a comprehensive response including:
            1. **Technical Explanation**: What this security issue is and why it matters
            2. **Business Impact**: How this affects operations, compliance, and reputation
            3. **Attack Scenarios**: How this could be exploited by attackers
            4. **Remediation Strategy**:
               - Overall approach to fixing this issue
               - Specific code fixes for each affected file
               - Implementation timeline and effort
            5. **Business Justification**: Cost-benefit analysis and priority recommendations
            6. **Risk Mitigation**: Additional security considerations

            Format your response with clear sections and actionable recommendations.
            Focus on both technical accuracy and business value.
            """

            start_time = time.time()
            response = client.chat.completions.create(
                model=config.settings.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert and business risk analyst providing clear, actionable security advice with business context. Provide comprehensive, well-structured responses.",
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=config.settings.openai_max_tokens,
                temperature=0.3,
                timeout=config.settings.ai_request_timeout,
            )

            api_time = time.time() - start_time
            print(f"✅ {query_name}: API call completed in {api_time:.2f}s")

            ai_explanation = response.choices[0].message.content.strip()

            # Parse the AI response to extract fixes for individual files
            # The AI will provide fixes in a structured format
            file_fixes = parse_ai_response_for_fixes(ai_explanation, files)

            # Add AI explanation and risk assessment to query
            query["ai_explanation"] = ai_explanation
            query["risk_assessment"] = {
                "impact": risk_assessment.impact.value,
                "likelihood": risk_assessment.likelihood.value,
                "business_risk_score": risk_assessment.business_risk_score,  # Add the calculated score
                "business_risk": risk_assessment.business_risk.value[1],  # Get the string part of the tuple
                "impact_description": risk_assessment.impact_description,
                "likelihood_description": risk_assessment.likelihood_description,
                "business_context": risk_assessment.business_context,
                "remediation_priority": risk_assessment.remediation_priority,
                "cost_estimate": risk_assessment.cost_estimate,
                "time_to_fix": risk_assessment.time_to_fix,
            }

            # Add parsed fixes to file findings
            for file_finding, fix in zip(files, file_fixes):
                file_finding["ai_fix"] = fix

        except Exception as e:
            print(f"⚠️ Error processing {query_name}: {e}")
            query["ai_explanation"] = f"AI explanation generation failed: {str(e)}"
            # Add default fixes for files
            for file_finding in files:
                file_finding["ai_fix"] = "AI fix generation failed"

        return query

    # Process queries in parallel with limited concurrency
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all queries for processing
        future_to_query = {executor.submit(process_single_query, query): query for query in queries_with_findings}

        # Collect results as they complete
        for future in as_completed(future_to_query):
            query = future_to_query[future]
            try:
                enriched_query = future.result()
                enriched_queries.append(enriched_query)
            except Exception as e:
                print(f"❌ Error processing query {query.get('query_name', 'Unknown')}: {e}")
                enriched_queries.append(query)

    # Add queries without findings
    enriched_queries.extend(queries_without_findings)

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


def explain_findings(queries: List[Dict], output_html: Optional[str] = None) -> List[Dict]:
    """
    Generate AI-powered explanations for security findings with business risk context.
    Optimized for performance with parallel processing and reduced API calls.

    Args:
        queries: List of query results from KICS
        output_html: Optional path for HTML output file

    Returns:
        List of queries with AI explanations and business risk assessment added
    """
    # Get API key with fallback support
    api_key = config.settings.get_openai_api_key()
    if not api_key:
        print("⚠️ No OpenAI API key available. AI explanations will be disabled.")
        print("💡 Set OPENAI_API_KEY environment variable or use demo mode.")
        return queries

    client = OpenAI(api_key=api_key)

    # Use parallel processing with limited concurrency to avoid rate limits
    max_workers = min(
        config.settings.ai_max_concurrent_requests,
        len([q for q in queries if q.get("files")]),
    )

    print(f"🚀 Starting AI explanation generation...")
    print(f"📊 Total queries: {len(queries)}")
    print(f"🔍 Queries with findings: {len([q for q in queries if q.get('files')])}")
    print(f"⚡ Using {max_workers} concurrent workers")
    print(f"⏱️ Request timeout: {config.settings.ai_request_timeout}s")

    start_time = time.time()

    enriched_queries = batch_generate_explanations(client, queries, max_workers)

    total_time = time.time() - start_time
    print(f"✅ AI explanation generation completed in {total_time:.2f}s")
    print(f"📈 Average time per query: {total_time/max(1, len([q for q in queries if q.get('files')])):.2f}s")

    # Generate HTML report if requested
    if output_html:
        # Calculate total cost for HTML report
        total_cost = 0.0
        for query in queries:
            risk_assessment = query.get("risk_assessment", {})
            cost_str = risk_assessment.get("cost_estimate", "$0")

            # Parse cost string to extract numerical value
            if "$" in cost_str:
                try:
                    # Remove $ and any text in parentheses
                    cost_clean = cost_str.replace("$", "").split("(")[0].strip()

                    # Handle K notation (e.g., "1K" = 1000)
                    if "K" in cost_clean:
                        cost_clean = cost_clean.replace("K", "000")

                    # Handle ranges (e.g., "1K-10K")
                    if "-" in cost_clean:
                        min_cost, max_cost = cost_clean.split("-")
                        avg_cost = (float(min_cost) + float(max_cost)) / 2
                    else:
                        # Remove any remaining non-numeric characters
                        cost_clean = "".join(c for c in cost_clean if c.isdigit() or c == ".")
                        avg_cost = float(cost_clean) if cost_clean else 0.0

                    total_cost += avg_cost
                    print(f"🔍 Debug - Parsed cost '{cost_str}' to {avg_cost}, total now: {total_cost}")
                except (ValueError, AttributeError) as e:
                    print(f"🔍 Debug - Could not parse cost '{cost_str}': {e}")
                    continue

        generate_html_report(enriched_queries, output_html, total_cost)

    return enriched_queries


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
