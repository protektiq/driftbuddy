"""
AI-powered explanation agent for DriftBuddy security findings.
Provides detailed, actionable explanations of security issues with business risk context.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from openai import OpenAI
from driftbuddy.config import get_config
from driftbuddy.risk_assessment import RiskMatrix

# Load configuration
config = get_config()

def load_kics_results(results_path: str) -> Dict[str, Any]:
    """
    Load KICS scan results from JSON file.
    
    Args:
        results_path: Path to the KICS results JSON file
        
    Returns:
        Dictionary containing the scan results
    """
    try:
        with open(results_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ Results file not found: {results_path}")
        return {}
    except json.JSONDecodeError:
        print(f"❌ Invalid JSON in results file: {results_path}")
        return {}

def explain_findings(queries: List[Dict], output_html: Optional[str] = None) -> List[Dict]:
    """
    Generate AI-powered explanations for security findings with business risk context.
    
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
    
    enriched_queries = []
    
    for query in queries:
        query_name = query.get("query_name", "Unknown Query")
        severity = query.get("severity", "UNKNOWN")
        description = query.get("description", "No description available")
        files = query.get("files", [])
        
        if not files:
            # No findings for this query
            enriched_queries.append(query)
            continue
        
        print(f"🤖 Generating AI explanations for: {query_name}")
        
        # Get business risk assessment
        risk_assessment = RiskMatrix.assess_risk(query_name, severity, description)
        
        # Generate AI explanation for the query with business context
        try:
            prompt = f"""
            As a cybersecurity expert and business risk analyst, explain this security finding with business context:
            
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
            
            Provide a comprehensive explanation including:
            1. What this security issue is (technical explanation)
            2. Why it's a business risk (impact on operations, compliance, reputation)
            3. How it can be exploited (attack scenarios)
            4. How to fix it (technical solution)
            5. Business justification for fixing it (cost-benefit analysis)
            6. Timeline and priority recommendations
            
            Make it clear and actionable for both technical teams and business stakeholders.
            Focus on the business impact and why this matters to the organization.
            """
            
            response = client.chat.completions.create(
                model=config.settings.openai_model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert and business risk analyst providing clear, actionable security advice with business context."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=config.settings.openai_max_tokens,
                temperature=0.3
            )
            
            ai_explanation = response.choices[0].message.content.strip()
            
            # Add AI explanation and risk assessment to query
            query["ai_explanation"] = ai_explanation
            query["risk_assessment"] = {
                "impact": risk_assessment.impact.value,
                "likelihood": risk_assessment.likelihood.value,
                "business_risk": risk_assessment.business_risk.value,
                "impact_description": risk_assessment.impact_description,
                "likelihood_description": risk_assessment.likelihood_description,
                "business_context": risk_assessment.business_context,
                "remediation_priority": risk_assessment.remediation_priority,
                "cost_estimate": risk_assessment.cost_estimate,
                "time_to_fix": risk_assessment.time_to_fix
            }
            
            # Generate specific explanations for each finding
            for file_finding in files:
                file_name = file_finding.get("file_name", "Unknown file")
                line_number = file_finding.get("line", "Unknown line")
                issue = file_finding.get("issue", "No issue description")
                
                try:
                    finding_prompt = f"""
                    Provide a specific fix for this security finding with business context:
                    
                    File: {file_name}
                    Line: {line_number}
                    Issue: {issue}
                    Technical Severity: {severity}
                    Business Risk: {risk_assessment.business_risk.value}
                    Estimated Cost: {risk_assessment.cost_estimate}
                    
                    Provide:
                    1. The exact code fix
                    2. Why this fix works (technical explanation)
                    3. Business benefits of implementing this fix
                    4. Additional security considerations
                    5. Implementation timeline and effort
                    
                    Be specific and provide actual code examples. Include business justification.
                    """
                    
                    finding_response = client.chat.completions.create(
                        model=config.settings.openai_model,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity expert providing specific code fixes with business context."},
                            {"role": "user", "content": finding_prompt}
                        ],
                        max_tokens=config.settings.openai_max_tokens,
                        temperature=0.3
                    )
                    
                    file_finding["ai_fix"] = finding_response.choices[0].message.content.strip()
                    
                except Exception as e:
                    print(f"⚠️ Error generating fix for {file_name}: {e}")
                    file_finding["ai_fix"] = "AI fix generation failed"
            
        except Exception as e:
            print(f"⚠️ Error generating explanation for {query_name}: {e}")
            query["ai_explanation"] = "AI explanation generation failed"
        
        enriched_queries.append(query)
    
    # Generate HTML report if requested
    if output_html:
        generate_html_report(enriched_queries, output_html)
    
    return enriched_queries

def generate_html_report(queries: List[Dict], output_path: str):
    """
    Generate an HTML report with AI explanations and business risk assessment.
    
    Args:
        queries: List of enriched queries with AI explanations and risk assessment
        output_path: Path for the HTML output file
    """
    
    # Calculate risk summary
    risk_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "minimal": 0
    }
    
    total_estimated_cost = 0
    
    for query in queries:
        risk_assessment = query.get("risk_assessment", {})
        business_risk = risk_assessment.get("business_risk", "Medium").lower()
        risk_summary[business_risk] += 1
        
        # Calculate total cost
        cost_str = risk_assessment.get("cost_estimate", "$0")
        if "$" in cost_str:
            try:
                cost_range = cost_str.replace("$", "").replace("K", "000").replace("+", "")
                if "-" in cost_range:
                    min_cost, max_cost = cost_range.split("-")
                    avg_cost = (int(min_cost) + int(max_cost)) / 2
                else:
                    avg_cost = int(cost_range)
                total_estimated_cost += avg_cost
            except:
                pass
    
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
            <h3>📋 Risk Matrix</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <th style="border: 1px solid #ddd; padding: 8px;">Impact/Likelihood</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Very High</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">High</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Medium</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Low</th>
                    <th style="border: 1px solid #ddd; padding: 8px;">Very Low</th>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">Critical</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #e74c3c; color: white;">🔴 Critical</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #e74c3c; color: white;">🔴 Critical</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #f39c12; color: white;">🟠 High</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">High</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #e74c3c; color: white;">🔴 Critical</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #f39c12; color: white;">🟠 High</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #f39c12; color: white;">🟠 High</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">Medium</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #f39c12; color: white;">🟠 High</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">Low</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #3498db; color: white;">🟡 Medium</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal</td>
                </tr>
                <tr>
                    <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">Minimal</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #27ae60; color: white;">🟢 Low</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal</td>
                    <td style="border: 1px solid #ddd; padding: 8px; background: #95a5a6; color: white;">⚪ Minimal</td>
                </tr>
            </table>
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
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"✅ HTML report generated: {output_path}")
    except Exception as e:
        print(f"❌ Error generating HTML report: {e}")

def main():
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

