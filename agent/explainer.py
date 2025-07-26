import os
import json
import markdown
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI


def load_kics_results(path="test_data/output/results.json"):
    with open(path) as f:
        data = json.load(f)
    return data.get("queries", [])


def explain_findings(queries, output_md="kics_explained.md", output_html="kics_explained.html"):
    load_dotenv()
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    has_findings = False
    findings_by_severity = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
        "INFO": []
    }

    # Process all findings first
    for query in queries:
        query_name = query.get("query_name")
        severity = query.get("severity", "UNKNOWN").upper()
        description = query.get("description")
        query_url = query.get("query_url", "#")
        files = query.get("files", [])

        for finding in files:
            has_findings = True
            file_path = finding.get("file_name", "Unknown File")
            line = finding.get("line", "Unknown Line")

            prompt = f"""
        The following issue was found in a Terraform file:
        - Query: {query_name}
        - File: {file_path}
        - Severity: {severity}
        - Line: {line}
        - Description: {description}

        Please explain this issue in plain English and provide a secure Terraform code fix.
        """
            print(f"🧠 Sending prompt for: {query_name}")
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
            )

            explanation = response.choices[0].message.content.strip()
            print(f"\n📘 Response:\n{explanation}\n{'=' * 50}\n")

            # Store finding with all details
            finding_data = {
                "query_name": query_name,
                "severity": severity,
                "description": description,
                "file_path": file_path,
                "line": line,
                "explanation": explanation,
                "url": query_url
            }
            
            findings_by_severity[severity].append(finding_data)
            
            # Also enrich the original query for markdown rendering
            query["explanation"] = explanation
            query["url"] = query_url

    if not has_findings:
        print("⚠️ No findings found in any queries.")
        return queries

    # Generate HTML dashboard if output_html is specified
    if output_html:
        generate_html_dashboard(findings_by_severity, output_html)
    
    # Return the enriched queries for markdown rendering
    return queries


def generate_html_dashboard(findings_by_severity, output_html):
    """Generate a beautiful HTML dashboard with findings grouped by severity"""
    
    # Count findings by severity
    severity_counts = {severity: len(findings) for severity, findings in findings_by_severity.items()}
    total_findings = sum(severity_counts.values())
    
    # Generate table of contents
    toc_html = ""
    if total_findings > 3:  # Only show TOC if there are many findings
        toc_html = """
        <div class="toc">
            <h3>📋 Table of Contents</h3>
            <ul>
        """
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if severity_counts[severity] > 0:
                toc_html += f'<li><a href="#{severity.lower()}-section">{severity} ({severity_counts[severity]})</a></li>'
        toc_html += "</ul></div>"
    
    # Generate findings HTML
    findings_html = ""
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        findings = findings_by_severity[severity]
        if findings:
            findings_html += f'<div id="{severity.lower()}-section" class="severity-section">'
            findings_html += f'<h2 class="severity-header {severity.lower()}">{severity} ({len(findings)})</h2>'
            
            for i, finding in enumerate(findings):
                findings_html += f"""
                <div class="finding-card">
                    <div class="finding-header">
                        <span class="severity-badge {severity.lower()}">{severity}</span>
                        <h3 class="finding-title">{finding['query_name']}</h3>
                    </div>
                    <div class="finding-details">
                        <div class="detail-item">
                            <strong>📁 File:</strong> <code>{finding['file_path']}</code>
                        </div>
                        <div class="detail-item">
                            <strong>📍 Line:</strong> <code>{finding['line']}</code>
                        </div>
                        <div class="detail-item">
                            <strong>📝 Description:</strong> {finding['description']}
                        </div>
                    </div>
                    <div class="finding-explanation">
                        <h4>🔍 Explanation & Fix</h4>
                        <div class="explanation-content">
                            {finding['explanation'].replace('\n', '<br>')}
                        </div>
                    </div>
                    <div class="finding-footer">
                        <a href="{finding['url']}" target="_blank" class="learn-more-btn">📚 Learn More</a>
                    </div>
                </div>
                """
            findings_html += '</div>'
    
    # Generate summary cards
    summary_cards = ""
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts[severity]
        if count > 0:
            summary_cards += f"""
            <div class="summary-card {severity.lower()}">
                <div class="summary-number">{count}</div>
                <div class="summary-label">{severity}</div>
            </div>
            """
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DriftBuddy Security Report</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }}
            
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }}
            
            .header {{
                background: white;
                border-radius: 15px;
                padding: 30px;
                margin-bottom: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                text-align: center;
            }}
            
            .header h1 {{
                color: #2c3e50;
                font-size: 2.5em;
                margin-bottom: 10px;
            }}
            
            .header .subtitle {{
                color: #7f8c8d;
                font-size: 1.1em;
            }}
            
            .summary-section {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            
            .summary-card {{
                background: white;
                border-radius: 15px;
                padding: 25px;
                text-align: center;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                transition: transform 0.3s ease;
            }}
            
            .summary-card:hover {{
                transform: translateY(-5px);
            }}
            
            .summary-number {{
                font-size: 2.5em;
                font-weight: bold;
                margin-bottom: 5px;
            }}
            
            .summary-label {{
                font-size: 1.1em;
                font-weight: 500;
            }}
            
            .summary-card.critical {{
                border-left: 5px solid #e74c3c;
            }}
            .summary-card.critical .summary-number {{
                color: #e74c3c;
            }}
            
            .summary-card.high {{
                border-left: 5px solid #f39c12;
            }}
            .summary-card.high .summary-number {{
                color: #f39c12;
            }}
            
            .summary-card.medium {{
                border-left: 5px solid #3498db;
            }}
            .summary-card.medium .summary-number {{
                color: #3498db;
            }}
            
            .summary-card.low {{
                border-left: 5px solid #27ae60;
            }}
            .summary-card.low .summary-number {{
                color: #27ae60;
            }}
            
            .summary-card.info {{
                border-left: 5px solid #95a5a6;
            }}
            .summary-card.info .summary-number {{
                color: #95a5a6;
            }}
            
            .toc {{
                background: white;
                border-radius: 15px;
                padding: 25px;
                margin-bottom: 30px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                position: sticky;
                top: 20px;
                z-index: 100;
            }}
            
            .toc h3 {{
                color: #2c3e50;
                margin-bottom: 15px;
            }}
            
            .toc ul {{
                list-style: none;
            }}
            
            .toc li {{
                margin-bottom: 8px;
            }}
            
            .toc a {{
                color: #3498db;
                text-decoration: none;
                font-weight: 500;
                transition: color 0.3s ease;
            }}
            
            .toc a:hover {{
                color: #2980b9;
            }}
            
            .severity-section {{
                margin-bottom: 40px;
            }}
            
            .severity-header {{
                background: white;
                border-radius: 15px 15px 0 0;
                padding: 20px 25px;
                margin-bottom: 0;
                font-size: 1.5em;
                font-weight: 600;
            }}
            
            .severity-header.critical {{
                background: linear-gradient(135deg, #e74c3c, #c0392b);
                color: white;
            }}
            
            .severity-header.high {{
                background: linear-gradient(135deg, #f39c12, #e67e22);
                color: white;
            }}
            
            .severity-header.medium {{
                background: linear-gradient(135deg, #3498db, #2980b9);
                color: white;
            }}
            
            .severity-header.low {{
                background: linear-gradient(135deg, #27ae60, #229954);
                color: white;
            }}
            
            .severity-header.info {{
                background: linear-gradient(135deg, #95a5a6, #7f8c8d);
                color: white;
            }}
            
            .finding-card {{
                background: white;
                border-radius: 0 0 15px 15px;
                margin-bottom: 20px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                overflow: hidden;
            }}
            
            .finding-header {{
                padding: 20px 25px;
                border-bottom: 1px solid #ecf0f1;
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            
            .severity-badge {{
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.8em;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            
            .severity-badge.critical {{
                background: #e74c3c;
                color: white;
            }}
            
            .severity-badge.high {{
                background: #f39c12;
                color: white;
            }}
            
            .severity-badge.medium {{
                background: #3498db;
                color: white;
            }}
            
            .severity-badge.low {{
                background: #27ae60;
                color: white;
            }}
            
            .severity-badge.info {{
                background: #95a5a6;
                color: white;
            }}
            
            .finding-title {{
                color: #2c3e50;
                font-size: 1.3em;
                margin: 0;
            }}
            
            .finding-details {{
                padding: 20px 25px;
                background: #f8f9fa;
            }}
            
            .detail-item {{
                margin-bottom: 10px;
            }}
            
            .detail-item:last-child {{
                margin-bottom: 0;
            }}
            
            .detail-item code {{
                background: #e9ecef;
                padding: 2px 6px;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
            }}
            
            .finding-explanation {{
                padding: 20px 25px;
            }}
            
            .finding-explanation h4 {{
                color: #2c3e50;
                margin-bottom: 15px;
                font-size: 1.1em;
            }}
            
            .explanation-content {{
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                border-left: 4px solid #3498db;
                line-height: 1.7;
            }}
            
            .finding-footer {{
                padding: 15px 25px;
                background: #f8f9fa;
                border-top: 1px solid #ecf0f1;
            }}
            
            .learn-more-btn {{
                display: inline-block;
                background: #3498db;
                color: white;
                padding: 8px 16px;
                border-radius: 6px;
                text-decoration: none;
                font-weight: 500;
                transition: background 0.3s ease;
            }}
            
            .learn-more-btn:hover {{
                background: #2980b9;
            }}
            
            .footer {{
                text-align: center;
                padding: 30px;
                color: white;
                font-size: 0.9em;
            }}
            
            @media (max-width: 768px) {{
                .container {{
                    padding: 10px;
                }}
                
                .header h1 {{
                    font-size: 2em;
                }}
                
                .summary-section {{
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                }}
                
                .finding-header {{
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 10px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ DriftBuddy Security Report</h1>
                <p class="subtitle">Infrastructure as Code Security Analysis Dashboard</p>
                <p class="subtitle">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary-section">
                {summary_cards}
            </div>
            
            {toc_html}
            
            <div class="findings-content">
                {findings_html}
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by DriftBuddy - AI-Powered Security Scanner</p>
        </div>
    </body>
    </html>
    """
    
    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"✅ Beautiful HTML dashboard saved as {output_html}")


def convert_md_to_html(md_file, html_file):
    # This function is kept for backward compatibility but is no longer used
    # The new generate_html_dashboard function creates a much better HTML report
    pass

