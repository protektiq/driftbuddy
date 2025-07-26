import os
import json
import markdown
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI


def load_kics_results(path="test_data/output/results.json"):
    """Load KICS results with enhanced error handling"""
    try:
        if not os.path.exists(path):
            print(f"⚠️ Warning: Results file not found at {path}")
            return []
        
        with open(path) as f:
            data = json.load(f)
        
        queries = data.get("queries", [])
        if not queries:
            print("ℹ️ No queries found in results file")
            return []
        
        return queries
        
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in results file: {str(e)}")
        return []
    except Exception as e:
        print(f"❌ Error loading KICS results: {str(e)}")
        return []


def explain_findings(queries, output_md="kics_explained.md", output_html="kics_explained.html"):
    """Explain findings with comprehensive error handling"""
    load_dotenv()
    
    # Check for OpenAI API key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("⚠️ Warning: OPENAI_API_KEY not found in environment variables")
        print("💡 AI explanations will be skipped. Reports will be generated without AI insights.")
        return queries
    
    try:
        client = OpenAI(api_key=api_key)
    except Exception as e:
        print(f"❌ Error initializing OpenAI client: {str(e)}")
        print("💡 Reports will be generated without AI explanations")
        return queries

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
        query_name = query.get("query_name", "Unknown Query")
        severity = query.get("severity", "UNKNOWN").upper()
        description = query.get("description", "No description available")
        query_url = query.get("query_url", "#")
        files = query.get("files", [])

        for finding in files:
            has_findings = True
            file_path = finding.get("file_name", "Unknown File")
            line = finding.get("line", "Unknown Line")

            # Create a comprehensive prompt for better AI explanations
            prompt = f"""
You are a security expert analyzing Infrastructure as Code (IaC) security findings. Please provide a clear, actionable explanation for the following security issue:

**Issue Details:**
- Query Name: {query_name}
- File: {file_path}
- Line: {line}
- Severity: {severity}
- Description: {description}

Please provide:
1. A plain English explanation of what this security issue means
2. Why it's a security concern
3. A specific, secure code example showing how to fix it
4. Best practices to prevent this issue

Keep the explanation concise but comprehensive. Focus on practical, actionable advice.
"""

            try:
                print(f"🧠 Sending prompt for: {query_name}")
                response = client.chat.completions.create(
                    model="gpt-4",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=500,
                    temperature=0.3
                )

                explanation = response.choices[0].message.content.strip()
                print(f"✅ AI explanation generated for: {query_name}")
                
            except Exception as e:
                print(f"⚠️ Warning: Failed to get AI explanation for {query_name}: {str(e)}")
                explanation = f"Unable to generate AI explanation for this finding. Error: {str(e)}"

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
        try:
            generate_html_dashboard(findings_by_severity, output_html)
        except Exception as e:
            print(f"❌ Error generating HTML dashboard: {str(e)}")
            print("💡 Markdown report will still be generated")
    
    # Return the enriched queries for markdown rendering
    return queries


def generate_html_dashboard(findings_by_severity, output_html):
    """Generate a beautiful HTML dashboard with findings grouped by severity"""
    
    # Count findings by severity
    severity_counts = {severity: len(findings) for severity, findings in findings_by_severity.items()}
    total_findings = sum(severity_counts.values())
    
    # Handle no findings case
    if total_findings == 0:
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
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 40px 20px;
                }}
                
                .header {{
                    background: white;
                    border-radius: 15px;
                    padding: 40px;
                    margin-bottom: 30px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                    text-align: center;
                }}
                
                .header h1 {{
                    color: #27ae60;
                    font-size: 2.5em;
                    margin-bottom: 10px;
                }}
                
                .header .subtitle {{
                    color: #7f8c8d;
                    font-size: 1.1em;
                }}
                
                .success-card {{
                    background: white;
                    border-radius: 15px;
                    padding: 40px;
                    text-align: center;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                }}
                
                .success-icon {{
                    font-size: 4em;
                    color: #27ae60;
                    margin-bottom: 20px;
                }}
                
                .success-message {{
                    font-size: 1.3em;
                    color: #2c3e50;
                    margin-bottom: 20px;
                }}
                
                .footer {{
                    text-align: center;
                    padding: 30px;
                    color: white;
                    font-size: 0.9em;
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
                
                <div class="success-card">
                    <div class="success-icon">✅</div>
                    <div class="success-message">No Security Issues Found!</div>
                    <p>Great news! Your infrastructure appears to follow security best practices.</p>
                    <p><strong>Total Findings:</strong> 0</p>
                    <p><strong>Status:</strong> ✅ Secure</p>
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
        return
    
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

