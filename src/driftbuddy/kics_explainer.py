from openai import OpenAI
import json
import os
import markdown
from datetime import datetime
from dotenv import load_dotenv
from .config import get_config

# Load configuration
config = get_config()
logger = config.settings.log_level

# Load API key with fallback support
api_key = config.settings.get_openai_api_key()
if not api_key:
    print("⚠️ No OpenAI API key available. AI explanations will be disabled.")
    print("💡 Set OPENAI_API_KEY environment variable or use demo mode.")
    exit(1)

client = OpenAI(api_key=api_key)

markdown_output = "../../outputs/analysis/kics_explained.md"

# Start fresh each time
with open(markdown_output, "w") as md_file:
    md_file.write(f"# KICS Explainer Output\n\nGenerated on {datetime.now()}\n\n")

# Load results
with open("../../test_data/output/results.json") as f:
    data = json.load(f)

queries = data.get("queries", [])
if not queries:
    print("No queries found.")
    exit()

has_findings = False

for query in queries:
    query_name = query.get("query_name")
    severity = query.get("severity", "UNKNOWN")
    description = query.get("description", "No description available")
    
    # Get findings for this query
    findings = query.get("files", [])
    
    if findings:
        has_findings = True
        
        # Write query header
        with open(markdown_output, "a") as md_file:
            md_file.write(f"## {query_name}\n\n")
            md_file.write(f"**Severity:** {severity}\n\n")
            md_file.write(f"**Description:** {description}\n\n")
        
        # Process each finding
        for finding in findings:
            file_path = finding.get("file_name", "Unknown file")
            line_number = finding.get("line", "Unknown line")
            issue = finding.get("issue", "No issue description")
            
            # Generate AI explanation for this finding
            try:
                prompt = f"""
                Explain this security finding in simple terms:
                
                File: {file_path}
                Line: {line_number}
                Issue: {issue}
                Severity: {severity}
                
                Provide:
                1. What the problem is
                2. Why it's a security risk
                3. How to fix it
                4. Best practices to prevent this
                
                Keep it concise and actionable.
                """
                
                response = client.chat.completions.create(
                    model=config.settings.openai_model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert explaining security findings in clear, actionable terms."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=config.settings.openai_max_tokens,
                    temperature=0.3
                )
                
                ai_explanation = response.choices[0].message.content.strip()
                
                # Write finding with AI explanation
                with open(markdown_output, "a") as md_file:
                    md_file.write(f"### Finding in {file_path}:{line_number}\n\n")
                    md_file.write(f"**Issue:** {issue}\n\n")
                    md_file.write("**AI Explanation:**\n\n")
                    md_file.write(f"{ai_explanation}\n\n")
                    md_file.write("---\n\n")
                
            except Exception as e:
                print(f"Error generating AI explanation for {file_path}: {e}")
                # Write finding without AI explanation
                with open(markdown_output, "a") as md_file:
                    md_file.write(f"### Finding in {file_path}:{line_number}\n\n")
                    md_file.write(f"**Issue:** {issue}\n\n")
                    md_file.write("*AI explanation unavailable*\n\n")
                    md_file.write("---\n\n")

if not has_findings:
    with open(markdown_output, "a") as md_file:
        md_file.write("## No Security Findings\n\n")
        md_file.write("Great job! No security issues were detected in your infrastructure code.\n\n")

# Convert to HTML
with open(markdown_output, "r") as md_file:
    md_text = md_file.read()

html_output = markdown.markdown(md_text, extensions=["fenced_code", "tables"])

html_filename = markdown_output.replace(".md", ".html")
with open(html_filename, "w") as html_file:
    html_file.write(f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KICS Explainer Output</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        h2 {{ color: #34495e; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }}
        h3 {{ color: #7f8c8d; }}
        code {{ background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; }}
        pre {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .severity-high {{ color: #e74c3c; }}
        .severity-medium {{ color: #f39c12; }}
        .severity-low {{ color: #27ae60; }}
    </style>
</head>
<body>
    {html_output}
</body>
</html>
    """)

print(f"✅ KICS explanation generated:")
print(f"   📄 Markdown: {markdown_output}")
print(f"   🌐 HTML: {html_filename}")
