from openai import OpenAI
import json
import os
import markdown
from datetime import datetime
from dotenv import load_dotenv

# Load API key
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

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
    severity = query.get("severity")
    description = query.get("description")
    files = query.get("files", [])

    for finding in files:
        has_findings = True
        prompt = f"""
        The following issue was found in a Terraform file:
        - Query: {query_name}
        - File: {finding['file_name']}
        - Severity: {severity}
        - Line: {finding['line']}
        - Description: {description}

        Please explain this issue in plain English and provide a secure Terraform code fix.
        """

        print(f"Sending prompt for: {query_name}")
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
        )

        explanation = response.choices[0].message.content.strip()

        print("\nResponse:\n")
        print(explanation)
        print("\n" + "="*50 + "\n")

        # Append to markdown file
        # Append to markdown file
        with open(markdown_output, "a") as md_file:
            md_file.write(f"## {query_name}\n")
            md_file.write(f"**File:** `{finding['file_name']}`\n\n")
            md_file.write(f"**Severity:** `{severity}`  \n")
            md_file.write(f"**Line:** `{finding['line']}`  \n")
            md_file.write(f"**Description:** {description}\n\n")
            md_file.write(f"### Explanation & Fix:\n{explanation}\n\n")
            md_file.write("---\n\n")


if not has_findings:
    print("No findings found in any queries.")

# Convert markdown to HTML
with open(markdown_output, "r") as md_file:
    md_text = md_file.read()

html_output = markdown.markdown(md_text, extensions=["fenced_code", "tables"])

# Save to .html
with open("kics_explained.html", "w") as html_file:
    html_file.write(f"""
    <html>
    <head>
      <meta charset="UTF-8">
      <title>KICS Explainer Output</title>
      <style>
        body {{ font-family: Arial, sans-serif; padding: 20px; max-width: 800px; margin: auto; }}
        pre {{ background: #f4f4f4; padding: 10px; overflow-x: auto; }}
        code {{ font-family: monospace; }}
        h2 {{ color: #2c3e50; }}
      </style>
    </head>
    <body>
      {html_output}
    </body>
    </html>
    """)
print("✅ HTML report saved as kics_explained.html")
