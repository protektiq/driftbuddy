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

    with open(output_md, "w") as md_file:
        md_file.write(f"# KICS Explainer Output\n\nGenerated on {datetime.now()}\n\n")

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

            print(f"🧠 Sending prompt for: {query_name}")
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
            )

            explanation = response.choices[0].message.content.strip()

            print(f"\n📘 Response:\n{explanation}\n{'=' * 50}\n")

            with open(output_md, "a") as md_file:
                md_file.write(f"## {query_name}\n")
                md_file.write(f"**File:** `{finding['file_name']}`\n\n")
                md_file.write(f"**Severity:** `{severity}`  \n")
                md_file.write(f"**Line:** `{finding['line']}`  \n")
                md_file.write(f"**Description:** {description}\n\n")
                md_file.write(f"### Explanation & Fix:\n{explanation}\n\n")
                md_file.write("---\n\n")

    if not has_findings:
        print("⚠️ No findings found in any queries.")
        return

    convert_md_to_html(output_md, output_html)


def convert_md_to_html(md_file, html_file):
    with open(md_file, "r") as f:
        md_text = f.read()

    html_output = markdown.markdown(md_text, extensions=["fenced_code", "tables"])

    with open(html_file, "w") as f:
        f.write(f"""
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
    print(f"✅ HTML report saved as {html_file}")
