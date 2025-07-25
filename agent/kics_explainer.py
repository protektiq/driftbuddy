from openai import OpenAI
import json
import os
from dotenv import load_dotenv

# Load API key
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Load results
with open("test_data/output/results.json") as f:
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

        print("\nResponse:\n")
        print(response.choices[0].message.content)
        print("\n" + "=" * 50 + "\n")

if not has_findings:
    print("No findings found in any queries.")
