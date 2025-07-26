import subprocess
import os
import sys
from pathlib import Path
from agent.explainer import load_kics_results, explain_findings

def run_kics(scan_path, output_dir="test_data/output"):
    print(f"🔍 Running KICS scan on: {scan_path}")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    result = subprocess.run([
        "kics",
        "scan",
        "--path", scan_path,
        "--output-path", output_dir,
        "--output-name", "results",
        "--report-formats", "json",
        "--queries-path", "/mnt/d/driftbuddy/kics/assets/queries"
    ])
    
    print(f"[DEBUG] KICS exited with code: {result.returncode}")

    if result.returncode in [0, 40, 60]:
        print(f"✅ KICS scan completed. Results saved to: {output_dir}/results.json")
    else:
        print("❌ KICS scan failed due to an unexpected error.")
        sys.exit(result.returncode)



def main():
    if len(sys.argv) != 2:
        print("Usage: python3 driftbuddy.py <path_to_terraform_code>")
        sys.exit(1)

    scan_path = sys.argv[1]
    run_kics(scan_path)
    queries = load_kics_results("test_data/output/results.json")
    explain_findings(queries)

if __name__ == "__main__":
    main()
