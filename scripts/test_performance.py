#!/usr/bin/env python3
"""
Performance testing script for DriftBuddy AI explanations.
Measures the time taken to generate AI explanations and provides optimization suggestions.
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def load_test_data() -> List[Dict]:
    """Load test data for performance testing."""
    test_file = Path("test_data/output/results.json")

    if not test_file.exists():
        print("❌ Test data not found. Please run KICS scan first.")
        return []

    try:
        with open(test_file) as f:
            data = json.load(f)
        return data.get("queries", [])
    except Exception as e:
        print(f"❌ Error loading test data: {e}")
        return []


def analyze_performance(queries: List[Dict]) -> Dict:
    """Analyze the performance characteristics of the queries."""
    total_queries = len(queries)
    queries_with_findings = [q for q in queries if q.get("files")]
    total_findings = sum(len(q.get("files", [])) for q in queries_with_findings)

    # Estimate API calls (old vs new method)
    old_api_calls = total_queries + total_findings  # 1 per query + 1 per finding
    new_api_calls = len(queries_with_findings)  # 1 per query with findings

    # Estimate time savings
    estimated_old_time = old_api_calls * 2.5  # ~2.5s per API call
    estimated_new_time = new_api_calls * 3.0  # ~3s per comprehensive call

    return {
        "total_queries": total_queries,
        "queries_with_findings": len(queries_with_findings),
        "total_findings": total_findings,
        "old_api_calls": old_api_calls,
        "new_api_calls": new_api_calls,
        "estimated_old_time": estimated_old_time,
        "estimated_new_time": estimated_new_time,
        "time_savings": estimated_old_time - estimated_new_time,
        "time_savings_percent": (((estimated_old_time - estimated_new_time) / estimated_old_time) * 100 if estimated_old_time > 0 else 0),
    }


def print_performance_report(analysis: Dict):
    """Print a detailed performance analysis report."""
    print("\n" + "=" * 60)
    print("🚀 DRIFTBUDDY PERFORMANCE ANALYSIS")
    print("=" * 60)

    print(f"\n📊 Dataset Statistics:")
    print(f"   Total Queries: {analysis['total_queries']}")
    print(f"   Queries with Findings: {analysis['queries_with_findings']}")
    print(f"   Total File Findings: {analysis['total_findings']}")

    print(f"\n⚡ API Call Optimization:")
    print(f"   Old Method API Calls: {analysis['old_api_calls']}")
    print(f"   New Method API Calls: {analysis['new_api_calls']}")
    print(
        f"   API Calls Reduced: {analysis['old_api_calls'] - analysis['new_api_calls']} ({((analysis['old_api_calls'] - analysis['new_api_calls']) / analysis['old_api_calls'] * 100):.1f}%)"
    )

    print(f"\n⏱️ Time Estimates:")
    print(f"   Estimated Old Method Time: {analysis['estimated_old_time']:.1f}s")
    print(f"   Estimated New Method Time: {analysis['estimated_new_time']:.1f}s")
    print(f"   Time Savings: {analysis['time_savings']:.1f}s ({analysis['time_savings_percent']:.1f}%)")

    print(f"\n💡 Performance Recommendations:")

    if analysis["total_findings"] > 20:
        print("   🔴 High volume detected - consider increasing AI_MAX_CONCURRENT_REQUESTS")
        print("   🔴 Consider using AI_BATCH_SIZE to group similar findings")

    if analysis["time_savings_percent"] > 50:
        print("   🟢 Excellent optimization achieved!")
    elif analysis["time_savings_percent"] > 25:
        print("   🟡 Good optimization - consider further tuning")
    else:
        print("   🟡 Moderate optimization - review configuration")

    print(f"\n🔧 Configuration Tips:")
    print(f"   Set AI_MAX_CONCURRENT_REQUESTS=3-5 for optimal performance")
    print(f"   Set AI_REQUEST_TIMEOUT=60 to prevent hanging requests")
    print(f"   Monitor API rate limits and adjust concurrency accordingly")

    print("\n" + "=" * 60)


def main():
    """Main performance testing function."""
    print("🔍 DriftBuddy Performance Testing")
    print("=" * 40)

    # Load test data
    queries = load_test_data()
    if not queries:
        print("❌ No test data available. Please run a KICS scan first.")
        return

    # Analyze performance
    analysis = analyze_performance(queries)

    # Print report
    print_performance_report(analysis)

    # Offer to run actual test
    print(f"\n🧪 Would you like to run an actual performance test?")
    print(f"   This will make real API calls to OpenAI.")
    print(f"   Estimated cost: ~${len([q for q in queries if q.get('files')]) * 0.02:.2f}")

    response = input("\nRun performance test? (y/N): ").lower()
    if response == "y":
        run_actual_test(queries)


def run_actual_test(queries: List[Dict]):
    """Run an actual performance test with real API calls."""
    print("\n🧪 Running actual performance test...")

    try:
        # Import using sys.path approach
        import sys

        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from agent.explainer import explain_findings

        start_time = time.time()
        enriched_queries = explain_findings(queries)
        total_time = time.time() - start_time

        print(f"\n✅ Actual Performance Results:")
        print(f"   Total Time: {total_time:.2f}s")
        print(f"   Queries Processed: {len([q for q in queries if q.get('files')])}")
        print(f"   Average Time per Query: {total_time/max(1, len([q for q in queries if q.get('files')])):.2f}s")

    except Exception as e:
        print(f"❌ Error during performance test: {e}")
        print("💡 Make sure you have set OPENAI_API_KEY environment variable")
        print(f"💡 Current working directory: {os.getcwd()}")
        print(f"💡 Python path: {sys.path[:3]}...")


if __name__ == "__main__":
    main()
