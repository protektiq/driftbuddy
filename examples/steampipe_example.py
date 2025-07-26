#!/usr/bin/env python3
"""
Example script demonstrating Steampipe integration with DriftBuddy
"""

import sys
import os
from pathlib import Path

# Add the parent directory to the path so we can import driftbuddy
sys.path.insert(0, str(Path(__file__).parent.parent))

def example_aws_security_scan():
    """Example: Run AWS security scan"""
    print("🔍 Example: AWS Security Scan")
    print("=" * 40)
    
    try:
        from src.driftbuddy.steampipe_integration import SteampipeIntegration
        
        steampipe = SteampipeIntegration()
        
        if not steampipe.steampipe_installed:
            print("❌ Steampipe not installed")
            return
        
        if not steampipe.plugins_installed.get("aws", False):
            print("❌ AWS plugin not installed")
            print("💡 Run: steampipe plugin install aws")
            return
        
        print("✅ Steampipe and AWS plugin ready")
        
        # Run security scan
        results = steampipe.scan_shadow_resources("aws")
        
        if "error" not in results:
            print(f"📊 Found {results.get('total_count', 0)} shadow resources")
            
            # Generate report
            report_file = steampipe.generate_steampipe_report(results)
            print(f"📄 Report generated: {report_file}")
        else:
            print(f"❌ Scan failed: {results['error']}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def example_custom_query():
    """Example: Run custom Steampipe query"""
    print("\n🔍 Example: Custom Query")
    print("=" * 40)
    
    try:
        from src.driftbuddy.steampipe_integration import SteampipeIntegration
        
        steampipe = SteampipeIntegration()
        
        if not steampipe.steampipe_installed:
            print("❌ Steampipe not installed")
            return
        
        # Custom query to find public S3 buckets
        custom_query = """
        SELECT 
            name,
            bucket_policy_is_public,
            versioning_enabled,
            logging_enabled
        FROM aws_s3_bucket 
        WHERE bucket_policy_is_public = true
        LIMIT 10
        """
        
        print("🔍 Running custom query...")
        success, results = steampipe.query_infrastructure(custom_query, "aws")
        
        if success:
            print(f"✅ Query successful! Found {len(results)} results")
            
            for i, result in enumerate(results[:3]):  # Show first 3
                print(f"  {i+1}. {result.get('name', 'Unknown')} - Public: {result.get('bucket_policy_is_public', 'Unknown')}")
        else:
            print("❌ Query failed")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def example_drift_detection():
    """Example: Drift detection"""
    print("\n🔍 Example: Drift Detection")
    print("=" * 40)
    
    try:
        from src.driftbuddy.steampipe_integration import SteampipeIntegration
        
        steampipe = SteampipeIntegration()
        
        if not steampipe.steampipe_installed:
            print("❌ Steampipe not installed")
            return
        
        # Simulate drift detection
        print("🔍 Checking for infrastructure drift...")
        
        # Query for resources that might not be in IaC
        drift_queries = [
            "SELECT name FROM aws_s3_bucket WHERE name LIKE '%test%' LIMIT 5",
            "SELECT instance_id FROM aws_ec2_instance WHERE state = 'running' LIMIT 5"
        ]
        
        extra_resources = []
        
        for query in drift_queries:
            success, results = steampipe.query_infrastructure(query, "aws")
            if success and results:
                extra_resources.extend(results)
        
        if extra_resources:
            print(f"🚨 Found {len(extra_resources)} potential drift resources:")
            for resource in extra_resources[:3]:  # Show first 3
                name = resource.get('name') or resource.get('instance_id', 'Unknown')
                print(f"  - {name}")
        else:
            print("✅ No drift detected")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def example_cli_integration():
    """Example: Using DriftBuddy CLI with Steampipe"""
    print("\n🔍 Example: DriftBuddy CLI Integration")
    print("=" * 40)
    
    print("💡 You can use DriftBuddy CLI with Steampipe:")
    print()
    print("  # AWS Security Scan")
    print("  python driftbuddy.py --cloud aws --scan-type security")
    print()
    print("  # Azure Shadow Resources")
    print("  python driftbuddy.py --cloud azure --scan-type shadow")
    print()
    print("  # GCP Drift Detection")
    print("  python driftbuddy.py --cloud gcp --scan-type drift")
    print()
    print("  # All AWS Scans")
    print("  python driftbuddy.py --cloud aws --all-scans")
    print()
    print("  # Combined IaC + Cloud Scanning")
    print("  python driftbuddy.py ./terraform-code --all --cloud aws --scan-type security")

def main():
    """Run all examples"""
    print("☁️ Steampipe Integration Examples")
    print("=" * 50)
    
    examples = [
        example_aws_security_scan,
        example_custom_query,
        example_drift_detection,
        example_cli_integration
    ]
    
    for example in examples:
        try:
            example()
        except KeyboardInterrupt:
            print("\n⏹️ Example interrupted by user")
            break
        except Exception as e:
            print(f"❌ Example failed: {e}")
        
        print("\n" + "-" * 50)
    
    print("\n🎉 Examples completed!")
    print("\n💡 Next steps:")
    print("   1. Install Steampipe: curl -s -L https://steampipe.io/install.sh | sh")
    print("   2. Install plugins: steampipe plugin install aws")
    print("   3. Configure cloud credentials")
    print("   4. Run: python driftbuddy.py --cloud aws --scan-type security")

if __name__ == "__main__":
    main() 