#!/usr/bin/env python3
"""
Test script for LangChain integration with DriftBuddy
Demonstrates the enhanced AI capabilities with KICS and Steampipe
"""

import sys
from pathlib import Path

# Add src directory to Python path for development
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))


def test_langchain_integration():
    """Test the LangChain integration with sample data"""
    try:
        from driftbuddy.agent.enhanced_agent import create_enhanced_agent
        from driftbuddy.langchain_integration import create_langchain_integration

        print("🔗 Testing LangChain Integration with DriftBuddy")
        print("=" * 50)

        # Test 1: Basic LangChain integration
        print("\n1. Testing basic LangChain integration...")
        langchain_integration = create_langchain_integration()
        print("✅ LangChain integration created successfully")

        # Test 2: Enhanced agent
        print("\n2. Testing enhanced security agent...")
        agent = create_enhanced_agent()
        print("✅ Enhanced security agent created successfully")

        # Test 3: Sample KICS results
        print("\n3. Testing with sample KICS results...")
        sample_kics_results = {
            "queries": [
                {
                    "query_name": "S3 Bucket Public Access",
                    "severity": "HIGH",
                    "description": "S3 bucket is publicly accessible",
                    "files": [{"file_name": "test_data/iac_example/aws-s3/aws_s3_vulnerable.tf", "line": 7, "issue": "S3 bucket allows public read access"}],
                },
                {
                    "query_name": "S3 Bucket Without Versioning",
                    "severity": "MEDIUM",
                    "description": "S3 bucket versioning is not enabled",
                    "files": [{"file_name": "test_data/iac_example/aws-s3/aws_s3_vulnerable.tf", "line": 15, "issue": "S3 bucket versioning is disabled"}],
                },
            ]
        }

        # Test enhanced analysis
        enhanced_results = agent.analyze_kics_results(sample_kics_results)
        print("✅ KICS results enhanced with LangChain analysis")

        # Test 4: Sample Steampipe results
        print("\n4. Testing with sample Steampipe results...")
        sample_steampipe_results = {
            "findings": [
                {
                    "query_name": "Unencrypted S3 Bucket",
                    "severity": "HIGH",
                    "description": "S3 bucket without encryption",
                    "resources": ["my-unencrypted-bucket-12345"],
                }
            ]
        }

        # Test enhanced analysis
        enhanced_steampipe = agent.analyze_steampipe_results(sample_steampipe_results)
        print("✅ Steampipe results enhanced with LangChain analysis")

        # Test 5: Comprehensive analysis
        print("\n5. Testing comprehensive analysis...")
        comprehensive_results = agent.run_comprehensive_analysis(kics_results=sample_kics_results, steampipe_results=sample_steampipe_results)
        print("✅ Comprehensive analysis completed")

        # Test 6: Generate report
        print("\n6. Testing report generation...")
        report_path = agent.generate_security_report(comprehensive_results)
        print(f"✅ Enhanced security report generated: {report_path}")

        print("\n🎉 All LangChain integration tests completed successfully!")
        print("\n📋 Summary of LangChain features tested:")
        print("   ✅ Basic LangChain integration")
        print("   ✅ Enhanced security agent")
        print("   ✅ KICS results enhancement")
        print("   ✅ Steampipe results enhancement")
        print("   ✅ Comprehensive analysis")
        print("   ✅ Report generation")

        return True

    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure to install LangChain dependencies:")
        print("   pip install langchain langchain-openai langchain-community")
        return False
    except Exception as e:
        print(f"❌ Error testing LangChain integration: {e}")
        return False


def test_langchain_tools():
    """Test individual LangChain tools"""
    try:
        from driftbuddy.langchain_integration import DriftBuddyLangChain

        print("\n🔧 Testing LangChain tools...")

        # Initialize LangChain integration
        langchain = DriftBuddyLangChain()

        # Test analysis chain
        print("1. Testing analysis chain...")
        sample_finding = {
            "query_name": "Test Security Issue",
            "severity": "HIGH",
            "description": "Test security finding for demonstration",
            "files": [{"file_name": "test.tf", "line": 10}],
        }

        analysis_result = langchain.analyze_with_context(sample_finding)
        print("✅ Analysis chain test completed")

        # Test remediation chain
        print("2. Testing remediation chain...")
        remediation_result = langchain.generate_remediation_with_chain(sample_finding)
        print("✅ Remediation chain test completed")

        # Test autonomous agent
        print("3. Testing autonomous agent...")
        agent_result = langchain.run_autonomous_analysis([sample_finding])
        print("✅ Autonomous agent test completed")

        print("🎉 All LangChain tools tests completed successfully!")
        return True

    except Exception as e:
        print(f"❌ Error testing LangChain tools: {e}")
        return False


def main():
    """Main test function"""
    print("🚀 DriftBuddy LangChain Integration Test")
    print("=" * 50)

    # Test basic integration
    success1 = test_langchain_integration()

    # Test individual tools
    success2 = test_langchain_tools()

    if success1 and success2:
        print("\n🎉 All tests passed! LangChain integration is working correctly.")
        print("\n📚 Next steps:")
        print("   1. Use --enable-langchain flag with driftbuddy-cli.py")
        print("   2. Explore enhanced analysis capabilities")
        print("   3. Create knowledge bases for specialized analysis")
    else:
        print("\n❌ Some tests failed. Please check the error messages above.")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
