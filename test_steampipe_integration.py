#!/usr/bin/env python3
"""
Test script for Steampipe integration with DriftBuddy
"""

import sys
import os
from pathlib import Path

def test_steampipe_import():
    """Test if Steampipe integration can be imported"""
    try:
        from steampipe_integration import SteampipeIntegration
        print("✅ Steampipe integration imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import Steampipe integration: {e}")
        return False

def test_steampipe_installation():
    """Test Steampipe installation"""
    try:
        from steampipe_integration import SteampipeIntegration
        steampipe = SteampipeIntegration()
        
        if steampipe.steampipe_installed:
            print("✅ Steampipe is installed and accessible")
            return True
        else:
            print("❌ Steampipe is not installed or not accessible")
            return False
    except Exception as e:
        print(f"❌ Error testing Steampipe installation: {e}")
        return False

def test_plugins_installation():
    """Test cloud provider plugins installation"""
    try:
        from steampipe_integration import SteampipeIntegration
        steampipe = SteampipeIntegration()
        
        available_plugins = [plugin for plugin, installed in steampipe.plugins_installed.items() if installed]
        
        if available_plugins:
            print(f"✅ Available plugins: {', '.join(available_plugins)}")
            return True
        else:
            print("❌ No cloud provider plugins installed")
            print("💡 Install plugins with:")
            print("   steampipe plugin install aws")
            print("   steampipe plugin install azure")
            print("   steampipe plugin install gcp")
            return False
    except Exception as e:
        print(f"❌ Error testing plugins: {e}")
        return False

def test_query_functionality():
    """Test basic query functionality"""
    try:
        from steampipe_integration import SteampipeIntegration
        steampipe = SteampipeIntegration()
        
        # Test with a simple query
        test_query = "SELECT 1 as test_column"
        success, results = steampipe.query_infrastructure(test_query, "aws")
        
        if success:
            print("✅ Query functionality working")
            return True
        else:
            print("❌ Query functionality failed")
            return False
    except Exception as e:
        print(f"❌ Error testing query functionality: {e}")
        return False

def test_report_generation():
    """Test report generation functionality"""
    try:
        from steampipe_integration import SteampipeIntegration
        steampipe = SteampipeIntegration()
        
        # Create test data
        test_results = {
            "provider": "aws",
            "timestamp": "2024-12-25T14:30:52",
            "security_issues": [
                {"name": "test-bucket", "issue": "public access"},
                {"name": "test-user", "issue": "admin access"}
            ],
            "total_issues": 2,
            "scan_type": "security"
        }
        
        # Generate report
        report_file = steampipe.generate_steampipe_report(test_results, "test_reports")
        
        if report_file and os.path.exists(report_file):
            print(f"✅ Report generated successfully: {report_file}")
            # Clean up
            os.remove(report_file)
            return True
        else:
            print("❌ Report generation failed")
            return False
    except Exception as e:
        print(f"❌ Error testing report generation: {e}")
        return False

def test_driftbuddy_integration():
    """Test DriftBuddy CLI integration"""
    try:
        # Test if driftbuddy.py can import steampipe_integration
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Import the main driftbuddy module
        import driftbuddy
        
        # Check if STEAMPIPE_AVAILABLE is set
        if hasattr(driftbuddy, 'STEAMPIPE_AVAILABLE'):
            if driftbuddy.STEAMPIPE_AVAILABLE:
                print("✅ DriftBuddy Steampipe integration enabled")
                return True
            else:
                print("❌ DriftBuddy Steampipe integration not available")
                return False
        else:
            print("❌ DriftBuddy doesn't have Steampipe integration")
            return False
    except Exception as e:
        print(f"❌ Error testing DriftBuddy integration: {e}")
        return False

def main():
    """Run all Steampipe integration tests"""
    print("🧪 Testing Steampipe Integration")
    print("=" * 50)
    
    tests = [
        ("Import Test", test_steampipe_import),
        ("Installation Test", test_steampipe_installation),
        ("Plugins Test", test_plugins_installation),
        ("Query Test", test_query_functionality),
        ("Report Test", test_report_generation),
        ("DriftBuddy Integration", test_driftbuddy_integration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 {test_name}...")
        if test_func():
            passed += 1
        else:
            print(f"❌ {test_name} failed")
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Steampipe integration is ready.")
        print("\n💡 Next steps:")
        print("   1. Configure cloud credentials")
        print("   2. Run: python driftbuddy.py --cloud aws --scan-type security")
        print("   3. Check generated reports")
    else:
        print("⚠️ Some tests failed. Please check the setup.")
        print("\n💡 Setup steps:")
        print("   1. Install Steampipe: curl -s -L https://steampipe.io/install.sh | sh")
        print("   2. Install plugins: steampipe plugin install aws")
        print("   3. Configure credentials")
        print("   4. Run tests again")

if __name__ == "__main__":
    main() 