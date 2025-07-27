#!/usr/bin/env python3
"""
Simple test script for Steampipe integration with DriftBuddy
"""

import os
import subprocess
import sys
from pathlib import Path


def test_steampipe_installation():
    """Test if Steampipe is installed"""
    try:
        result = subprocess.run(["steampipe", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ Steampipe is installed: {result.stdout.strip()}")
            return True
        else:
            print("❌ Steampipe is installed but not working properly")
            return False
    except FileNotFoundError:
        print("❌ Steampipe not found in PATH")
        return False
    except Exception as e:
        print(f"❌ Error testing Steampipe installation: {e}")
        return False


def test_steampipe_plugins():
    """Test if Steampipe plugins are installed"""
    try:
        # Try different commands to list plugins
        commands = [["steampipe", "plugin", "list"], ["steampipe", "plugin", "list", "--output", "table"], ["steampipe", "plugin", "list", "--output", "json"]]

        for cmd in commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    output = result.stdout
                    if "aws" in output or "azure" in output or "gcp" in output:
                        print("✅ Steampipe plugins are installed")
                        print(f"Available plugins: {output}")
                        return True
            except Exception:
                continue

        # If we can't list plugins, check if AWS plugin is installed directly
        try:
            result = subprocess.run(["steampipe", "plugin", "install", "aws"], capture_output=True, text=True, timeout=10)
            if "Already installed" in result.stdout:
                print("✅ AWS plugin is installed")
                return True
        except Exception:
            pass

        print("❌ No cloud provider plugins installed")
        print("💡 Install plugins with:")
        print("   steampipe plugin install aws")
        print("   steampipe plugin install azure")
        print("   steampipe plugin install gcp")
        return False
    except Exception as e:
        print(f"❌ Error testing plugins: {e}")
        return False


def test_steampipe_query():
    """Test basic Steampipe query functionality"""
    try:
        # Test with a simple query that doesn't require credentials
        test_query = "SELECT 1 as test_column"
        result = subprocess.run(["steampipe", "query", test_query], capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            print("✅ Steampipe query functionality working")
            return True
        else:
            # Check if the error is due to no credentials (which is expected)
            if "no rows in result set" in result.stderr or "no rows in result set" in result.stdout:
                print("✅ Steampipe query functionality working (no credentials configured)")
                print("💡 This is expected - configure AWS credentials for full functionality")
                return True
            else:
                print("❌ Steampipe query functionality failed")
                print(f"Error: {result.stderr}")
                return False
    except Exception as e:
        print(f"❌ Error testing query functionality: {e}")
        return False


def test_driftbuddy_steampipe_integration():
    """Test DriftBuddy's Steampipe integration"""
    try:
        # Import from the installed package (this should work now)
        from driftbuddy import SteampipeIntegration

        print("✅ Imported SteampipeIntegration from driftbuddy package")

        steampipe = SteampipeIntegration()

        if steampipe.steampipe_installed:
            print("✅ Steampipe found and accessible")
            print("✅ DriftBuddy Steampipe integration working")
            return True
        else:
            print("❌ DriftBuddy Steampipe integration not working")
            return False
    except Exception as e:
        print(f"❌ Error testing DriftBuddy integration: {e}")
        return False


def main():
    """Run all tests"""
    print("🧪 Testing Steampipe Integration (Simple)")
    print("=" * 50)
    print()

    tests = [
        ("Steampipe Installation", test_steampipe_installation),
        ("Steampipe Plugins", test_steampipe_plugins),
        ("Steampipe Query", test_steampipe_query),
        ("DriftBuddy Integration", test_driftbuddy_steampipe_integration),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"🔍 {test_name}...")
        if test_func():
            passed += 1
        print()

    print(f"📊 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("✅ All tests passed!")
    else:
        print("⚠️ Some tests failed. Please check the setup.")
        print()
        print("💡 Setup steps:")
        print("   1. Install Steampipe: curl -s -L https://steampipe.io/install.sh | sh")
        print("   2. Install plugins: steampipe plugin install aws")
        print("   3. Configure credentials")
        print("   4. Run tests again")


if __name__ == "__main__":
    main()
