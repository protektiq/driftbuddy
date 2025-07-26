#!/usr/bin/env python3
"""
Test script to verify KICS integration fixes
"""

import subprocess
import sys
import os
from pathlib import Path

def test_kics_installation():
    """Test if KICS is properly installed"""
    try:
        result = subprocess.run(["kics", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ KICS found: {result.stdout.strip()}")
            return True
        else:
            print("❌ KICS is installed but not working properly")
            return False
    except FileNotFoundError:
        print("❌ KICS not found in PATH")
        return False
    except Exception as e:
        print(f"❌ Error checking KICS: {str(e)}")
        return False

def test_kics_scan():
    """Test KICS scan with a simple file"""
    test_file = "test_data/iac_example/main.tf"
    
    if not os.path.exists(test_file):
        print(f"❌ Test file not found: {test_file}")
        return False
    
    try:
        # Test basic KICS scan
        result = subprocess.run([
            "kics", "scan",
            "--path", test_file,
            "--output-path", "test_output",
            "--output-name", "test_results",
            "--report-formats", "json"
        ], capture_output=True, text=True, timeout=60)
        
        print(f"KICS exit code: {result.returncode}")
        print(f"STDOUT: {result.stdout[:200]}...")
        print(f"STDERR: {result.stderr[:200]}...")
        
        if result.returncode in [0, 40, 50, 60]:
            print("✅ KICS scan completed successfully")
            return True
        else:
            print("❌ KICS scan failed")
            return False
            
    except Exception as e:
        print(f"❌ Error testing KICS scan: {str(e)}")
        return False

def main():
    print("🧪 Testing KICS Integration Fixes")
    print("=" * 50)
    
    # Test 1: KICS Installation
    print("\n1. Testing KICS Installation...")
    if not test_kics_installation():
        print("❌ KICS installation test failed")
        sys.exit(1)
    
    # Test 2: KICS Scan
    print("\n2. Testing KICS Scan...")
    if not test_kics_scan():
        print("❌ KICS scan test failed")
        sys.exit(1)
    
    print("\n✅ All tests passed! KICS integration should work properly.")

if __name__ == "__main__":
    main() 