#!/usr/bin/env python3
"""
Simple test for KICS integration
"""

import requests
import json

BASE_URL = "http://localhost:8080"

def test_kics():
    print("🔍 Testing KICS Integration")
    print("=" * 40)
    
    # Login
    print("1. Logging in...")
    login_data = {
        "email": "admin@driftbuddy.com",
        "password": "admin123"
    }
    
    response = requests.post(f"{BASE_URL}/api/auth/login", data=login_data)
    if response.status_code != 200:
        print(f"❌ Login failed: {response.status_code}")
        return
    
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("✅ Login successful")
    
    # Create scan
    print("\n2. Creating scan...")
    scan_data = {
        "name": "KICS Test",
        "description": "Testing KICS integration",
        "scan_type": "kics",
        "target_path": "test_data/iac_example/main"
    }
    
    response = requests.post(f"{BASE_URL}/api/scans", json=scan_data, headers=headers)
    if response.status_code != 200:
        print(f"❌ Scan creation failed: {response.status_code}")
        return
    
    scan_id = response.json()["id"]
    print(f"✅ Scan created: ID {scan_id}")
    
    # Run scan
    print("\n3. Running KICS scan...")
    response = requests.post(f"{BASE_URL}/api/scans/{scan_id}/run", headers=headers)
    if response.status_code != 200:
        print(f"❌ Scan execution failed: {response.status_code}")
        print(f"Response: {response.text}")
        return
    
    result = response.json()
    print("✅ Scan executed successfully")
    print(f"   Findings count: {result.get('findings_count', 0)}")
    
    # Get findings
    print("\n4. Getting findings...")
    response = requests.get(f"{BASE_URL}/api/scans/{scan_id}/findings", headers=headers)
    if response.status_code == 200:
        findings = response.json()
        print(f"✅ Found {len(findings)} findings")
        
        for i, finding in enumerate(findings[:3], 1):
            print(f"   {i}. {finding.get('query_name', 'Unknown')}")
            print(f"      Severity: {finding.get('severity', 'Unknown')}")
            print(f"      File: {finding.get('file_path', 'Unknown')}")
            print()
    else:
        print(f"❌ Failed to get findings: {response.status_code}")
    
    print("🎉 KICS Integration Test Complete!")

if __name__ == "__main__":
    test_kics() 