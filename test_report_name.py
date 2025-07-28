#!/usr/bin/env python3
"""
Test script to verify report name functionality
"""
import requests
import json

# Test configuration
BASE_URL = "http://localhost:8080"
LOGIN_DATA = {
    "email": "admin@driftbuddy.com",
    "password": "admin123"
}

def test_report_generation():
    """Test report generation with custom name"""
    
    # Step 1: Login and get JWT token
    print("🔐 Logging in...")
    login_response = requests.post(f"{BASE_URL}/api/auth/login", data=LOGIN_DATA)
    if login_response.status_code != 200:
        print(f"❌ Login failed: {login_response.status_code}")
        print(f"Response: {login_response.text}")
        return
    
    login_data = login_response.json()
    access_token = login_data.get('access_token')
    if not access_token:
        print("❌ No access token received")
        return
    
    print("✅ Login successful")
    print(f"   Token: {access_token[:20]}...")
    
    # Set up headers with JWT token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    # Step 2: Generate a report with custom name
    print("\n📊 Generating report with custom name...")
    custom_name = "My Custom Test Report"
    report_url = f"{BASE_URL}/api/reports/generate/8?format=html&report_name={custom_name}"
    
    report_response = requests.post(report_url, headers=headers)
    print(f"Report generation status: {report_response.status_code}")
    
    if report_response.status_code == 200:
        report_data = report_response.json()
        print(f"✅ Report generated successfully!")
        print(f"   Report ID: {report_data.get('report_id')}")
        print(f"   Report Path: {report_data.get('report_path')}")
    else:
        print(f"❌ Report generation failed: {report_response.text}")
        return
    
    # Step 3: Check the reports list
    print("\n📋 Checking reports list...")
    reports_response = requests.get(f"{BASE_URL}/api/reports", headers=headers)
    
    if reports_response.status_code == 200:
        reports = reports_response.json()
        print(f"✅ Found {len(reports)} reports")
        
        # Find our newly created report
        for report in reports:
            print(f"   Report: {report.get('name')} (ID: {report.get('id')})")
            if report.get('id') == report_data.get('report_id'):
                print(f"   🎯 This is our new report!")
                print(f"   Expected name: '{custom_name}'")
                print(f"   Actual name: '{report.get('name')}'")
                
                if report.get('name') == custom_name:
                    print("   ✅ Name matches!")
                else:
                    print("   ❌ Name doesn't match!")
    else:
        print(f"❌ Failed to get reports: {reports_response.status_code}")

if __name__ == "__main__":
    test_report_generation() 