#!/usr/bin/env python3
"""
Test script to verify timestamped filename generation
"""

import os
from datetime import datetime
from pathlib import Path

def test_timestamped_filename():
    """Test the timestamped filename generation"""
    from driftbuddy import generate_timestamped_filename
    
    print("🧪 Testing Timestamped Filename Generation")
    print("=" * 50)
    
    # Test 1: Basic filename generation
    print("\n1. Testing basic filename generation...")
    filename = generate_timestamped_filename("security_report", "md")
    print(f"Generated filename: {filename}")
    
    # Verify filename format
    if filename.startswith("driftbuddy_security_report_") and filename.endswith(".md"):
        print("✅ Basic filename format is correct")
    else:
        print("❌ Basic filename format is incorrect")
        return False
    
    # Test 2: Directory creation
    print("\n2. Testing directory creation...")
    test_dir = "test_reports"
    filename_with_dir = generate_timestamped_filename("security_dashboard", "html", test_dir)
    print(f"Generated filename with directory: {filename_with_dir}")
    
    # Check if directory was created
    if os.path.exists(test_dir):
        print("✅ Directory was created successfully")
        # Clean up
        os.rmdir(test_dir)
    else:
        print("❌ Directory was not created")
        return False
    
    # Test 3: Timestamp format
    print("\n3. Testing timestamp format...")
    timestamp_part = filename.split("_")[-1].replace(".md", "")
    try:
        datetime.strptime(timestamp_part, "%Y%m%d_%H%M%S")
        print("✅ Timestamp format is correct")
    except ValueError:
        print("❌ Timestamp format is incorrect")
        return False
    
    print("\n✅ All timestamped filename tests passed!")
    return True

if __name__ == "__main__":
    test_timestamped_filename() 