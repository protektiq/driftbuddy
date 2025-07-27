#!/usr/bin/env python3
"""
Performance test runner for DriftBuddy.
This script properly sets up the Python path and runs the performance test.
"""

import os
import sys
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))


def main():
    """Run the performance test with proper path setup."""
    try:
        # Import and run the performance test
        from scripts.test_performance import main as run_test

        run_test()
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 Make sure you're running this from the project root directory")
        print(f"💡 Current directory: {os.getcwd()}")
        print(f"💡 Python path: {sys.path[:3]}...")
    except Exception as e:
        print(f"❌ Error running performance test: {e}")


if __name__ == "__main__":
    main()
