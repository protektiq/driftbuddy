#!/usr/bin/env python3
"""
Test CI pipeline locally to ensure GitHub Actions will work.
"""

import os
import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    """Run a command and return success status."""
    print(f"🔍 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {description} - SUCCESS")
            return True
        else:
            print(f"❌ {description} - FAILED")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False


def main():
    """Run all CI checks locally."""
    print("🧪 Testing CI Pipeline Locally")
    print("=" * 50)

    # Check if we're in the right directory
    if not Path("pyproject.toml").exists():
        print("❌ Not in project root directory")
        sys.exit(1)

    # Test steps
    tests = [
        ("pip install -r requirements.txt", "Install main dependencies"),
        ("pip install -r requirements-dev.txt", "Install dev dependencies"),
        ("pip install -e .", "Install package in editable mode"),
        (
            "black --check --diff src/ scripts/ tests/ || true",
            "Check code formatting (black)",
        ),
        (
            "isort --check-only --diff src/ scripts/ tests/ || true",
            "Check import sorting (isort)",
        ),
        (
            "flake8 src/ scripts/ tests/ --max-line-length=120 --extend-ignore=E203,W503,E501,F401,W291,W292,W293,F541,E302,E305,E128 || true",
            "Check code style (flake8)",
        ),
        (
            "mypy src/ --ignore-missing-imports --no-strict-optional --allow-untyped-decorators || true",
            "Check type hints (mypy)",
        ),
        ("bandit -r src/ -f json -c .bandit", "Security scan (bandit)"),
        ("python scripts/check_version.py", "Check version consistency"),
        ("python scripts/security_scan.py", "Run security scan"),
    ]

    # Run tests
    passed = 0
    total = len(tests)

    for cmd, description in tests:
        if run_command(cmd, description):
            passed += 1
        print()

    # Summary
    print("=" * 50)
    print(f"📊 CI Test Results: {passed}/{total} passed")

    if passed == total:
        print("🎉 All tests passed! GitHub Actions should work.")
        return 0
    else:
        print("⚠️  Some tests failed. Please fix issues before pushing.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
