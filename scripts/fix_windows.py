#!/usr/bin/env python3
"""Windows-compatible fix script for DriftBuddy CI issues."""

import os
import stat
import subprocess
import sys
from pathlib import Path


def fix_permissions():
    """Fix file permissions for critical project files."""
    print("🔧 Fixing file permissions...")

    critical_files = [
        "src/driftbuddy/config.py",
        "src/driftbuddy/core.py",
        "src/agent/explainer.py",
        "scripts/check_version.py",
        "scripts/security_scan.py",
        "README.md",
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "setup.py",
        ".pre-commit-config.yaml",
        ".bandit",
        "driftbuddy.py",
    ]

    for file_path in critical_files:
        if os.path.exists(file_path):
            try:
                # On Windows, we'll try to set read-only for others
                # This is the closest equivalent to 644 permissions
                current_mode = os.stat(file_path).st_mode

                # Remove write permissions for group and others
                new_mode = current_mode & ~stat.S_IWGRP & ~stat.S_IWOTH

                os.chmod(file_path, new_mode)
                print(f"✅ Fixed permissions for {file_path}")

            except Exception as e:
                print(f"❌ Failed to fix permissions for {file_path}: {e}")
        else:
            print(f"⚠️  File not found: {file_path}")


def fix_whitespace():
    """Fix trailing whitespace in Python files."""
    print("🔧 Fixing trailing whitespace...")

    python_files = [
        "src/driftbuddy/exceptions.py",
        "tests/test_risk_assessment.py",
        "tests/test_steampipe_integration.py",
    ]

    for file_path in python_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, encoding="utf-8") as f:
                    content = f.read()

                # Remove trailing whitespace
                lines = content.split("\n")
                cleaned_lines = [line.rstrip() for line in lines]
                cleaned_content = "\n".join(cleaned_lines)

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(cleaned_content)

                print(f"✅ Fixed whitespace in {file_path}")
            except Exception as e:
                print(f"❌ Failed to fix whitespace in {file_path}: {e}")


def install_type_stubs():
    """Install missing type stubs."""
    print("🔧 Installing type stubs...")

    try:
        # Use sys.executable to get the correct Python interpreter
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "types-Markdown",
                "types-requests",
                "types-PyYAML",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        print("✅ Type stubs installed successfully")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install type stubs: {e}")
        print(f"STDOUT: {e.stdout}")
        print(f"STDERR: {e.stderr}")


def run_ci_tests():
    """Run the CI tests to check if fixes worked."""
    print("🔧 Running CI tests...")

    try:
        result = subprocess.run([sys.executable, "scripts/test_ci.py"], capture_output=True, text=True)

        print("📊 CI Test Results:")
        print(result.stdout)
        if result.stderr:
            print("STDERR:")
            print(result.stderr)

        return result.returncode == 0
    except Exception as e:
        print(f"❌ Failed to run CI tests: {e}")
        return False


def main():
    """Main function to fix all issues."""
    print("🔧 DriftBuddy Windows Fix Script")
    print("=" * 50)

    # Fix permissions
    fix_permissions()
    print()

    # Fix whitespace
    fix_whitespace()
    print()

    # Install type stubs
    install_type_stubs()
    print()

    # Run tests
    print("🔧 Testing fixes...")
    success = run_ci_tests()

    if success:
        print("\n✅ All fixes applied successfully!")
        print("🎉 CI tests should now pass")
    else:
        print("\n⚠️  Some issues may still remain")
        print("💡 Check the output above for details")


if __name__ == "__main__":
    main()
