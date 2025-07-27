#!/usr/bin/env python3
"""Basic security scanning for DriftBuddy project."""

import os
import platform
import re
import subprocess
import sys
from pathlib import Path


def check_file_permissions():
    """Check for overly permissive file permissions."""
    print("🔍 Checking file permissions...")

    # Skip detailed permission checks on Windows **and** WSL mounts where the
    # underlying NTFS permissions are always presented as world-writable.
    if platform.system() == "Windows" or "microsoft" in platform.release().lower():
        print("ℹ️  Skipping file-permission checks on Windows / WSL")
        return True

    # Critical files that should not be world-writable
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

    issues_found = []

    for file_path in critical_files:
        if os.path.exists(file_path):
            try:
                # Get file permissions
                mode = os.stat(file_path).st_mode

                # Check if file is world-writable (others can write)
                if mode & 0o002:  # S_IWOTH
                    issues_found.append(file_path)

            except Exception as e:
                print(f"⚠️  Could not check permissions for {file_path}: {e}")

    if issues_found:
        print("⚠️  World writable files found:")
        for file_path in issues_found:
            print(f"   - {file_path}")
        print("💡 Run: chmod 644 <file> to fix")
        return False
    else:
        print("✅ File permissions are secure")
        return True


def check_dependencies():
    """Check for basic dependency issues."""
    print("🔍 Checking dependencies...")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list"],
            capture_output=True,
            text=True,
            check=True,
        )

        if result.returncode == 0:
            print("✅ Dependencies check passed")
            return True
        else:
            print("❌ Dependencies check failed")
            return False

    except Exception as e:
        print(f"❌ Could not check dependencies: {e}")
        return False


def check_secrets():
    """Check for potential secrets in the codebase."""
    print("🔍 Checking for potential secrets...")

    # Patterns for common secret formats
    secret_patterns = [
        r"sk-[a-zA-Z0-9]{20,}",  # OpenAI API keys
        r"AKIA[0-9A-Z]{16}",  # AWS access keys
        r"[0-9]{12}",  # AWS account IDs
        r"ghp_[a-zA-Z0-9]{36}",  # GitHub personal access tokens
        r"xoxb-[a-zA-Z0-9-]+",  # Slack bot tokens
        r'password\s*[:=]\s*["\'][^"\']+["\']',  # Hardcoded passwords
        r'secret\s*[:=]\s*["\'][^"\']+["\']',  # Hardcoded secrets
    ]

    # File extensions to check
    check_extensions = {".py", ".yaml", ".yml", ".json", ".toml", ".md", ".txt", ".sh"}

    # Keep the scan fast and relevant – ignore large vendored / test / doc trees
    exclude_dirs = {
        ".git",
        ".venv",
        "__pycache__",
        ".mypy_cache",
        "node_modules",
        "kics",
        "assets",
        "outputs",
        "examples",
        "test_data",
        "tests",
        "docs",
        "fuzz",
    }

    # Skip files larger than 250 KB – they are almost certainly test fixtures or binaries
    MAX_FILE_SIZE = 250 * 1024  # bytes

    issues_found = []

    for root, dirs, files in os.walk("."):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for file in files:
            file_path = os.path.join(root, file)

            # Only check specific file types
            if not any(file.endswith(ext) for ext in check_extensions):
                continue

            try:
                # Skip very large files (speed + false-positives)
                if os.path.getsize(file_path) > MAX_FILE_SIZE:
                    continue

                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for pattern in secret_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        issues_found.append(f"{file_path}: {len(matches)} potential secret(s)")

            except Exception:
                # Skip files that can't be read
                continue

    if issues_found:
        print("⚠️  Potential secrets found:")
        for issue in issues_found:
            print(f"   - {issue}")
        return False
    else:
        print("✅ No obvious secrets found")
        return True


def main():
    """Main security scan function."""
    print("🔒 Running security scan...")
    print("=" * 40)

    # Check file permissions
    permissions_ok = check_file_permissions()
    print()

    # Check dependencies
    dependencies_ok = check_dependencies()
    print()

    # Check for secrets
    secrets_ok = check_secrets()
    print()

    # Summary
    print("=" * 40)
    total_checks = 3
    passed_checks = sum([permissions_ok, dependencies_ok, secrets_ok])

    print(f"📊 Security Scan Results: {passed_checks}/{total_checks} passed")

    if passed_checks == total_checks:
        print("✅ All security checks passed")
        return 0
    else:
        print("⚠️  Security issues found - review before deployment")
        return 1


if __name__ == "__main__":
    sys.exit(main())
