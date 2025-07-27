#!/usr/bin/env python3
"""Fix file permissions for critical project files."""

import os
import stat
from pathlib import Path


def fix_permissions():
    """Set proper permissions for critical project files."""

    # List of critical files that should have 644 permissions
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

    print("🔧 Fixing file permissions...")

    for file_path in critical_files:
        if os.path.exists(file_path):
            try:
                # Get current permissions
                current_mode = os.stat(file_path).st_mode

                # Set permissions to 644 (rw-r--r--)
                # On Windows, this translates to removing write permissions for others
                new_mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH

                os.chmod(file_path, new_mode)

                # Verify the change
                new_stat = os.stat(file_path).st_mode
                if new_stat != current_mode:
                    print(f"✅ Fixed permissions for {file_path}")
                else:
                    print(f"⚠️  Permissions unchanged for {file_path} (may be expected on Windows)")

            except Exception as e:
                print(f"❌ Failed to fix permissions for {file_path}: {e}")
        else:
            print(f"⚠️  File not found: {file_path}")

    print("✅ Permission fix completed!")


if __name__ == "__main__":
    fix_permissions()
