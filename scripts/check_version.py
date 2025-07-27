#!/usr/bin/env python3
"""
Check version consistency across the project.
"""

import re
import sys
from pathlib import Path


def extract_version_from_pyproject():
    """Extract version from pyproject.toml."""
    pyproject_path = Path("pyproject.toml")
    if not pyproject_path.exists():
        return None

    with open(pyproject_path) as f:
        content = f.read()
        match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
        return match.group(1) if match else None


def extract_version_from_init():
    """Extract version from __init__.py."""
    init_path = Path("src/driftbuddy/__init__.py")
    if not init_path.exists():
        return None

    with open(init_path) as f:
        content = f.read()
        match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
        return match.group(1) if match else None


def extract_version_from_setup():
    """Extract version from setup.py."""
    setup_path = Path("setup.py")
    if not setup_path.exists():
        return None

    with open(setup_path) as f:
        content = f.read()
        match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
        return match.group(1) if match else None


def main():
    """Check version consistency."""
    print("🔍 Checking version consistency...")

    versions = {
        "pyproject.toml": extract_version_from_pyproject(),
        "src/driftbuddy/__init__.py": extract_version_from_init(),
        "setup.py": extract_version_from_setup(),
    }

    # Filter out None values
    versions = {k: v for k, v in versions.items() if v is not None}

    if not versions:
        print("❌ No version information found")
        return 1

    # Check if all versions match
    unique_versions = set(versions.values())
    if len(unique_versions) == 1:
        version = list(unique_versions)[0]
        print(f"✅ Version consistency check passed: {version}")
        print("📋 Version found in:")
        for file_path, ver in versions.items():
            print(f"   - {file_path}: {ver}")
        return 0
    else:
        print("❌ Version inconsistency detected:")
        for file_path, version in versions.items():
            print(f"   - {file_path}: {version}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
