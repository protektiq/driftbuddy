#!/usr/bin/env python3
"""
Version consistency checker for DriftBuddy.
Ensures version numbers are consistent across all files.
"""

import re
import sys
from pathlib import Path


def extract_version_from_pyproject():
    """Extract version from pyproject.toml."""
    pyproject_path = Path("pyproject.toml")
    if not pyproject_path.exists():
        return None
    
    with open(pyproject_path, "r") as f:
        content = f.read()
        match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
        return match.group(1) if match else None


def extract_version_from_init():
    """Extract version from __init__.py."""
    init_path = Path("src/__init__.py")
    if not init_path.exists():
        return None
    
    with open(init_path, "r") as f:
        content = f.read()
        match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
        return match.group(1) if match else None


def check_changelog_version(version):
    """Check if version is mentioned in CHANGELOG.md."""
    changelog_path = Path("CHANGELOG.md")
    if not changelog_path.exists():
        return False
    
    with open(changelog_path, "r") as f:
        content = f.read()
        return f"## [{version}]" in content


def main():
    """Main version check function."""
    print("🔍 Checking version consistency...")
    
    # Get versions from different sources
    pyproject_version = extract_version_from_pyproject()
    init_version = extract_version_from_init()
    
    if not pyproject_version:
        print("❌ Could not extract version from pyproject.toml")
        sys.exit(1)
    
    if not init_version:
        print("❌ Could not extract version from src/__init__.py")
        sys.exit(1)
    
    # Check if versions match
    if pyproject_version != init_version:
        print(f"❌ Version mismatch:")
        print(f"   pyproject.toml: {pyproject_version}")
        print(f"   src/__init__.py: {init_version}")
        sys.exit(1)
    
    # Check changelog
    if not check_changelog_version(pyproject_version):
        print(f"⚠️  Version {pyproject_version} not found in CHANGELOG.md")
        print("   Consider adding a new changelog entry")
    
    print(f"✅ Version consistency check passed: {pyproject_version}")
    return 0


if __name__ == "__main__":
    sys.exit(main()) 