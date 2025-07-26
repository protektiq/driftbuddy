#!/usr/bin/env python3
"""
Security scanning script for DriftBuddy.
Performs basic security checks on the codebase.
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Any


def check_for_hardcoded_secrets(file_path: Path) -> List[str]:
    """Check for hardcoded secrets in a file."""
    issues = []
    
    # Common secret patterns
    secret_patterns = [
        r'password\s*=\s*["\'][^"\']+["\']',
        r'secret\s*=\s*["\'][^"\']+["\']',
        r'api_key\s*=\s*["\'][^"\']+["\']',
        r'token\s*=\s*["\'][^"\']+["\']',
        r'key\s*=\s*["\'][^"\']+["\']',
        r'aws_access_key_id\s*=\s*["\'][^"\']+["\']',
        r'aws_secret_access_key\s*=\s*["\'][^"\']+["\']',
    ]
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        for pattern in secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                issues.append(f"Line {line_num}: Potential hardcoded secret found")
                
    except Exception as e:
        issues.append(f"Error reading file: {e}")
    
    return issues


def check_for_debug_statements(file_path: Path) -> List[str]:
    """Check for debug statements in code."""
    issues = []
    
    debug_patterns = [
        r'print\s*\(',
        r'console\.log\(',
        r'debugger;',
        r'pdb\.set_trace\(',
        r'breakpoint\(',
    ]
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        for pattern in debug_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                issues.append(f"Line {line_num}: Debug statement found")
                
    except Exception as e:
        issues.append(f"Error reading file: {e}")
    
    return issues


def check_file_permissions(file_path: Path) -> List[str]:
    """Check file permissions for security issues."""
    issues = []
    
    try:
        stat = file_path.stat()
        # Check if file is world writable
        if stat.st_mode & 0o002:
            issues.append("File is world writable")
        
        # Check if file is world readable (for sensitive files)
        if stat.st_mode & 0o004 and file_path.name in ['.env', 'secrets.json']:
            issues.append("Sensitive file is world readable")
            
    except Exception as e:
        issues.append(f"Error checking permissions: {e}")
    
    return issues


def scan_directory(directory: Path, exclude_patterns: List[str] = None) -> Dict[str, List[str]]:
    """Scan a directory for security issues."""
    if exclude_patterns is None:
        exclude_patterns = [
            r'\.git/',
            r'__pycache__/',
            r'\.venv/',
            r'node_modules/',
            r'\.pytest_cache/',
            r'\.mypy_cache/',
            r'build/',
            r'dist/',
            r'\.tox/',
        ]
    
    results = {
        "hardcoded_secrets": [],
        "debug_statements": [],
        "permission_issues": [],
    }
    
    # File extensions to scan
    code_extensions = {'.py', '.js', '.ts', '.java', '.go', '.rb', '.php'}
    config_extensions = {'.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.env'}
    
    for file_path in directory.rglob('*'):
        if file_path.is_file():
            # Skip excluded patterns
            if any(re.search(pattern, str(file_path)) for pattern in exclude_patterns):
                continue
            
            # Check file extension
            if file_path.suffix in code_extensions or file_path.suffix in config_extensions:
                # Check for hardcoded secrets
                secret_issues = check_for_hardcoded_secrets(file_path)
                if secret_issues:
                    results["hardcoded_secrets"].extend([
                        f"{file_path}: {issue}" for issue in secret_issues
                    ])
                
                # Check for debug statements (only in code files)
                if file_path.suffix in code_extensions:
                    debug_issues = check_for_debug_statements(file_path)
                    if debug_issues:
                        results["debug_statements"].extend([
                            f"{file_path}: {issue}" for issue in debug_issues
                        ])
                
                # Check file permissions
                permission_issues = check_file_permissions(file_path)
                if permission_issues:
                    results["permission_issues"].extend([
                        f"{file_path}: {issue}" for issue in permission_issues
                    ])
    
    return results


def main():
    """Main security scan function."""
    print("🔒 Running security scan...")
    
    # Scan the current directory
    current_dir = Path(".")
    results = scan_directory(current_dir)
    
    # Report results
    total_issues = 0
    
    if results["hardcoded_secrets"]:
        print("\n❌ Hardcoded secrets found:")
        for issue in results["hardcoded_secrets"]:
            print(f"   {issue}")
        total_issues += len(results["hardcoded_secrets"])
    
    if results["debug_statements"]:
        print("\n⚠️  Debug statements found:")
        for issue in results["debug_statements"]:
            print(f"   {issue}")
        total_issues += len(results["debug_statements"])
    
    if results["permission_issues"]:
        print("\n⚠️  Permission issues found:")
        for issue in results["permission_issues"]:
            print(f"   {issue}")
        total_issues += len(results["permission_issues"])
    
    if total_issues == 0:
        print("✅ No security issues found")
        return 0
    else:
        print(f"\n📊 Total issues found: {total_issues}")
        print("💡 Consider addressing these issues before deployment")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 