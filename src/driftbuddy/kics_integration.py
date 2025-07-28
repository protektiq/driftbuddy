"""
Real KICS (Keeping Infrastructure as Code Secure) Integration
Phase 3B: Real Integrations
"""

import json
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class KICSIntegration:
    """Real KICS integration for IaC security scanning"""
    
    def __init__(self, kics_path: str = "kics"):
        self.kics_path = kics_path
        self.supported_platforms = [
            "terraform", "cloudformation", "kubernetes", 
            "dockerfile", "ansible", "openapi", "azure"
        ]
    
    def check_kics_installation(self) -> bool:
        """Check if KICS is properly installed"""
        try:
            result = subprocess.run(
                [self.kics_path, "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def scan_directory(self, scan_path: str, output_format: str = "json") -> Dict[str, Any]:
        """
        Scan a directory for IaC security issues using KICS
        
        Args:
            scan_path: Path to directory containing IaC files
            output_format: Output format (json, sarif, html)
            
        Returns:
            Dictionary containing scan results
        """
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{output_format}', delete=False) as tmp_file:
                output_file = tmp_file.name
            
            # Build KICS command
            cmd = [
                self.kics_path,
                "scan",
                "-p", scan_path,
                "-o", output_file,
                "--output-name", "driftbuddy-scan",
                "--report-formats", output_format,
                "--type", "all"
            ]
            
            logger.info(f"Running KICS scan: {' '.join(cmd)}")
            
            # Execute KICS scan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            # Read results
            scan_results = self._parse_kics_output(output_file, output_format)
            
            # Clean up
            os.unlink(output_file)
            
            return {
                "success": result.returncode == 0,
                "scan_path": scan_path,
                "timestamp": datetime.utcnow().isoformat(),
                "kics_version": self._get_kics_version(),
                "results": scan_results,
                "stderr": result.stderr if result.stderr else None,
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "KICS scan timed out after 5 minutes",
                "scan_path": scan_path,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"KICS scan failed: {str(e)}")
            return {
                "success": False,
                "error": f"KICS scan failed: {str(e)}",
                "scan_path": scan_path,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def scan_file(self, file_path: str, output_format: str = "json") -> Dict[str, Any]:
        """
        Scan a single IaC file for security issues
        
        Args:
            file_path: Path to the IaC file
            output_format: Output format (json, sarif, html)
            
        Returns:
            Dictionary containing scan results
        """
        try:
            # Create temporary output file
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{output_format}', delete=False) as tmp_file:
                output_file = tmp_file.name
            
            # Build KICS command for single file
            cmd = [
                self.kics_path,
                "scan",
                "-p", file_path,
                "-o", output_file,
                "--output-name", f"driftbuddy-{Path(file_path).stem}",
                "--report-formats", output_format,
                "--type", "all"
            ]
            
            logger.info(f"Running KICS scan on file: {' '.join(cmd)}")
            
            # Execute KICS scan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout for single file
            )
            
            # Read results
            scan_results = self._parse_kics_output(output_file, output_format)
            
            # Clean up
            os.unlink(output_file)
            
            return {
                "success": result.returncode == 0,
                "file_path": file_path,
                "timestamp": datetime.utcnow().isoformat(),
                "kics_version": self._get_kics_version(),
                "results": scan_results,
                "stderr": result.stderr if result.stderr else None,
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "KICS scan timed out",
                "file_path": file_path,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"KICS scan failed: {str(e)}")
            return {
                "success": False,
                "error": f"KICS scan failed: {str(e)}",
                "file_path": file_path,
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def _parse_kics_output(self, output_file: str, output_format: str) -> Dict[str, Any]:
        """Parse KICS output file"""
        try:
            if output_format == "json":
                with open(output_file, 'r') as f:
                    return json.load(f)
            elif output_format == "sarif":
                with open(output_file, 'r') as f:
                    return json.load(f)
            elif output_format == "html":
                with open(output_file, 'r') as f:
                    return {"html_content": f.read()}
            else:
                return {"error": f"Unsupported output format: {output_format}"}
        except Exception as e:
            logger.error(f"Failed to parse KICS output: {str(e)}")
            return {"error": f"Failed to parse output: {str(e)}"}
    
    def _get_kics_version(self) -> str:
        """Get KICS version"""
        try:
            result = subprocess.run(
                [self.kics_path, "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return "unknown"
        except:
            return "unknown"
    
    def get_supported_queries(self) -> List[Dict[str, Any]]:
        """Get list of supported KICS queries"""
        try:
            result = subprocess.run(
                [self.kics_path, "query", "list"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse the query list output
                queries = []
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            queries.append({
                                "query_id": parts[0],
                                "query_name": parts[1],
                                "platform": parts[2],
                                "severity": parts[3] if len(parts) > 3 else "MEDIUM"
                            })
                return queries
            return []
        except Exception as e:
            logger.error(f"Failed to get KICS queries: {str(e)}")
            return []
    
    def validate_scan_path(self, scan_path: str) -> Dict[str, Any]:
        """Validate if the scan path contains supported IaC files"""
        try:
            path = Path(scan_path)
            if not path.exists():
                return {"valid": False, "error": "Path does not exist"}
            
            if not path.is_dir():
                return {"valid": False, "error": "Path is not a directory"}
            
            # Check for supported file types
            supported_extensions = [
                '.tf', '.tfvars', '.hcl',  # Terraform
                '.yaml', '.yml', '.json',  # CloudFormation, Kubernetes
                'Dockerfile', '.dockerfile',  # Docker
                '.yml', '.yaml',  # Ansible
                '.json', '.yaml', '.yml'  # OpenAPI
            ]
            
            found_files = []
            for ext in supported_extensions:
                found_files.extend(path.rglob(f"*{ext}"))
                if ext in ['Dockerfile', '.dockerfile']:
                    found_files.extend(path.rglob("Dockerfile*"))
            
            return {
                "valid": len(found_files) > 0,
                "found_files": [str(f) for f in found_files],
                "file_count": len(found_files)
            }
            
        except Exception as e:
            return {"valid": False, "error": f"Validation failed: {str(e)}"}


# Convenience function for easy integration
def run_kics_scan(scan_path: str, output_format: str = "json") -> Dict[str, Any]:
    """
    Convenience function to run a KICS scan
    
    Args:
        scan_path: Path to scan
        output_format: Output format
        
    Returns:
        Scan results dictionary
    """
    kics = KICSIntegration()
    
    if not kics.check_kics_installation():
        return {
            "success": False,
            "error": "KICS is not installed or not accessible",
            "scan_path": scan_path,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    # Validate scan path
    validation = kics.validate_scan_path(scan_path)
    if not validation.get("valid", False):
        return {
            "success": False,
            "error": validation.get("error", "Invalid scan path"),
            "scan_path": scan_path,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    return kics.scan_directory(scan_path, output_format) 