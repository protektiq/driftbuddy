"""
Service layer for DriftBuddy Web Interface
Handles scan operations, file processing, and KICS integration
"""

import asyncio
import os
import shutil

# Import DriftBuddy core functionality
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from .auth import get_user_permissions
from .models import Finding, Scan, ScanStatus, User

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from driftbuddy.config import get_config
from driftbuddy.core import run_kics, validate_scan_path
from driftbuddy.risk_assessment import RiskMatrix


class ScanService:
    """Service for managing security scans"""

    def __init__(self):
        self.config = get_config()
        self.upload_dir = Path("uploads")
        self.upload_dir.mkdir(exist_ok=True)

    async def create_scan(self, db: Session, user: User, name: str, description: Optional[str] = None, scan_type: str = "kics") -> Scan:
        """Create a new scan"""
        scan = Scan(
            user_id=user.id,
            organization_id=user.organization_id,
            name=name,
            description=description,
            scan_type=scan_type,
            status=ScanStatus.PENDING.value,
            metadata={},
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        return scan

    async def upload_files(self, scan_id: int, files: List[UploadFile]) -> Dict[str, Any]:
        """Upload and process files for scanning"""
        scan_dir = self.upload_dir / str(scan_id)
        scan_dir.mkdir(exist_ok=True)

        uploaded_files = []
        total_size = 0

        for file in files:
            # Validate file type
            if not self._is_valid_file_type(file.filename):
                raise HTTPException(status_code=400, detail=f"Invalid file type: {file.filename}")

            # Save file
            file_path = scan_dir / file.filename
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            uploaded_files.append(str(file_path))
            total_size += file_path.stat().st_size

        return {"scan_id": scan_id, "files": uploaded_files, "total_size": total_size, "file_count": len(uploaded_files)}

    def _is_valid_file_type(self, filename: str) -> bool:
        """Check if file type is supported for scanning"""
        valid_extensions = [".tf", ".yaml", ".yml", ".json", ".dockerfile", ".bicep", ".hcl", ".tfvars"]

        return any(filename.lower().endswith(ext) for ext in valid_extensions)

    async def run_kics_scan(self, db: Session, scan: Scan, scan_path: str) -> Dict[str, Any]:
        """Run KICS scan and process results"""
        try:
            # Update scan status
            scan.status = ScanStatus.RUNNING.value
            scan.updated_at = datetime.utcnow()
            db.commit()

            # Run KICS scan using existing DriftBuddy core
            kics_results = run_kics(scan_path)

            if not kics_results.get("success", False):
                scan.status = ScanStatus.FAILED.value
                scan.results = {"error": kics_results.get("error", "Unknown error")}
                db.commit()
                return kics_results

            # Load detailed results from the output file
            detailed_results = self._load_kics_results(kics_results.get("output_file"))
            
            # Process findings
            findings = await self._process_kics_findings(db, scan, detailed_results)

            # Update scan with enhanced results
            scan.status = ScanStatus.COMPLETED.value
            scan.results = {
                "kics_results": kics_results,
                "detailed_results": detailed_results,
                "findings_count": len(findings),
                "severity_summary": detailed_results.get("severity_counters", {}),
                "scan_summary": {
                    "files_scanned": detailed_results.get("files_scanned", 0),
                    "lines_scanned": detailed_results.get("lines_scanned", 0),
                    "queries_total": detailed_results.get("queries_total", 0),
                    "total_findings": detailed_results.get("total_counter", 0)
                }
            }
            scan.completed_at = datetime.utcnow()
            scan.updated_at = datetime.utcnow()
            db.commit()

            return {
                "success": True, 
                "scan_id": scan.id, 
                "findings_count": len(findings), 
                "results": scan.results,
                "severity_summary": detailed_results.get("severity_counters", {})
            }

        except Exception as e:
            scan.status = ScanStatus.FAILED.value
            scan.results = {"error": str(e)}
            db.commit()
            raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    def _load_kics_results(self, output_file: str) -> Dict[str, Any]:
        """Load detailed KICS results from the output file"""
        try:
            import json
            with open(output_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load detailed KICS results: {str(e)}")
            return {"queries": [], "severity_counters": {}}

    async def _process_kics_findings(self, db: Session, scan: Scan, kics_results: Dict[str, Any]) -> List[Finding]:
        """Process KICS findings and create Finding records"""
        findings = []
        queries = kics_results.get("queries", [])

        for query in queries:
            if not query.get("files"):
                continue

            for file_info in query["files"]:
                # Create finding record
                finding = Finding(
                    scan_id=scan.id,
                    query_name=query.get("query_name", "Unknown"),
                    severity=query.get("severity", "INFO"),
                    description=query.get("description", "No description"),
                    file_path=file_info.get("file_name"),
                    line_number=file_info.get("line"),
                    remediation=self._generate_remediation(query, file_info),
                    created_at=datetime.utcnow(),
                )

                # Calculate risk score if possible
                try:
                    risk_matrix = RiskMatrix()
                    risk_score = risk_matrix.calculate_risk_score(impact=query.get("severity", "MEDIUM"), likelihood="MEDIUM")
                    finding.risk_score = risk_score
                except Exception:
                    finding.risk_score = None

                db.add(finding)
                findings.append(finding)

        db.commit()
        return findings

    def _generate_remediation(self, query: Dict[str, Any], file_info: Dict[str, Any]) -> str:
        """Generate remediation guidance based on KICS query and file info"""
        remediation = query.get("description", "")
        
        # Add specific remediation based on query type
        if "expected_value" in file_info and "actual_value" in file_info:
            remediation += f"\n\nExpected: {file_info['expected_value']}"
            remediation += f"\nActual: {file_info['actual_value']}"
        
        # Add platform-specific guidance
        platform = query.get("platform", "")
        if platform == "Terraform":
            remediation += "\n\nTo fix this issue in Terraform, update your configuration to follow security best practices."
        elif platform == "Dockerfile":
            remediation += "\n\nTo fix this issue in Dockerfile, update your configuration to follow security best practices."
        
        return remediation

    async def get_scan(self, db: Session, scan_id: int, user: User) -> Scan:
        """Get scan by ID with permission check"""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Check permissions
        permissions = get_user_permissions(user)
        if not permissions.get("view_all_scans", False) and scan.user_id != user.id:
            raise HTTPException(status_code=403, detail="Access denied")

        return scan

    async def get_user_scans(self, db: Session, user: User, skip: int = 0, limit: int = 100) -> List[Scan]:
        """Get scans for user with pagination"""
        permissions = get_user_permissions(user)

        if permissions.get("view_all_scans", False):
            # AppSec and Admin can see all scans in their organization
            scans = db.query(Scan).filter(Scan.organization_id == user.organization_id).offset(skip).limit(limit).all()
        else:
            # Developers can only see their own scans
            scans = db.query(Scan).filter(Scan.user_id == user.id).offset(skip).limit(limit).all()

        return scans

    async def get_scan_findings(self, db: Session, scan_id: int, user: User) -> List[Finding]:
        """Get findings for a scan"""
        # Verify scan access
        await self.get_scan(db, scan_id, user)

        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

        return findings

    async def delete_scan(self, db: Session, scan_id: int, user: User) -> bool:
        """Delete a scan with permission check"""
        scan = await self.get_scan(db, scan_id, user)

        permissions = get_user_permissions(user)
        if not permissions.get("delete_scans", False) and scan.user_id != user.id:
            raise HTTPException(status_code=403, detail="Access denied")

        # Delete associated files
        scan_dir = self.upload_dir / str(scan_id)
        if scan_dir.exists():
            shutil.rmtree(scan_dir)

        # Delete findings
        db.query(Finding).filter(Finding.scan_id == scan_id).delete()

        # Delete scan
        db.delete(scan)
        db.commit()

        return True


class FileService:
    """Service for file operations"""

    def __init__(self):
        self.upload_dir = Path("uploads")
        self.upload_dir.mkdir(exist_ok=True)

    async def save_uploaded_files(self, scan_id: int, files: List[UploadFile]) -> List[str]:
        """Save uploaded files and return paths"""
        scan_dir = self.upload_dir / str(scan_id)
        scan_dir.mkdir(exist_ok=True)

        saved_paths = []

        for file in files:
            file_path = scan_dir / file.filename
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            saved_paths.append(str(file_path))

        return saved_paths

    def cleanup_scan_files(self, scan_id: int):
        """Clean up files for a scan"""
        scan_dir = self.upload_dir / str(scan_id)
        if scan_dir.exists():
            shutil.rmtree(scan_dir)
