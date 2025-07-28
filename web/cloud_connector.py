"""
Cloud Connector for DriftBuddy Web Interface
Integrates with AWS, Azure, and GCP for cloud infrastructure scanning
"""

import asyncio
import json
import os
import subprocess

# Import DriftBuddy Steampipe integration
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from .auth import get_user_permissions
from .models import Finding, Scan, ScanStatus, User

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))
from driftbuddy.steampipe_integration import SteampipeIntegration


class CloudConnector:
    """Cloud connector for AWS, Azure, and GCP integration"""

    def __init__(self):
        self.steampipe = SteampipeIntegration()
        self.supported_providers = ["aws", "azure", "gcp"]

    async def connect_aws(self, access_key: str, secret_key: str, region: str = "us-east-1", profile: Optional[str] = None) -> Dict[str, Any]:
        """Connect to AWS using credentials"""
        try:
            # Configure AWS credentials
            aws_config = {"access_key": access_key, "secret_key": secret_key, "region": region, "profile": profile}

            # Test connection
            connection_status = await self._test_aws_connection(aws_config)

            if connection_status["success"]:
                return {"success": True, "provider": "aws", "region": region, "message": "AWS connection successful", "config": aws_config}
            else:
                return {"success": False, "provider": "aws", "error": connection_status["error"]}

        except Exception as e:
            return {"success": False, "provider": "aws", "error": f"AWS connection failed: {str(e)}"}

    async def connect_azure(self, tenant_id: str, client_id: str, client_secret: str, subscription_id: str) -> Dict[str, Any]:
        """Connect to Azure using service principal"""
        try:
            # Configure Azure credentials
            azure_config = {"tenant_id": tenant_id, "client_id": client_id, "client_secret": client_secret, "subscription_id": subscription_id}

            # Test connection
            connection_status = await self._test_azure_connection(azure_config)

            if connection_status["success"]:
                return {
                    "success": True,
                    "provider": "azure",
                    "subscription_id": subscription_id,
                    "message": "Azure connection successful",
                    "config": azure_config,
                }
            else:
                return {"success": False, "provider": "azure", "error": connection_status["error"]}

        except Exception as e:
            return {"success": False, "provider": "azure", "error": f"Azure connection failed: {str(e)}"}

    async def connect_gcp(self, project_id: str, service_account_key: str) -> Dict[str, Any]:
        """Connect to GCP using service account"""
        try:
            # Configure GCP credentials
            gcp_config = {"project_id": project_id, "service_account_key": service_account_key}

            # Test connection
            connection_status = await self._test_gcp_connection(gcp_config)

            if connection_status["success"]:
                return {"success": True, "provider": "gcp", "project_id": project_id, "message": "GCP connection successful", "config": gcp_config}
            else:
                return {"success": False, "provider": "gcp", "error": connection_status["error"]}

        except Exception as e:
            return {"success": False, "provider": "gcp", "error": f"GCP connection failed: {str(e)}"}

    async def run_cloud_scan(self, db: Session, scan: Scan, provider: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run cloud infrastructure scan"""
        try:
            # Update scan status
            scan.status = ScanStatus.RUNNING.value
            scan.scan_type = f"cloud_{provider}"
            scan.scan_metadata = {"provider": provider, "config": config, "started_at": datetime.utcnow().isoformat()}
            db.commit()

            # Run Steampipe scan
            steampipe_results = await self._run_steampipe_scan(provider, config)

            if not steampipe_results.get("success", False):
                scan.status = ScanStatus.FAILED.value
                scan.results = {"error": steampipe_results.get("error", "Unknown error")}
                db.commit()
                return steampipe_results

            # Process findings
            findings = await self._process_cloud_findings(db, scan, steampipe_results)

            # Update scan with results
            scan.status = ScanStatus.COMPLETED.value
            scan.results = steampipe_results
            scan.completed_at = datetime.utcnow()
            scan.updated_at = datetime.utcnow()
            db.commit()

            return {"success": True, "scan_id": scan.id, "provider": provider, "findings_count": len(findings), "results": steampipe_results}

        except Exception as e:
            scan.status = ScanStatus.FAILED.value
            scan.results = {"error": str(e)}
            db.commit()
            return {"success": False, "provider": provider, "error": f"Cloud scan failed: {str(e)}"}

    async def _test_aws_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test AWS connection using Steampipe"""
        try:
            # Set AWS environment variables
            env = os.environ.copy()
            env["AWS_ACCESS_KEY_ID"] = config["access_key"]
            env["AWS_SECRET_ACCESS_KEY"] = config["secret_key"]
            env["AWS_DEFAULT_REGION"] = config["region"]

            if config.get("profile"):
                env["AWS_PROFILE"] = config["profile"]

            # Test with Steampipe
            cmd = ["steampipe", "query", "select account_id, arn from aws_account"]
            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)

            if result.returncode == 0:
                return {"success": True, "data": result.stdout}
            else:
                return {"success": False, "error": result.stderr}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _test_azure_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test Azure connection using Steampipe"""
        try:
            # Set Azure environment variables
            env = os.environ.copy()
            env["AZURE_TENANT_ID"] = config["tenant_id"]
            env["AZURE_CLIENT_ID"] = config["client_id"]
            env["AZURE_CLIENT_SECRET"] = config["client_secret"]
            env["AZURE_SUBSCRIPTION_ID"] = config["subscription_id"]

            # Test with Steampipe
            cmd = ["steampipe", "query", "select subscription_id, display_name from azure_subscription"]
            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)

            if result.returncode == 0:
                return {"success": True, "data": result.stdout}
            else:
                return {"success": False, "error": result.stderr}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _test_gcp_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test GCP connection using Steampipe"""
        try:
            # Set GCP environment variables
            env = os.environ.copy()
            env["GOOGLE_APPLICATION_CREDENTIALS"] = config["service_account_key"]
            env["GOOGLE_CLOUD_PROJECT"] = config["project_id"]

            # Test with Steampipe
            cmd = ["steampipe", "query", "select project_id, name from gcp_project"]
            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)

            if result.returncode == 0:
                return {"success": True, "data": result.stdout}
            else:
                return {"success": False, "error": result.stderr}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _run_steampipe_scan(self, provider: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Run Steampipe scan for cloud provider"""
        try:
            # Set environment variables based on provider
            env = os.environ.copy()

            if provider == "aws":
                env["AWS_ACCESS_KEY_ID"] = config["access_key"]
                env["AWS_SECRET_ACCESS_KEY"] = config["secret_key"]
                env["AWS_DEFAULT_REGION"] = config["region"]
                if config.get("profile"):
                    env["AWS_PROFILE"] = config["profile"]

            elif provider == "azure":
                env["AZURE_TENANT_ID"] = config["tenant_id"]
                env["AZURE_CLIENT_ID"] = config["client_id"]
                env["AZURE_CLIENT_SECRET"] = config["client_secret"]
                env["AZURE_SUBSCRIPTION_ID"] = config["subscription_id"]

            elif provider == "gcp":
                env["GOOGLE_APPLICATION_CREDENTIALS"] = config["service_account_key"]
                env["GOOGLE_CLOUD_PROJECT"] = config["project_id"]

            # Run security queries
            queries = self._get_security_queries(provider)
            results = []

            for query_name, query in queries.items():
                try:
                    cmd = ["steampipe", "query", query, "--output", "json"]
                    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60)

                    if result.returncode == 0:
                        query_results = json.loads(result.stdout)
                        results.append({"query_name": query_name, "results": query_results, "status": "success"})
                    else:
                        results.append({"query_name": query_name, "error": result.stderr, "status": "failed"})

                except Exception as e:
                    results.append({"query_name": query_name, "error": str(e), "status": "failed"})

            return {"success": True, "provider": provider, "queries": results, "timestamp": datetime.utcnow().isoformat()}

        except Exception as e:
            return {"success": False, "provider": provider, "error": str(e)}

    def _get_security_queries(self, provider: str) -> Dict[str, str]:
        """Get security queries for cloud provider"""
        queries = {
            "aws": {
                "public_s3_buckets": "select name, arn from aws_s3_bucket where bucket_policy_is_public = true",
                "unencrypted_volumes": "select volume_id, state from aws_ebs_volume where encrypted = false",
                "public_ec2_instances": "select instance_id, state from aws_ec2_instance where public_ip_address is not null",
                "unrestricted_security_groups": "select group_id, group_name from aws_vpc_security_group where description like '%0.0.0.0/0%'",
            },
            "azure": {
                "public_storage_accounts": "select name, resource_group from azure_storage_account where allow_blob_public_access = true",
                "unencrypted_disks": "select name, resource_group from azure_compute_disk where encryption_type = 'EncryptionAtRestWithPlatformKey'",
                "public_vms": "select name, resource_group from azure_compute_virtual_machine where public_ip_address is not null",
            },
            "gcp": {
                "public_buckets": "select name from gcp_storage_bucket where iam_configuration_bucket_policy_only_enabled = false",
                "unencrypted_disks": "select name from gcp_compute_disk where disk_encryption_key is null",
                "public_instances": "select name from gcp_compute_instance where network_interface_access_config_nat_ip is not null",
            },
        }

        return queries.get(provider, {})

    async def _process_cloud_findings(self, db: Session, scan: Scan, steampipe_results: Dict[str, Any]) -> List[Finding]:
        """Process cloud scan findings"""
        findings = []
        queries = steampipe_results.get("queries", [])

        for query in queries:
            if query.get("status") == "success":
                results = query.get("results", [])

                for result in results:
                    # Create finding record
                    finding = Finding(
                        scan_id=scan.id,
                        query_name=query.get("query_name", "Unknown"),
                        severity=self._determine_severity(query.get("query_name", "")),
                        description=self._generate_description(query.get("query_name", ""), result),
                        file_path="cloud_infrastructure",
                        line_number=None,
                        remediation=self._generate_remediation(query.get("query_name", ""), result),
                        created_at=datetime.utcnow(),
                    )

                    # Calculate risk score
                    finding.risk_score = self._calculate_risk_score(query.get("query_name", ""), result)

                    db.add(finding)
                    findings.append(finding)

        db.commit()
        return findings

    def _determine_severity(self, query_name: str) -> str:
        """Determine severity based on query name"""
        high_severity_queries = ["public_s3_buckets", "public_storage_accounts", "public_buckets", "unrestricted_security_groups"]

        medium_severity_queries = ["unencrypted_volumes", "unencrypted_disks", "public_ec2_instances", "public_vms", "public_instances"]

        if query_name in high_severity_queries:
            return "HIGH"
        elif query_name in medium_severity_queries:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_description(self, query_name: str, result: Dict[str, Any]) -> str:
        """Generate description for cloud finding"""
        descriptions = {
            "public_s3_buckets": f"Public S3 bucket found: {result.get('name', 'Unknown')}",
            "unencrypted_volumes": f"Unencrypted EBS volume found: {result.get('volume_id', 'Unknown')}",
            "public_ec2_instances": f"Public EC2 instance found: {result.get('instance_id', 'Unknown')}",
            "unrestricted_security_groups": f"Unrestricted security group found: {result.get('group_name', 'Unknown')}",
            "public_storage_accounts": f"Public Azure storage account found: {result.get('name', 'Unknown')}",
            "unencrypted_disks": f"Unencrypted Azure disk found: {result.get('name', 'Unknown')}",
            "public_vms": f"Public Azure VM found: {result.get('name', 'Unknown')}",
            "public_buckets": f"Public GCP bucket found: {result.get('name', 'Unknown')}",
            "unencrypted_disks": f"Unencrypted GCP disk found: {result.get('name', 'Unknown')}",
            "public_instances": f"Public GCP instance found: {result.get('name', 'Unknown')}",
        }

        return descriptions.get(query_name, f"Cloud security issue found: {query_name}")

    def _generate_remediation(self, query_name: str, result: Dict[str, Any]) -> str:
        """Generate remediation for cloud finding"""
        remediations = {
            "public_s3_buckets": "Remove public access from S3 bucket and implement proper IAM policies",
            "unencrypted_volumes": "Enable encryption for EBS volumes and recreate if necessary",
            "public_ec2_instances": "Remove public IP or place behind NAT gateway",
            "unrestricted_security_groups": "Restrict security group rules to specific IP ranges",
            "public_storage_accounts": "Disable public access and implement proper access controls",
            "unencrypted_disks": "Enable encryption for Azure disks",
            "public_vms": "Remove public IP or use Azure Bastion for secure access",
            "public_buckets": "Make GCP bucket private and implement proper IAM policies",
            "unencrypted_disks": "Enable encryption for GCP disks",
            "public_instances": "Remove public IP or use Cloud NAT",
        }

        return remediations.get(query_name, "Review and implement appropriate security controls")

    def _calculate_risk_score(self, query_name: str, result: Dict[str, Any]) -> int:
        """Calculate risk score for cloud finding"""
        base_scores = {
            "public_s3_buckets": 20,
            "unencrypted_volumes": 15,
            "public_ec2_instances": 18,
            "unrestricted_security_groups": 22,
            "public_storage_accounts": 20,
            "unencrypted_disks": 15,
            "public_vms": 18,
            "public_buckets": 20,
            "unencrypted_disks": 15,
            "public_instances": 18,
        }

        return base_scores.get(query_name, 10)
