#!/usr/bin/env python3
"""
Steampipe Integration for DriftBuddy
Allows querying real cloud infrastructure to detect drift, misconfigurations, and shadow resources.
"""

import json
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple


class SteampipeIntegration:
    """Steampipe integration for cloud infrastructure querying"""

    def __init__(self):
        self.steampipe_installed = self._check_steampipe_installation()
        self.plugins_installed = self._check_plugins_installation()

    def _check_steampipe_installation(self) -> bool:
        """Check if Steampipe is installed and accessible"""
        try:
            result = subprocess.run(["steampipe", "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✅ Steampipe found and accessible")
                return True
            else:
                print("❌ Steampipe is installed but not working properly")
                return False
        except FileNotFoundError:
            print("❌ Steampipe not found in PATH")
            print("💡 Please install Steampipe:")
            print("   Visit: https://steampipe.io/downloads")
            print("   Or use: curl -s -L https://steampipe.io/install.sh | sh")
            return False
        except Exception as e:
            print(f"❌ Error checking Steampipe installation: {str(e)}")
            return False

    def _check_plugins_installation(self) -> Dict[str, bool]:
        """Check which cloud provider plugins are installed"""
        plugins = {"aws": False, "azure": False, "gcp": False, "kubernetes": False}

        if not self.steampipe_installed:
            return plugins

        try:
            result = subprocess.run(
                ["steampipe", "plugin", "list"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                plugins["aws"] = "aws" in output
                plugins["azure"] = "azure" in output
                plugins["gcp"] = "gcp" in output
                plugins["kubernetes"] = "kubernetes" in output

                print("📊 Available Steampipe plugins:")
                for plugin, installed in plugins.items():
                    status = "✅" if installed else "❌"
                    print(f"   {status} {plugin.upper()}")

                return plugins
        except Exception as e:
            print(f"❌ Error checking plugins: {str(e)}")

        return plugins

    def install_plugin(self, plugin_name: str) -> bool:
        """Install a Steampipe plugin"""
        if not self.steampipe_installed:
            print("❌ Steampipe not installed")
            return False

        try:
            print(f"📦 Installing Steampipe plugin: {plugin_name}")
            result = subprocess.run(
                ["steampipe", "plugin", "install", plugin_name],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                print(f"✅ Successfully installed {plugin_name} plugin")
                self.plugins_installed[plugin_name] = True
                return True
            else:
                print(f"❌ Failed to install {plugin_name} plugin: {result.stderr}")
                return False
        except Exception as e:
            print(f"❌ Error installing {plugin_name} plugin: {str(e)}")
            return False

    def query_infrastructure(self, query: str, plugin: str = "aws") -> Tuple[bool, List[Dict]]:
        """Execute a Steampipe query and return results"""
        if not self.steampipe_installed:
            return False, []

        if not self.plugins_installed.get(plugin, False):
            print(f"❌ {plugin.upper()} plugin not installed")
            return False, []

        try:
            print(f"🔍 Executing Steampipe query for {plugin.upper()}:")
            print(f"   Query: {query[:100]}{'...' if len(query) > 100 else ''}")

            result = subprocess.run(
                ["steampipe", "query", query, "--output", "json"],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    rows = data.get("rows", [])
                    print(f"✅ Query completed. Found {len(rows)} results")
                    return True, rows
                except json.JSONDecodeError:
                    print("❌ Failed to parse query results as JSON")
                    return False, []
            else:
                print(f"❌ Query failed: {result.stderr}")
                return False, []

        except subprocess.TimeoutExpired:
            print("❌ Query timed out after 5 minutes")
            return False, []
        except Exception as e:
            print(f"❌ Error executing query: {str(e)}")
            return False, []

    def get_common_queries(self) -> Dict[str, List[str]]:
        """Get common security and drift detection queries"""
        return {
            "aws": [
                # S3 Security
                "SELECT name, bucket_policy_is_public, versioning_enabled FROM aws_s3_bucket WHERE bucket_policy_is_public = true",
                "SELECT name, versioning_enabled FROM aws_s3_bucket WHERE versioning_enabled = false",
                # IAM Security - Fixed column names based on actual schema
                "SELECT name, attached_policy_arns, inline_policies FROM aws_iam_user WHERE name LIKE '%admin%'",
                "SELECT name, attached_policy_arns FROM aws_iam_role WHERE attached_policy_arns LIKE '%AdministratorAccess%'",
                # Security Groups - Fixed table name to aws_vpc_security_group
                "SELECT name, description, vpc_id FROM aws_vpc_security_group WHERE description = '' OR description IS NULL",
                "SELECT name, ip_permissions FROM aws_vpc_security_group WHERE ip_permissions LIKE '%0.0.0.0/0%'",
                # EC2 Instances
                "SELECT instance_id, instance_type, state, public_ip_address FROM aws_ec2_instance WHERE state = 'running' AND public_ip_address IS NOT NULL",
                "SELECT instance_id, instance_type, state FROM aws_ec2_instance WHERE state = 'stopped'",
                # RDS Security
                "SELECT db_instance_identifier, publicly_accessible, storage_encrypted FROM aws_rds_db_instance WHERE publicly_accessible = true",
                # Shadow Resources
                "SELECT name, creation_date FROM aws_s3_bucket WHERE creation_date < NOW() - INTERVAL '90 days'",
                "SELECT instance_id, launch_time FROM aws_ec2_instance WHERE launch_time < NOW() - INTERVAL '30 days'",
            ],
            "azure": [
                # Storage Security
                "SELECT name, allow_blob_public_access FROM azure_storage_account WHERE allow_blob_public_access = true",
                "SELECT name, enable_https_traffic_only FROM azure_storage_account WHERE enable_https_traffic_only = false",
                # Network Security
                "SELECT name, address_prefix FROM azure_network_security_group WHERE address_prefix = '0.0.0.0/0'",
                # Virtual Machines
                "SELECT name, power_state FROM azure_compute_virtual_machine WHERE power_state = 'VM running'",
                # Key Vault
                "SELECT name, enable_soft_delete FROM azure_key_vault WHERE enable_soft_delete = false",
            ],
            "gcp": [
                # Storage Security
                "SELECT name, uniform_bucket_level_access FROM gcp_storage_bucket WHERE uniform_bucket_level_access = false",
                "SELECT name, public_access_prevention FROM gcp_storage_bucket WHERE public_access_prevention = 'inherited'",
                # Compute Instances
                "SELECT name, status FROM gcp_compute_instance WHERE status = 'RUNNING'",
                # IAM
                "SELECT name, role FROM gcp_project_iam_member WHERE role LIKE '%admin%'",
                # Network
                "SELECT name, source_ranges FROM gcp_compute_firewall WHERE source_ranges LIKE '%0.0.0.0/0%'",
            ],
            "kubernetes": [
                # Pod Security
                "SELECT name, namespace, security_context FROM kubernetes_pod WHERE security_context IS NULL",
                "SELECT name, namespace FROM kubernetes_pod WHERE namespace = 'default'",
                # Service Security
                "SELECT name, namespace, type FROM kubernetes_service WHERE type = 'LoadBalancer'",
                # ConfigMaps and Secrets
                "SELECT name, namespace FROM kubernetes_config_map WHERE namespace = 'default'",
                "SELECT name, namespace FROM kubernetes_secret WHERE namespace = 'default'",
            ],
        }

    def detect_drift(self, iac_file: str, cloud_provider: str = "aws") -> Dict:
        """Detect drift between IaC and actual cloud infrastructure"""
        if not self.steampipe_installed:
            return {"error": "Steampipe not installed"}

        print(f"🔍 Detecting drift for {iac_file} against {cloud_provider.upper()} infrastructure...")

        # This is a simplified drift detection
        # In a real implementation, you'd parse the IaC file and compare with cloud resources
        drift_results = {
            "file": iac_file,
            "provider": cloud_provider,
            "timestamp": datetime.now().isoformat(),
            "drift_detected": False,
            "missing_resources": [],
            "extra_resources": [],
            "configuration_drift": [],
        }

        # Example drift detection queries
        if cloud_provider == "aws":
            # Check for S3 buckets in IaC vs actual
            success, s3_results = self.query_infrastructure("SELECT name FROM aws_s3_bucket WHERE name LIKE '%test%' OR name LIKE '%dev%'")
            if success and s3_results:
                drift_results["extra_resources"].extend([row.get("name") for row in s3_results])
                drift_results["drift_detected"] = True

        return drift_results

    def scan_shadow_resources(self, cloud_provider: str = "aws") -> Dict:
        """Scan for shadow resources (unmanaged infrastructure)"""
        if not self.steampipe_installed:
            return {"error": "Steampipe not installed"}

        print(f"👻 Scanning for shadow resources in {cloud_provider.upper()}...")

        shadow_resources = {
            "provider": cloud_provider,
            "timestamp": datetime.now().isoformat(),
            "shadow_resources": [],
            "total_count": 0,
        }

        # Common shadow resource queries
        queries = {
            "aws": [
                "SELECT name, created_date FROM aws_s3_bucket WHERE created_date < NOW() - INTERVAL '90 days'",
                "SELECT instance_id, launch_time FROM aws_ec2_instance WHERE launch_time < NOW() - INTERVAL '30 days'",
                "SELECT name, created_date FROM aws_iam_user WHERE created_date < NOW() - INTERVAL '60 days'",
            ],
            "azure": [
                "SELECT name, created_time FROM azure_storage_account WHERE created_time < NOW() - INTERVAL '90 days'",
                "SELECT name, created_time FROM azure_compute_virtual_machine WHERE created_time < NOW() - INTERVAL '30 days'",
            ],
            "gcp": [
                "SELECT name, creation_timestamp FROM gcp_storage_bucket WHERE creation_timestamp < NOW() - INTERVAL '90 days'",
                "SELECT name, creation_timestamp FROM gcp_compute_instance WHERE creation_timestamp < NOW() - INTERVAL '30 days'",
            ],
        }

        provider_queries = queries.get(cloud_provider, [])

        for query in provider_queries:
            success, results = self.query_infrastructure(query, cloud_provider)
            if success:
                shadow_resources["shadow_resources"].extend(results)
                shadow_resources["total_count"] += len(results)

        return shadow_resources

    def generate_steampipe_report(self, results: Dict, output_file: str = None) -> str:
        """Generate a markdown report from Steampipe results"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"steampipe_report_{timestamp}.md"

        report = f"""# 🔍 Steampipe Infrastructure Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Provider:** {results.get('provider', 'Unknown')}

## 📊 Summary

"""

        if "drift_detected" in results:
            report += f"""
### 🚨 Drift Detection Results

- **File Analyzed:** {results.get('file', 'Unknown')}
- **Drift Detected:** {'Yes' if results.get('drift_detected') else 'No'}
- **Missing Resources:** {len(results.get('missing_resources', []))}
- **Extra Resources:** {len(results.get('extra_resources', []))}
- **Configuration Drift:** {len(results.get('configuration_drift', []))}

"""

        if "shadow_resources" in results:
            report += f"""
### 👻 Shadow Resources

- **Total Shadow Resources:** {results.get('total_count', 0)}
- **Resources Found:** {len(results.get('shadow_resources', []))}

"""

        if "shadow_resources" in results and results.get("shadow_resources"):
            report += "#### Detailed Shadow Resources:\n\n"
            for resource in results.get("shadow_resources", [])[:10]:  # Show first 10
                report += f"- **{resource.get('name', 'Unknown')}** (Created: {resource.get('created_date', 'Unknown')})\n"
            report += "\n"

        report += """
## 💡 Recommendations

1. **Review Shadow Resources:** Investigate and document all shadow resources
2. **Implement IaC:** Convert shadow resources to Infrastructure as Code
3. **Regular Audits:** Schedule regular infrastructure audits
4. **Access Control:** Review and restrict access to prevent future shadow resources

---
*Generated by DriftBuddy with Steampipe integration*
"""

        # Write report to file
        with open(output_file, "w") as f:
            f.write(report)

        print(f"📄 Steampipe report generated: {output_file}")
        return output_file


def main():
    """Test Steampipe integration"""
    steampipe = SteampipeIntegration()

    if not steampipe.steampipe_installed:
        print("❌ Steampipe not available. Please install Steampipe first.")
        return

    # Example usage
    print("\n🔍 Testing Steampipe integration...")

    # Check available plugins
    available_plugins = [plugin for plugin, installed in steampipe.plugins_installed.items() if installed]

    if not available_plugins:
        print("❌ No cloud provider plugins installed")
        print("💡 Install plugins with: steampipe plugin install aws")
        return

    # Test with first available plugin
    plugin = available_plugins[0]
    print(f"\n🧪 Testing with {plugin.upper()} plugin...")

    # Get common queries
    queries = steampipe.get_common_queries()
    if plugin in queries:
        test_query = queries[plugin][0]  # Use first query
        success, results = steampipe.query_infrastructure(test_query, plugin)

        if success:
            print(f"✅ Query successful! Found {len(results)} results")

            # Generate report
            report_data = {
                "provider": plugin,
                "query_results": results,
                "total_count": len(results),
            }

            steampipe.generate_steampipe_report(report_data)
        else:
            print("❌ Query failed")

    print("\n🎉 Steampipe integration test completed!")


if __name__ == "__main__":
    main()
