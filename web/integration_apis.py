"""
Integration APIs for DriftBuddy Web Interface - Phase 3
Provides integrations with Jira, Slack, Teams, and other external systems
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from sqlalchemy.orm import Session

from .auth import get_user_permissions
from .models import Finding, Organization, Scan, User


class IntegrationBase:
    """Base class for external integrations"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", False)
        self.api_url = config.get("api_url", "")
        self.api_key = config.get("api_key", "")
        self.webhook_url = config.get("webhook_url", "")

    async def test_connection(self) -> Dict[str, Any]:
        """Test connection to external system"""
        raise NotImplementedError

    async def send_notification(self, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send notification to external system"""
        raise NotImplementedError


class JiraIntegration(IntegrationBase):
    """Jira integration for issue tracking"""

    def __init__(self):
        config = {
            "enabled": os.getenv("JIRA_ENABLED", "false").lower() == "true",
            "api_url": os.getenv("JIRA_API_URL", ""),
            "api_key": os.getenv("JIRA_API_KEY", ""),
            "username": os.getenv("JIRA_USERNAME", ""),
            "project_key": os.getenv("JIRA_PROJECT_KEY", ""),
            "issue_type": os.getenv("JIRA_ISSUE_TYPE", "Bug"),
            "priority_mapping": json.loads(os.getenv("JIRA_PRIORITY_MAPPING", "{}")),
        }
        super().__init__(config)
        self.username = config.get("username", "")
        self.project_key = config.get("project_key", "")
        self.issue_type = config.get("issue_type", "Bug")
        self.priority_mapping = config.get("priority_mapping", {})

    async def test_connection(self) -> Dict[str, Any]:
        """Test Jira connection"""
        if not self.enabled:
            return {"success": False, "error": "Jira integration not enabled"}

        try:
            headers = {"Authorization": f"Basic {self._get_auth_header()}", "Content-Type": "application/json"}

            response = requests.get(f"{self.api_url}/rest/api/2/myself", headers=headers, timeout=10)

            if response.status_code == 200:
                return {"success": True, "message": "Jira connection successful", "user": response.json().get("displayName", "Unknown")}
            else:
                return {"success": False, "error": f"Jira connection failed: {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": f"Jira connection failed: {str(e)}"}

    async def create_issue_from_finding(self, finding: Dict[str, Any], scan: Dict[str, Any], user: User) -> Dict[str, Any]:
        """Create Jira issue from security finding"""
        if not self.enabled:
            return {"success": False, "error": "Jira integration not enabled"}

        try:
            # Map severity to Jira priority
            severity = finding.get("severity", "LOW")
            priority = self.priority_mapping.get(severity, "Medium")

            # Create issue payload
            issue_data = {
                "fields": {
                    "project": {"key": self.project_key},
                    "summary": f"Security Finding: {finding.get('query_name', 'Unknown')}",
                    "description": self._format_finding_description(finding, scan),
                    "issuetype": {"name": self.issue_type},
                    "priority": {"name": priority},
                    "labels": ["security", "driftbuddy", finding.get("severity", "LOW").lower()],
                    "components": [{"name": "Security"}],
                }
            }

            headers = {"Authorization": f"Basic {self._get_auth_header()}", "Content-Type": "application/json"}

            response = requests.post(f"{self.api_url}/rest/api/2/issue", headers=headers, json=issue_data, timeout=30)

            if response.status_code == 201:
                issue_data = response.json()
                return {
                    "success": True,
                    "issue_key": issue_data.get("key"),
                    "issue_id": issue_data.get("id"),
                    "issue_url": f"{self.api_url}/browse/{issue_data.get('key')}",
                }
            else:
                return {"success": False, "error": f"Failed to create Jira issue: {response.status_code} - {response.text}"}

        except Exception as e:
            return {"success": False, "error": f"Jira issue creation failed: {str(e)}"}

    async def update_issue(self, issue_key: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing Jira issue"""
        if not self.enabled:
            return {"success": False, "error": "Jira integration not enabled"}

        try:
            headers = {"Authorization": f"Basic {self._get_auth_header()}", "Content-Type": "application/json"}

            response = requests.put(f"{self.api_url}/rest/api/2/issue/{issue_key}", headers=headers, json={"fields": updates}, timeout=30)

            if response.status_code == 204:
                return {"success": True, "message": "Issue updated successfully"}
            else:
                return {"success": False, "error": f"Failed to update issue: {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": f"Jira issue update failed: {str(e)}"}

    def _get_auth_header(self) -> str:
        """Get Basic Auth header for Jira"""
        import base64

        auth_string = f"{self.username}:{self.api_key}"
        return base64.b64encode(auth_string.encode()).decode()

    def _format_finding_description(self, finding: Dict[str, Any], scan: Dict[str, Any]) -> str:
        """Format finding description for Jira"""
        description = f"""
h2. Security Finding Details

*Finding:* {finding.get('query_name', 'Unknown')}
*Severity:* {finding.get('severity', 'LOW')}
*Risk Score:* {finding.get('risk_score', 0)}/25

h3. Description
{finding.get('description', 'No description available')}

h3. Remediation
{finding.get('remediation', 'No remediation guidance available')}

h3. Scan Information
*Scan:* {scan.get('name', 'Unknown')}
*Scan Type:* {scan.get('scan_type', 'Unknown')}
*File:* {finding.get('file_path', 'N/A')}
*Line:* {finding.get('line_number', 'N/A')}

h3. Additional Information
*Created:* {datetime.utcnow().isoformat()}
*Risk Level:* {self._get_risk_level(finding.get('risk_score', 0))}
        """

        return description.strip()

    def _get_risk_level(self, risk_score: int) -> str:
        """Get risk level based on risk score"""
        if risk_score >= 20:
            return "Critical"
        elif risk_score >= 15:
            return "High"
        elif risk_score >= 10:
            return "Medium"
        else:
            return "Low"


class SlackIntegration(IntegrationBase):
    """Slack integration for notifications"""

    def __init__(self):
        config = {
            "enabled": os.getenv("SLACK_ENABLED", "false").lower() == "true",
            "webhook_url": os.getenv("SLACK_WEBHOOK_URL", ""),
            "channel": os.getenv("SLACK_CHANNEL", "#security"),
            "username": os.getenv("SLACK_USERNAME", "DriftBuddy"),
            "icon_emoji": os.getenv("SLACK_ICON_EMOJI", ":shield:"),
        }
        super().__init__(config)
        self.channel = config.get("channel", "#security")
        self.username = config.get("username", "DriftBuddy")
        self.icon_emoji = config.get("icon_emoji", ":shield:")

    async def test_connection(self) -> Dict[str, Any]:
        """Test Slack connection"""
        if not self.enabled:
            return {"success": False, "error": "Slack integration not enabled"}

        try:
            test_message = {
                "text": "🔒 DriftBuddy Slack integration test successful!",
                "channel": self.channel,
                "username": self.username,
                "icon_emoji": self.icon_emoji,
            }

            response = requests.post(self.webhook_url, json=test_message, timeout=10)

            if response.status_code == 200:
                return {"success": True, "message": "Slack connection successful"}
            else:
                return {"success": False, "error": f"Slack connection failed: {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": f"Slack connection failed: {str(e)}"}

    async def send_scan_completion_notification(self, scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Send scan completion notification to Slack"""
        if not self.enabled:
            return {"success": False, "error": "Slack integration not enabled"}

        try:
            # Calculate statistics
            total_findings = len(findings)
            high_findings = len([f for f in findings if f.get("severity") == "HIGH"])
            medium_findings = len([f for f in findings if f.get("severity") == "MEDIUM"])
            low_findings = len([f for f in findings if f.get("severity") == "LOW"])

            # Create message
            color = "#36a64f" if total_findings == 0 else "#ff0000" if high_findings > 0 else "#ffa500"

            message = {
                "channel": self.channel,
                "username": self.username,
                "icon_emoji": self.icon_emoji,
                "attachments": [
                    {
                        "color": color,
                        "title": f"🔒 Security Scan Completed: {scan.get('name', 'Unknown')}",
                        "text": f"Scan completed with {total_findings} findings",
                        "fields": [
                            {"title": "High Severity", "value": str(high_findings), "short": True},
                            {"title": "Medium Severity", "value": str(medium_findings), "short": True},
                            {"title": "Low Severity", "value": str(low_findings), "short": True},
                            {"title": "Scan Type", "value": scan.get("scan_type", "Unknown"), "short": True},
                        ],
                        "footer": "DriftBuddy Security Scanner",
                        "ts": int(datetime.utcnow().timestamp()),
                    }
                ],
            }

            response = requests.post(self.webhook_url, json=message, timeout=30)

            if response.status_code == 200:
                return {"success": True, "message": "Slack notification sent successfully"}
            else:
                return {"success": False, "error": f"Failed to send Slack notification: {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": f"Slack notification failed: {str(e)}"}

    async def send_finding_alert(self, finding: Dict[str, Any], scan: Dict[str, Any]) -> Dict[str, Any]:
        """Send individual finding alert to Slack"""
        if not self.enabled:
            return {"success": False, "error": "Slack integration not enabled"}

        try:
            severity = finding.get("severity", "LOW")
            color_map = {"HIGH": "#ff0000", "MEDIUM": "#ffa500", "LOW": "#ffff00"}

            message = {
                "channel": self.channel,
                "username": self.username,
                "icon_emoji": self.icon_emoji,
                "attachments": [
                    {
                        "color": color_map.get(severity, "#cccccc"),
                        "title": f"🚨 Security Finding: {finding.get('query_name', 'Unknown')}",
                        "text": finding.get("description", "No description available"),
                        "fields": [
                            {"title": "Severity", "value": severity, "short": True},
                            {"title": "Risk Score", "value": str(finding.get("risk_score", 0)), "short": True},
                            {"title": "Scan", "value": scan.get("name", "Unknown"), "short": True},
                            {"title": "File", "value": finding.get("file_path", "N/A"), "short": True},
                        ],
                        "footer": "DriftBuddy Security Scanner",
                        "ts": int(datetime.utcnow().timestamp()),
                    }
                ],
            }

            response = requests.post(self.webhook_url, json=message, timeout=30)

            if response.status_code == 200:
                return {"success": True, "message": "Slack alert sent successfully"}
            else:
                return {"success": False, "error": f"Failed to send Slack alert: {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": f"Slack alert failed: {str(e)}"}


class TeamsIntegration(IntegrationBase):
    """Microsoft Teams integration for notifications"""

    def __init__(self):
        config = {
            "enabled": os.getenv("TEAMS_ENABLED", "false").lower() == "true",
            "webhook_url": os.getenv("TEAMS_WEBHOOK_URL", ""),
            "title": os.getenv("TEAMS_TITLE", "DriftBuddy Security Scanner"),
            "theme_color": os.getenv("TEAMS_THEME_COLOR", "0078D4"),
        }
        super().__init__(config)
        self.title = config.get("title", "DriftBuddy Security Scanner")
        self.theme_color = config.get("theme_color", "0078D4")

    async def test_connection(self) -> Dict[str, Any]:
        """Test Teams connection"""
        if not self.enabled:
            return {"success": False, "error": "Teams integration not enabled"}

        try:
            test_message = {"title": "🔒 DriftBuddy Teams Integration Test", "text": "Teams integration test successful!", "themeColor": self.theme_color}

            response = requests.post(self.webhook_url, json=test_message, timeout=10)

            if response.status_code == 200:
                return {"success": True, "message": "Teams connection successful"}
            else:
                return {"success": False, "error": f"Teams connection failed: {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": f"Teams connection failed: {str(e)}"}

    async def send_scan_completion_notification(self, scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Send scan completion notification to Teams"""
        if not self.enabled:
            return {"success": False, "error": "Teams integration not enabled"}

        try:
            # Calculate statistics
            total_findings = len(findings)
            high_findings = len([f for f in findings if f.get("severity") == "HIGH"])
            medium_findings = len([f for f in findings if f.get("severity") == "MEDIUM"])
            low_findings = len([f for f in findings if f.get("severity") == "LOW"])

            # Create message
            color = "00FF00" if total_findings == 0 else "FF0000" if high_findings > 0 else "FFA500"

            facts = [
                {"name": "High Severity", "value": str(high_findings)},
                {"name": "Medium Severity", "value": str(medium_findings)},
                {"name": "Low Severity", "value": str(low_findings)},
                {"name": "Scan Type", "value": scan.get("scan_type", "Unknown")},
                {"name": "Total Findings", "value": str(total_findings)},
            ]

            message = {
                "title": f"🔒 Security Scan Completed: {scan.get('name', 'Unknown')}",
                "text": f"Scan completed with {total_findings} findings",
                "themeColor": color,
                "sections": [
                    {"activityTitle": "Scan Results", "activitySubtitle": f"Completed at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}", "facts": facts}
                ],
            }

            response = requests.post(self.webhook_url, json=message, timeout=30)

            if response.status_code == 200:
                return {"success": True, "message": "Teams notification sent successfully"}
            else:
                return {"success": False, "error": f"Failed to send Teams notification: {response.status_code}"}

        except Exception as e:
            return {"success": False, "error": f"Teams notification failed: {str(e)}"}


class IntegrationService:
    """Main integration service for managing all external integrations"""

    def __init__(self):
        self.integrations = {"jira": JiraIntegration(), "slack": SlackIntegration(), "teams": TeamsIntegration()}

    async def get_available_integrations(self) -> Dict[str, Dict[str, Any]]:
        """Get list of available integrations"""
        return {
            name: {"enabled": integration.enabled, "type": integration.__class__.__name__, "config_keys": list(integration.config.keys())}
            for name, integration in self.integrations.items()
        }

    async def test_integration(self, integration_name: str) -> Dict[str, Any]:
        """Test a specific integration"""
        if integration_name not in self.integrations:
            return {"success": False, "error": f"Integration {integration_name} not found"}

        integration = self.integrations[integration_name]
        return await integration.test_connection()

    async def send_notification(self, integration_name: str, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send notification through specified integration"""
        if integration_name not in self.integrations:
            return {"success": False, "error": f"Integration {integration_name} not found"}

        integration = self.integrations[integration_name]
        return await integration.send_notification(message, data)

    async def create_jira_issue_from_finding(self, finding: Dict[str, Any], scan: Dict[str, Any], user: User) -> Dict[str, Any]:
        """Create Jira issue from security finding"""
        jira = self.integrations.get("jira")
        if not jira:
            return {"success": False, "error": "Jira integration not available"}

        return await jira.create_issue_from_finding(finding, scan, user)

    async def send_scan_notification(self, scan: Dict[str, Any], findings: List[Dict[str, Any]], integrations: List[str] = None) -> Dict[str, Any]:
        """Send scan completion notification to multiple integrations"""
        if integrations is None:
            integrations = ["slack", "teams"]

        results = {}

        for integration_name in integrations:
            if integration_name in self.integrations:
                integration = self.integrations[integration_name]

                if integration_name == "slack":
                    result = await integration.send_scan_completion_notification(scan, findings)
                elif integration_name == "teams":
                    result = await integration.send_scan_completion_notification(scan, findings)
                else:
                    result = {"success": False, "error": f"Unsupported integration: {integration_name}"}

                results[integration_name] = result

        return {"success": any(result.get("success", False) for result in results.values()), "results": results}

    async def send_finding_alert(self, finding: Dict[str, Any], scan: Dict[str, Any], integrations: List[str] = None) -> Dict[str, Any]:
        """Send finding alert to multiple integrations"""
        if integrations is None:
            integrations = ["slack", "teams"]

        results = {}

        for integration_name in integrations:
            if integration_name in self.integrations:
                integration = self.integrations[integration_name]

                if integration_name == "slack":
                    result = await integration.send_finding_alert(finding, scan)
                elif integration_name == "teams":
                    # Teams doesn't have individual finding alerts, skip
                    result = {"success": True, "message": "Skipped - Teams doesn't support individual alerts"}
                else:
                    result = {"success": False, "error": f"Unsupported integration: {integration_name}"}

                results[integration_name] = result

        return {"success": any(result.get("success", False) for result in results.values()), "results": results}
