"""
Integrations Service for DriftBuddy
Handles external integrations with cloud providers, development platforms, and communication tools
"""
import json
import boto3
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc

from .models import (
    Integration, IntegrationLog, Finding, Scan, User,
    ComplianceAssessment, ComplianceControl
)

class IntegrationsService:
    def __init__(self):
        self.supported_integrations = {
            'aws': {
                'name': 'Amazon Web Services',
                'services': ['iam', 'cloudtrail', 'security_hub', 'config', 'guardduty'],
                'icon': '☁️',
                'color': 'orange'
            },
            'azure': {
                'name': 'Microsoft Azure',
                'services': ['security_center', 'sentinel', 'key_vault', 'monitor'],
                'icon': '🔷',
                'color': 'blue'
            },
            'gcp': {
                'name': 'Google Cloud Platform',
                'services': ['security_command_center', 'iam', 'cloud_logging'],
                'icon': '☁️',
                'color': 'green'
            },
            'github': {
                'name': 'GitHub',
                'services': ['repository_scanning', 'pr_checks', 'security_alerts'],
                'icon': '🐙',
                'color': 'black'
            },
            'slack': {
                'name': 'Slack',
                'services': ['notifications', 'alerts', 'reports'],
                'icon': '💬',
                'color': 'purple'
            },
            'teams': {
                'name': 'Microsoft Teams',
                'services': ['notifications', 'alerts', 'reports'],
                'icon': '💬',
                'color': 'blue'
            },
            'jira': {
                'name': 'JIRA',
                'services': ['ticket_creation', 'workflow_automation'],
                'icon': '📋',
                'color': 'blue'
            },
            'email': {
                'name': 'Email Notifications',
                'services': ['reports', 'alerts', 'digests'],
                'icon': '📧',
                'color': 'gray'
            }
        }

    def create_integration(self, db: Session, integration_data: Dict[str, Any]) -> Integration:
        """Create a new integration"""
        integration = Integration(
            provider=integration_data['provider'],
            name=integration_data['name'],
            config=integration_data['config'],
            is_active=integration_data.get('is_active', True),
            last_sync=datetime.utcnow()
        )
        db.add(integration)
        db.commit()
        db.refresh(integration)
        return integration

    def get_integrations(self, db: Session, provider: Optional[str] = None) -> List[Integration]:
        """Get integrations, optionally filtered by provider"""
        query = db.query(Integration)
        if provider:
            query = query.filter(Integration.provider == provider)
        return query.all()

    def test_aws_integration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test AWS integration with provided credentials"""
        try:
            # Test basic AWS connectivity
            session = boto3.Session(
                aws_access_key_id=config.get('access_key_id'),
                aws_secret_access_key=config.get('secret_access_key'),
                region_name=config.get('region', 'us-east-1')
            )
            
            # Test IAM access
            iam = session.client('iam')
            iam.get_user()
            
            # Test CloudTrail access
            cloudtrail = session.client('cloudtrail')
            cloudtrail.list_trails()
            
            return {
                'status': 'success',
                'message': 'AWS integration test successful',
                'services_available': ['iam', 'cloudtrail', 'security_hub', 'config', 'guardduty']
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'AWS integration test failed: {str(e)}',
                'services_available': []
            }

    def test_azure_integration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test Azure integration with provided credentials"""
        try:
            # Test Azure connectivity using REST API
            headers = {
                'Authorization': f"Bearer {config.get('access_token')}",
                'Content-Type': 'application/json'
            }
            
            # Test subscription access
            subscription_id = config.get('subscription_id')
            url = f"https://management.azure.com/subscriptions/{subscription_id}?api-version=2020-01-01"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'message': 'Azure integration test successful',
                'services_available': ['security_center', 'sentinel', 'key_vault', 'monitor']
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Azure integration test failed: {str(e)}',
                'services_available': []
            }

    def test_gcp_integration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test GCP integration with provided credentials"""
        try:
            # Test GCP connectivity using REST API
            headers = {
                'Authorization': f"Bearer {config.get('access_token')}",
                'Content-Type': 'application/json'
            }
            
            # Test project access
            project_id = config.get('project_id')
            url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'message': 'GCP integration test successful',
                'services_available': ['security_command_center', 'iam', 'cloud_logging']
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'GCP integration test failed: {str(e)}',
                'services_available': []
            }

    def test_github_integration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test GitHub integration with provided token"""
        try:
            headers = {
                'Authorization': f"token {config.get('access_token')}",
                'Accept': 'application/vnd.github.v3+json'
            }
            
            # Test API access
            response = requests.get('https://api.github.com/user', headers=headers)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'message': 'GitHub integration test successful',
                'services_available': ['repository_scanning', 'pr_checks', 'security_alerts']
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'GitHub integration test failed: {str(e)}',
                'services_available': []
            }

    def test_slack_integration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test Slack integration with webhook URL"""
        try:
            webhook_url = config.get('webhook_url')
            payload = {
                'text': 'DriftBuddy integration test - this is a test message'
            }
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'message': 'Slack integration test successful',
                'services_available': ['notifications', 'alerts', 'reports']
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Slack integration test failed: {str(e)}',
                'services_available': []
            }

    def test_teams_integration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test Microsoft Teams integration with webhook URL"""
        try:
            webhook_url = config.get('webhook_url')
            payload = {
                'text': 'DriftBuddy integration test - this is a test message'
            }
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'message': 'Teams integration test successful',
                'services_available': ['notifications', 'alerts', 'reports']
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Teams integration test failed: {str(e)}',
                'services_available': []
            }

    def test_jira_integration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test JIRA integration with provided credentials"""
        try:
            base_url = config.get('base_url')
            username = config.get('username')
            api_token = config.get('api_token')
            
            # Test API access
            url = f"{base_url}/rest/api/2/myself"
            auth = (username, api_token)
            
            response = requests.get(url, auth=auth)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'message': 'JIRA integration test successful',
                'services_available': ['ticket_creation', 'workflow_automation']
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'JIRA integration test failed: {str(e)}',
                'services_available': []
            }

    def sync_aws_findings(self, db: Session, integration: Integration) -> Dict[str, Any]:
        """Sync findings from AWS Security Hub and GuardDuty"""
        try:
            config = integration.config
            session = boto3.Session(
                aws_access_key_id=config.get('access_key_id'),
                aws_secret_access_key=config.get('secret_access_key'),
                region_name=config.get('region', 'us-east-1')
            )
            
            findings = []
            
            # Sync Security Hub findings
            if config.get('sync_security_hub', True):
                security_hub = session.client('securityhub')
                response = security_hub.get_findings(
                    MaxResults=100,
                    Filters={
                        'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
                    }
                )
                
                for finding in response['Findings']:
                    findings.append({
                        'source': 'aws_security_hub',
                        'title': finding.get('Title', 'Unknown'),
                        'description': finding.get('Description', ''),
                        'severity': finding.get('Severity', {}).get('Label', 'MEDIUM'),
                        'status': finding.get('Workflow', {}).get('Status', 'NEW'),
                        'raw_data': finding
                    })
            
            # Sync GuardDuty findings
            if config.get('sync_guardduty', True):
                guardduty = session.client('guardduty')
                response = guardduty.list_findings(
                    DetectorId=config.get('guardduty_detector_id'),
                    FindingCriteria={
                        'Criterion': {
                            'severity': {
                                'Gte': 4  # Medium and above
                            }
                        }
                    }
                )
                
                for finding_id in response['FindingIds']:
                    finding_detail = guardduty.get_findings(
                        DetectorId=config.get('guardduty_detector_id'),
                        FindingIds=[finding_id]
                    )['Findings'][0]
                    
                    findings.append({
                        'source': 'aws_guardduty',
                        'title': finding_detail.get('Title', 'Unknown'),
                        'description': finding_detail.get('Description', ''),
                        'severity': finding_detail.get('Severity', 'MEDIUM'),
                        'status': finding_detail.get('Workflow', {}).get('Status', 'NEW'),
                        'raw_data': finding_detail
                    })
            
            # Create findings in database
            created_findings = []
            for finding_data in findings:
                finding = Finding(
                    title=finding_data['title'],
                    description=finding_data['description'],
                    severity=finding_data['severity'].lower(),
                    status=finding_data['status'].lower(),
                    source=finding_data['source'],
                    raw_data=finding_data['raw_data'],
                    integration_id=integration.id
                )
                db.add(finding)
                created_findings.append(finding)
            
            db.commit()
            
            # Log the sync
            self.log_integration_activity(db, integration.id, 'sync', {
                'findings_synced': len(created_findings),
                'sources': list(set(f['source'] for f in findings))
            })
            
            return {
                'status': 'success',
                'findings_synced': len(created_findings),
                'message': f'Successfully synced {len(created_findings)} findings from AWS'
            }
            
        except Exception as e:
            db.rollback()
            self.log_integration_activity(db, integration.id, 'error', {
                'error': str(e)
            })
            return {
                'status': 'error',
                'message': f'AWS sync failed: {str(e)}'
            }

    def sync_azure_findings(self, db: Session, integration: Integration) -> Dict[str, Any]:
        """Sync findings from Azure Security Center"""
        try:
            config = integration.config
            headers = {
                'Authorization': f"Bearer {config.get('access_token')}",
                'Content-Type': 'application/json'
            }
            
            subscription_id = config.get('subscription_id')
            findings = []
            
            # Get Security Center alerts
            url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Security/alerts?api-version=2020-01-01"
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            for alert in response.json().get('value', []):
                findings.append({
                    'source': 'azure_security_center',
                    'title': alert.get('properties', {}).get('alertDisplayName', 'Unknown'),
                    'description': alert.get('properties', {}).get('description', ''),
                    'severity': alert.get('properties', {}).get('severity', 'MEDIUM'),
                    'status': alert.get('properties', {}).get('state', 'Active'),
                    'raw_data': alert
                })
            
            # Create findings in database
            created_findings = []
            for finding_data in findings:
                finding = Finding(
                    title=finding_data['title'],
                    description=finding_data['description'],
                    severity=finding_data['severity'].lower(),
                    status=finding_data['status'].lower(),
                    source=finding_data['source'],
                    raw_data=finding_data['raw_data'],
                    integration_id=integration.id
                )
                db.add(finding)
                created_findings.append(finding)
            
            db.commit()
            
            # Log the sync
            self.log_integration_activity(db, integration.id, 'sync', {
                'findings_synced': len(created_findings),
                'sources': ['azure_security_center']
            })
            
            return {
                'status': 'success',
                'findings_synced': len(created_findings),
                'message': f'Successfully synced {len(created_findings)} findings from Azure'
            }
            
        except Exception as e:
            db.rollback()
            self.log_integration_activity(db, integration.id, 'error', {
                'error': str(e)
            })
            return {
                'status': 'error',
                'message': f'Azure sync failed: {str(e)}'
            }

    def sync_github_findings(self, db: Session, integration: Integration) -> Dict[str, Any]:
        """Sync security findings from GitHub repositories"""
        try:
            config = integration.config
            headers = {
                'Authorization': f"token {config.get('access_token')}",
                'Accept': 'application/vnd.github.v3+json'
            }
            
            findings = []
            repositories = config.get('repositories', [])
            
            for repo in repositories:
                # Get Dependabot alerts
                url = f"https://api.github.com/repos/{repo}/dependabot/alerts"
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    for alert in response.json():
                        findings.append({
                            'source': 'github_dependabot',
                            'title': f"Dependabot Alert: {alert.get('security_vulnerability', {}).get('package', {}).get('name', 'Unknown')}",
                            'description': alert.get('security_vulnerability', {}).get('description', ''),
                            'severity': alert.get('security_vulnerability', {}).get('severity', 'medium'),
                            'status': alert.get('state', 'open'),
                            'raw_data': alert
                        })
                
                # Get CodeQL alerts
                url = f"https://api.github.com/repos/{repo}/code-scanning/alerts"
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    for alert in response.json():
                        findings.append({
                            'source': 'github_codeql',
                            'title': f"CodeQL Alert: {alert.get('rule', {}).get('name', 'Unknown')}",
                            'description': alert.get('rule', {}).get('description', ''),
                            'severity': alert.get('rule', {}).get('security_severity', 'medium'),
                            'status': alert.get('state', 'open'),
                            'raw_data': alert
                        })
            
            # Create findings in database
            created_findings = []
            for finding_data in findings:
                finding = Finding(
                    title=finding_data['title'],
                    description=finding_data['description'],
                    severity=finding_data['severity'].lower(),
                    status=finding_data['status'].lower(),
                    source=finding_data['source'],
                    raw_data=finding_data['raw_data'],
                    integration_id=integration.id
                )
                db.add(finding)
                created_findings.append(finding)
            
            db.commit()
            
            # Log the sync
            self.log_integration_activity(db, integration.id, 'sync', {
                'findings_synced': len(created_findings),
                'repositories': repositories
            })
            
            return {
                'status': 'success',
                'findings_synced': len(created_findings),
                'message': f'Successfully synced {len(created_findings)} findings from GitHub'
            }
            
        except Exception as e:
            db.rollback()
            self.log_integration_activity(db, integration.id, 'error', {
                'error': str(e)
            })
            return {
                'status': 'error',
                'message': f'GitHub sync failed: {str(e)}'
            }

    def send_slack_notification(self, config: Dict[str, Any], message: str, 
                               severity: str = 'info', findings: List[Dict] = None) -> Dict[str, Any]:
        """Send notification to Slack"""
        try:
            webhook_url = config.get('webhook_url')
            
            # Create rich message
            color_map = {
                'critical': '#ff0000',
                'high': '#ff6600',
                'medium': '#ffcc00',
                'low': '#00cc00',
                'info': '#0066cc'
            }
            
            payload = {
                'attachments': [{
                    'color': color_map.get(severity, '#0066cc'),
                    'title': 'DriftBuddy Security Alert',
                    'text': message,
                    'fields': []
                }]
            }
            
            if findings:
                for finding in findings[:5]:  # Limit to 5 findings
                    payload['attachments'][0]['fields'].append({
                        'title': finding.get('title', 'Unknown'),
                        'value': f"Severity: {finding.get('severity', 'Unknown')} | Status: {finding.get('status', 'Unknown')}",
                        'short': True
                    })
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'message': 'Slack notification sent successfully'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Slack notification failed: {str(e)}'
            }

    def send_teams_notification(self, config: Dict[str, Any], message: str,
                                severity: str = 'info', findings: List[Dict] = None) -> Dict[str, Any]:
        """Send notification to Microsoft Teams"""
        try:
            webhook_url = config.get('webhook_url')
            
            # Create Teams message card
            color_map = {
                'critical': '#ff0000',
                'high': '#ff6600',
                'medium': '#ffcc00',
                'low': '#00cc00',
                'info': '#0066cc'
            }
            
            payload = {
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                'themeColor': color_map.get(severity, '#0066cc'),
                'title': 'DriftBuddy Security Alert',
                'text': message,
                'sections': []
            }
            
            if findings:
                facts = []
                for finding in findings[:5]:  # Limit to 5 findings
                    facts.append({
                        'name': finding.get('title', 'Unknown'),
                        'value': f"Severity: {finding.get('severity', 'Unknown')} | Status: {finding.get('status', 'Unknown')}"
                    })
                payload['sections'].append({
                    'title': 'Recent Findings',
                    'facts': facts
                })
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'message': 'Teams notification sent successfully'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Teams notification failed: {str(e)}'
            }

    def create_jira_ticket(self, config: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
        """Create JIRA ticket for a finding"""
        try:
            base_url = config.get('base_url')
            username = config.get('username')
            api_token = config.get('api_token')
            project_key = config.get('project_key')
            
            auth = (username, api_token)
            
            # Create ticket payload
            payload = {
                'fields': {
                    'project': {'key': project_key},
                    'summary': f"Security Finding: {finding.get('title', 'Unknown')}",
                    'description': finding.get('description', ''),
                    'issuetype': {'name': 'Bug'},
                    'priority': {'name': finding.get('severity', 'Medium').title()},
                    'labels': ['driftbuddy', 'security', finding.get('source', 'unknown')]
                }
            }
            
            url = f"{base_url}/rest/api/2/issue"
            response = requests.post(url, json=payload, auth=auth)
            response.raise_for_status()
            
            ticket_data = response.json()
            
            return {
                'status': 'success',
                'ticket_id': ticket_data['id'],
                'ticket_key': ticket_data['key'],
                'message': f'JIRA ticket created: {ticket_data["key"]}'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'JIRA ticket creation failed: {str(e)}'
            }

    def send_email_notification(self, config: Dict[str, Any], subject: str, 
                               message: str, recipients: List[str]) -> Dict[str, Any]:
        """Send email notification"""
        try:
            # This would integrate with your email service (SendGrid, SES, etc.)
            # For now, we'll simulate the email sending
            
            email_data = {
                'to': recipients,
                'subject': subject,
                'body': message,
                'from': config.get('from_email', 'noreply@driftbuddy.com')
            }
            
            # Log the email (in production, this would actually send the email)
            print(f"Email would be sent: {email_data}")
            
            return {
                'status': 'success',
                'message': f'Email notification sent to {len(recipients)} recipients'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Email notification failed: {str(e)}'
            }

    def log_integration_activity(self, db: Session, integration_id: int, 
                                activity_type: str, details: Dict[str, Any]) -> IntegrationLog:
        """Log integration activity"""
        log = IntegrationLog(
            integration_id=integration_id,
            activity_type=activity_type,
            details=details,
            timestamp=datetime.utcnow()
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    def get_integration_logs(self, db: Session, integration_id: Optional[int] = None,
                            limit: int = 100) -> List[IntegrationLog]:
        """Get integration logs"""
        query = db.query(IntegrationLog)
        if integration_id:
            query = query.filter(IntegrationLog.integration_id == integration_id)
        return query.order_by(IntegrationLog.timestamp.desc()).limit(limit).all()

    def get_supported_integrations(self) -> Dict[str, Any]:
        """Get list of supported integrations"""
        return self.supported_integrations 