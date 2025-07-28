#!/usr/bin/env python3
"""
Test script for DriftBuddy Integrations
Tests AWS, Azure, GCP, GitHub, Slack, Teams, JIRA, and email integrations
"""

import requests
import json
import time
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8080"
ADMIN_EMAIL = "admin@driftbuddy.com"
ADMIN_PASSWORD = "admin123"

class IntegrationTester:
    def __init__(self):
        self.session = requests.Session()
        self.token = None
        self.base_url = BASE_URL

    def login(self):
        """Login and get authentication token"""
        print("🔐 Logging in...")
        
        login_data = {
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        }
        
        response = self.session.post(f"{self.base_url}/api/auth/login", data=login_data)
        
        if response.status_code == 200:
            data = response.json()
            self.token = data["access_token"]
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            print("✅ Login successful")
            return True
        else:
            print(f"❌ Login failed: {response.status_code}")
            return False

    def test_supported_integrations(self):
        """Test getting supported integrations"""
        print("\n📋 Testing supported integrations...")
        
        response = self.session.get(f"{self.base_url}/api/integrations/supported")
        
        if response.status_code == 200:
            integrations = response.json()
            print("✅ Supported integrations retrieved:")
            for provider, details in integrations.items():
                print(f"   {details['icon']} {details['name']} ({provider})")
                print(f"      Services: {', '.join(details['services'])}")
            return True
        else:
            print(f"❌ Failed to get supported integrations: {response.status_code}")
            return False

    def test_aws_integration(self):
        """Test AWS integration"""
        print("\n☁️ Testing AWS Integration...")
        
        # Test configuration (you would need real AWS credentials)
        aws_config = {
            "access_key_id": "test-access-key",
            "secret_access_key": "test-secret-key",
            "region": "us-east-1",
            "sync_security_hub": True,
            "sync_guardduty": True
        }
        
        test_data = {
            "provider": "aws",
            "config": aws_config
        }
        
        response = self.session.post(f"{self.base_url}/api/integrations/test", json=test_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ AWS integration test completed: {result['message']}")
            print(f"   Services available: {', '.join(result['services_available'])}")
            return True
        else:
            print(f"❌ AWS integration test failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    def test_azure_integration(self):
        """Test Azure integration"""
        print("\n🔷 Testing Azure Integration...")
        
        azure_config = {
            "subscription_id": "test-subscription-id",
            "access_token": "test-access-token",
            "tenant_id": "test-tenant-id"
        }
        
        test_data = {
            "provider": "azure",
            "config": azure_config
        }
        
        response = self.session.post(f"{self.base_url}/api/integrations/test", json=test_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Azure integration test completed: {result['message']}")
            print(f"   Services available: {', '.join(result['services_available'])}")
            return True
        else:
            print(f"❌ Azure integration test failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    def test_gcp_integration(self):
        """Test GCP integration"""
        print("\n☁️ Testing GCP Integration...")
        
        gcp_config = {
            "project_id": "test-project-id",
            "access_token": "test-access-token",
            "service_account_key": "test-service-account-key"
        }
        
        test_data = {
            "provider": "gcp",
            "config": gcp_config
        }
        
        response = self.session.post(f"{self.base_url}/api/integrations/test", json=test_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ GCP integration test completed: {result['message']}")
            print(f"   Services available: {', '.join(result['services_available'])}")
            return True
        else:
            print(f"❌ GCP integration test failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    def test_github_integration(self):
        """Test GitHub integration"""
        print("\n🐙 Testing GitHub Integration...")
        
        github_config = {
            "access_token": "test-github-token",
            "repositories": ["owner/repo1", "owner/repo2"],
            "webhook_secret": "test-webhook-secret"
        }
        
        test_data = {
            "provider": "github",
            "config": github_config
        }
        
        response = self.session.post(f"{self.base_url}/api/integrations/test", json=test_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ GitHub integration test completed: {result['message']}")
            print(f"   Services available: {', '.join(result['services_available'])}")
            return True
        else:
            print(f"❌ GitHub integration test failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    def test_slack_integration(self):
        """Test Slack integration"""
        print("\n💬 Testing Slack Integration...")
        
        slack_config = {
            "webhook_url": "https://hooks.slack.com/services/test/test/test",
            "channel": "#security-alerts",
            "username": "DriftBuddy"
        }
        
        test_data = {
            "provider": "slack",
            "config": slack_config
        }
        
        response = self.session.post(f"{self.base_url}/api/integrations/test", json=test_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Slack integration test completed: {result['message']}")
            print(f"   Services available: {', '.join(result['services_available'])}")
            return True
        else:
            print(f"❌ Slack integration test failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    def test_teams_integration(self):
        """Test Microsoft Teams integration"""
        print("\n💬 Testing Teams Integration...")
        
        teams_config = {
            "webhook_url": "https://test.webhook.office.com/webhookb2/test/test",
            "channel": "Security Alerts"
        }
        
        test_data = {
            "provider": "teams",
            "config": teams_config
        }
        
        response = self.session.post(f"{self.base_url}/api/integrations/test", json=test_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Teams integration test completed: {result['message']}")
            print(f"   Services available: {', '.join(result['services_available'])}")
            return True
        else:
            print(f"❌ Teams integration test failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    def test_jira_integration(self):
        """Test JIRA integration"""
        print("\n📋 Testing JIRA Integration...")
        
        jira_config = {
            "base_url": "https://test.atlassian.net",
            "username": "test@example.com",
            "api_token": "test-api-token",
            "project_key": "SEC"
        }
        
        test_data = {
            "provider": "jira",
            "config": jira_config
        }
        
        response = self.session.post(f"{self.base_url}/api/integrations/test", json=test_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ JIRA integration test completed: {result['message']}")
            print(f"   Services available: {', '.join(result['services_available'])}")
            return True
        else:
            print(f"❌ JIRA integration test failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    def create_test_integrations(self):
        """Create test integrations for each provider"""
        print("\n🔧 Creating test integrations...")
        
        integrations = [
            {
                "provider": "aws",
                "name": "AWS Production",
                "description": "AWS integration for production environment",
                "config": {
                    "access_key_id": "test-access-key",
                    "secret_access_key": "test-secret-key",
                    "region": "us-east-1"
                },
                "sync_frequency": "daily"
            },
            {
                "provider": "github",
                "name": "GitHub Security",
                "description": "GitHub integration for security scanning",
                "config": {
                    "access_token": "test-github-token",
                    "repositories": ["owner/repo1"]
                },
                "sync_frequency": "hourly"
            },
            {
                "provider": "slack",
                "name": "Security Alerts",
                "description": "Slack integration for security notifications",
                "config": {
                    "webhook_url": "https://hooks.slack.com/services/test/test/test",
                    "channel": "#security-alerts"
                },
                "sync_frequency": "manual"
            }
        ]
        
        created_integrations = []
        
        for integration_data in integrations:
            response = self.session.post(f"{self.base_url}/api/integrations/", json=integration_data)
            
            if response.status_code == 200:
                integration = response.json()
                created_integrations.append(integration)
                print(f"✅ Created {integration['provider']} integration: {integration['name']} (ID: {integration['id']})")
            else:
                print(f"❌ Failed to create {integration_data['provider']} integration: {response.status_code}")
        
        return created_integrations

    def test_notifications(self, integration_id):
        """Test sending notifications through an integration"""
        print(f"\n📢 Testing notifications for integration {integration_id}...")
        
        notification_data = {
            "message": "Test security alert from DriftBuddy",
            "severity": "high",
            "findings": [
                {
                    "title": "Test Finding",
                    "severity": "high",
                    "status": "open"
                }
            ]
        }
        
        response = self.session.post(f"{self.base_url}/api/integrations/{integration_id}/notify", json=notification_data)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Notification sent: {result['message']}")
            return True
        else:
            print(f"❌ Notification failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    def test_jira_ticket_creation(self, integration_id):
        """Test creating JIRA tickets"""
        print(f"\n🎫 Testing JIRA ticket creation for integration {integration_id}...")
        
        finding_data = {
            "title": "Test Security Finding",
            "description": "This is a test security finding for JIRA integration",
            "severity": "high",
            "source": "driftbuddy_test"
        }
        
        response = self.session.post(f"{self.base_url}/api/integrations/jira/create-ticket", 
                                   json={"integration_id": integration_id, "finding_data": finding_data})
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ JIRA ticket created: {result['message']}")
            return True
        else:
            print(f"❌ JIRA ticket creation failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False

    def test_integration_management(self, integration_id):
        """Test integration management features"""
        print(f"\n⚙️ Testing integration management for integration {integration_id}...")
        
        # Test getting integration status
        response = self.session.get(f"{self.base_url}/api/integrations/{integration_id}/status")
        if response.status_code == 200:
            status_data = response.json()
            print(f"✅ Integration status retrieved")
            print(f"   Active: {status_data['integration']['is_active']}")
            print(f"   Last sync: {status_data['last_sync']}")
            print(f"   Error count: {status_data['error_count']}")
        else:
            print(f"❌ Failed to get integration status: {response.status_code}")
        
        # Test getting integration logs
        response = self.session.get(f"{self.base_url}/api/integrations/{integration_id}/logs")
        if response.status_code == 200:
            logs = response.json()
            print(f"✅ Integration logs retrieved: {len(logs)} logs")
        else:
            print(f"❌ Failed to get integration logs: {response.status_code}")

    def run_comprehensive_test(self):
        """Run comprehensive integration tests"""
        print("🚀 Starting Comprehensive Integration Tests")
        print("=" * 50)
        
        # Login
        if not self.login():
            return False
        
        # Test supported integrations
        self.test_supported_integrations()
        
        # Test individual provider integrations
        self.test_aws_integration()
        self.test_azure_integration()
        self.test_gcp_integration()
        self.test_github_integration()
        self.test_slack_integration()
        self.test_teams_integration()
        self.test_jira_integration()
        
        # Create test integrations
        created_integrations = self.create_test_integrations()
        
        if created_integrations:
            # Test notifications for the first integration
            if len(created_integrations) > 0:
                first_integration = created_integrations[0]
                self.test_notifications(first_integration['id'])
                self.test_integration_management(first_integration['id'])
            
            # Test JIRA ticket creation if we have a JIRA integration
            jira_integrations = [i for i in created_integrations if i['provider'] == 'jira']
            if jira_integrations:
                self.test_jira_ticket_creation(jira_integrations[0]['id'])
        
        print("\n" + "=" * 50)
        print("🎉 Integration Tests Completed!")
        print("=" * 50)
        
        return True


def main():
    """Main test function"""
    tester = IntegrationTester()
    tester.run_comprehensive_test()


if __name__ == "__main__":
    main() 