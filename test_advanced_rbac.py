#!/usr/bin/env python3
"""
Test script for Advanced RBAC functionality in DriftBuddy
Demonstrates custom roles, permissions, role hierarchies, and conditional access control
"""

import json
import requests
import time
from typing import Dict, Any

# Configuration
BASE_URL = "http://localhost:8080"
ADMIN_EMAIL = "admin@driftbuddy.com"
ADMIN_PASSWORD = "admin123"

# Test users
TEST_USERS = [
    {
        "email": "security.analyst@company.com",
        "username": "security_analyst",
        "password": "password123",
        "role": "appsec"
    },
    {
        "email": "developer@company.com", 
        "username": "developer",
        "password": "password123",
        "role": "developer"
    },
    {
        "email": "compliance.auditor@company.com",
        "username": "compliance_auditor", 
        "password": "password123",
        "role": "developer"
    }
]


class RBACTester:
    """Test class for Advanced RBAC functionality"""
    
    def __init__(self):
        self.session = requests.Session()
        self.admin_token = None
        self.user_tokens = {}
        
    def login_admin(self) -> bool:
        """Login as admin user"""
        print("🔐 Logging in as admin...")
        
        response = self.session.post(
            f"{BASE_URL}/api/auth/login",
            data={
                "email": ADMIN_EMAIL,
                "password": ADMIN_PASSWORD
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            self.admin_token = data["access_token"]
            print("✅ Admin login successful")
            return True
        else:
            print(f"❌ Admin login failed: {response.text}")
            return False
    
    def create_test_users(self) -> bool:
        """Create test users for RBAC testing"""
        print("\n👥 Creating test users...")
        
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        
        for user_data in TEST_USERS:
            response = self.session.post(
                f"{BASE_URL}/api/auth/register",
                json=user_data,
                headers=headers
            )
            
            if response.status_code == 200:
                print(f"✅ Created user: {user_data['email']}")
            else:
                print(f"❌ Failed to create user {user_data['email']}: {response.text}")
        
        return True
    
    def login_test_users(self) -> bool:
        """Login test users and store tokens"""
        print("\n🔐 Logging in test users...")
        
        for user_data in TEST_USERS:
            response = self.session.post(
                f"{BASE_URL}/api/auth/login",
                data={
                    "email": user_data["email"],
                    "password": user_data["password"]
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                self.user_tokens[user_data["email"]] = data["access_token"]
                print(f"✅ Login successful: {user_data['email']}")
            else:
                print(f"❌ Login failed for {user_data['email']}: {response.text}")
        
        return True
    
    def test_rbac_permissions(self) -> bool:
        """Test RBAC permissions endpoint"""
        print("\n📋 Testing RBAC permissions...")
        
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        response = self.session.get(f"{BASE_URL}/api/rbac/permissions", headers=headers)
        
        if response.status_code == 200:
            permissions = response.json()
            print("✅ Available permissions:")
            for resource, perms in permissions.items():
                print(f"  {resource}: {len(perms)} permissions")
            return True
        else:
            print(f"❌ Failed to get permissions: {response.text}")
            return False
    
    def test_role_templates(self) -> bool:
        """Test role templates endpoint"""
        print("\n📋 Testing role templates...")
        
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        response = self.session.get(f"{BASE_URL}/api/rbac/templates", headers=headers)
        
        if response.status_code == 200:
            templates = response.json()
            print("✅ Available role templates:")
            for template_name, template_data in templates.items():
                print(f"  {template_name}: {template_data['name']}")
            return True
        else:
            print(f"❌ Failed to get role templates: {response.text}")
            return False
    
    def create_custom_roles(self) -> Dict[str, int]:
        """Create custom roles for testing"""
        print("\n👥 Creating custom roles...")
        
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        role_ids = {}
        
        # Create Security Analyst role
        response = self.session.post(
            f"{BASE_URL}/api/rbac/roles",
            data={
                "name": "Security Analyst",
                "description": "Security analyst with comprehensive access to security features",
                "organization_id": "1",
                "permissions": json.dumps([
                    "scan:create", "scan:read", "scan:run", "scan:export",
                    "report:create", "report:read", "report:export",
                    "cloud:connect", "cloud:scan",
                    "compliance:read", "compliance:generate", "compliance:export"
                ])
            },
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            role_ids["security_analyst"] = data["role"]["id"]
            print("✅ Created Security Analyst role")
        else:
            print(f"❌ Failed to create Security Analyst role: {response.text}")
        
        # Create Compliance Auditor role
        response = self.session.post(
            f"{BASE_URL}/api/rbac/roles",
            data={
                "name": "Compliance Auditor",
                "description": "Compliance auditor with focus on reporting and auditing",
                "organization_id": "1",
                "permissions": json.dumps([
                    "scan:read", "scan:export",
                    "report:create", "report:read", "report:export", "report:schedule",
                    "compliance:read", "compliance:generate", "compliance:export"
                ])
            },
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            role_ids["compliance_auditor"] = data["role"]["id"]
            print("✅ Created Compliance Auditor role")
        else:
            print(f"❌ Failed to create Compliance Auditor role: {response.text}")
        
        return role_ids
    
    def assign_roles_to_users(self, role_ids: Dict[str, int]) -> bool:
        """Assign custom roles to test users"""
        print("\n👥 Assigning roles to users...")
        
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        
        # Get user IDs first
        response = self.session.get(f"{BASE_URL}/api/admin/users", headers=headers)
        if response.status_code != 200:
            print(f"❌ Failed to get users: {response.text}")
            return False
        
        users = response.json()
        user_map = {user["email"]: user["id"] for user in users}
        
        # Assign Security Analyst role to security analyst
        if "security_analyst" in role_ids and "security.analyst@company.com" in user_map:
            response = self.session.post(
                f"{BASE_URL}/api/rbac/users/{user_map['security.analyst@company.com']}/roles/{role_ids['security_analyst']}",
                headers=headers
            )
            if response.status_code == 200:
                print("✅ Assigned Security Analyst role to security analyst")
            else:
                print(f"❌ Failed to assign Security Analyst role: {response.text}")
        
        # Assign Compliance Auditor role to compliance auditor
        if "compliance_auditor" in role_ids and "compliance.auditor@company.com" in user_map:
            response = self.session.post(
                f"{BASE_URL}/api/rbac/users/{user_map['compliance.auditor@company.com']}/roles/{role_ids['compliance_auditor']}",
                headers=headers
            )
            if response.status_code == 200:
                print("✅ Assigned Compliance Auditor role to compliance auditor")
            else:
                print(f"❌ Failed to assign Compliance Auditor role: {response.text}")
        
        return True
    
    def test_user_permissions(self) -> bool:
        """Test user permissions for different roles"""
        print("\n🔍 Testing user permissions...")
        
        # Test Security Analyst permissions
        security_analyst_token = self.user_tokens.get("security.analyst@company.com")
        if security_analyst_token:
            headers = {"Authorization": f"Bearer {security_analyst_token}"}
            
            # Test scan creation (should be allowed)
            response = self.session.post(
                f"{BASE_URL}/api/scans",
                json={
                    "name": "Security Analyst Test Scan",
                    "description": "Test scan by security analyst",
                    "scan_type": "kics"
                },
                headers=headers
            )
            
            if response.status_code == 200:
                print("✅ Security Analyst can create scans")
            else:
                print(f"❌ Security Analyst cannot create scans: {response.text}")
            
            # Test report creation (should be allowed)
            response = self.session.post(
                f"{BASE_URL}/api/reports/generate",
                json={
                    "name": "Security Analyst Test Report",
                    "type": "scan_report",
                    "format": "html"
                },
                headers=headers
            )
            
            if response.status_code == 200:
                print("✅ Security Analyst can create reports")
            else:
                print(f"❌ Security Analyst cannot create reports: {response.text}")
        
        # Test Developer permissions (should be limited)
        developer_token = self.user_tokens.get("developer@company.com")
        if developer_token:
            headers = {"Authorization": f"Bearer {developer_token}"}
            
            # Test scan creation (should be allowed for developers)
            response = self.session.post(
                f"{BASE_URL}/api/scans",
                json={
                    "name": "Developer Test Scan",
                    "description": "Test scan by developer",
                    "scan_type": "kics"
                },
                headers=headers
            )
            
            if response.status_code == 200:
                print("✅ Developer can create scans")
            else:
                print(f"❌ Developer cannot create scans: {response.text}")
            
            # Test report creation (should be denied for developers)
            response = self.session.post(
                f"{BASE_URL}/api/reports/generate",
                json={
                    "name": "Developer Test Report",
                    "type": "scan_report",
                    "format": "html"
                },
                headers=headers
            )
            
            if response.status_code == 403:
                print("✅ Developer correctly denied report creation")
            else:
                print(f"❌ Developer incorrectly allowed report creation: {response.text}")
        
        return True
    
    def test_role_hierarchy(self) -> bool:
        """Test role hierarchy functionality"""
        print("\n👥 Testing role hierarchy...")
        
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        
        # Get available roles
        response = self.session.get(f"{BASE_URL}/api/rbac/roles", headers=headers)
        if response.status_code != 200:
            print(f"❌ Failed to get roles: {response.text}")
            return False
        
        roles = response.json()
        if len(roles) < 2:
            print("❌ Need at least 2 roles for hierarchy testing")
            return False
        
        # Create hierarchy between first two roles
        parent_role_id = roles[0]["id"]
        child_role_id = roles[1]["id"]
        
        response = self.session.post(
            f"{BASE_URL}/api/rbac/hierarchy",
            data={
                "parent_role_id": str(parent_role_id),
                "child_role_id": str(child_role_id)
            },
            headers=headers
        )
        
        if response.status_code == 200:
            print("✅ Created role hierarchy")
        else:
            print(f"❌ Failed to create role hierarchy: {response.text}")
        
        return True
    
    def test_permission_checking(self) -> bool:
        """Test permission checking functionality"""
        print("\n🔍 Testing permission checking...")
        
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        
        # Test permission check for scan creation
        response = self.session.post(
            f"{BASE_URL}/api/rbac/check-permission",
            data={
                "resource": "scan",
                "action": "create"
            },
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Permission check result: {data['has_permission']}")
        else:
            print(f"❌ Failed to check permission: {response.text}")
        
        return True
    
    def test_my_permissions(self) -> bool:
        """Test getting current user permissions"""
        print("\n🔍 Testing my permissions...")
        
        # Test for different users
        for email, token in self.user_tokens.items():
            headers = {"Authorization": f"Bearer {token}"}
            
            response = self.session.get(f"{BASE_URL}/api/rbac/my-permissions", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ {email} permissions:")
                print(f"  Built-in role: {data['built_in_role']}")
                print(f"  Custom roles: {len(data['custom_roles'])}")
                print(f"  Total permissions: {len(data['permissions'])}")
            else:
                print(f"❌ Failed to get permissions for {email}: {response.text}")
        
        return True
    
    def run_comprehensive_test(self):
        """Run comprehensive RBAC test"""
        print("🚀 Starting Advanced RBAC Test")
        print("=" * 50)
        
        # Step 1: Login as admin
        if not self.login_admin():
            return False
        
        # Step 2: Create test users
        self.create_test_users()
        
        # Step 3: Login test users
        self.login_test_users()
        
        # Step 4: Test RBAC endpoints
        self.test_rbac_permissions()
        self.test_role_templates()
        
        # Step 5: Create custom roles
        role_ids = self.create_custom_roles()
        
        # Step 6: Assign roles to users
        self.assign_roles_to_users(role_ids)
        
        # Step 7: Test user permissions
        self.test_user_permissions()
        
        # Step 8: Test role hierarchy
        self.test_role_hierarchy()
        
        # Step 9: Test permission checking
        self.test_permission_checking()
        
        # Step 10: Test my permissions
        self.test_my_permissions()
        
        print("\n🎉 Advanced RBAC Test Complete!")
        print("=" * 50)
        return True


def main():
    """Main test function"""
    tester = RBACTester()
    success = tester.run_comprehensive_test()
    
    if success:
        print("\n✅ All RBAC tests completed successfully!")
    else:
        print("\n❌ Some RBAC tests failed!")
    
    return success


if __name__ == "__main__":
    main() 