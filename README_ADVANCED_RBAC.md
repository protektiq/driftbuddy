# Advanced RBAC (Role-Based Access Control) - DriftBuddy Phase 3

## Overview

DriftBuddy now includes a comprehensive Advanced RBAC system that provides granular access control, custom roles, role hierarchies, and conditional permissions. This implementation supports enterprise-grade security requirements with flexible role management.

## Features

### 🔐 Core RBAC Features
- **Custom Roles**: Create and manage custom roles with specific permissions
- **Granular Permissions**: Fine-grained control over resources and actions
- **Role Hierarchies**: Inherit permissions through role inheritance
- **Conditional Access**: Time-based and context-aware permissions
- **Role Templates**: Predefined role templates for common use cases
- **Multi-Organization Support**: Role management across organizations

### 👥 Role Management
- **Built-in Roles**: Admin, AppSec, Developer roles
- **Custom Roles**: Create unlimited custom roles
- **Role Assignment**: Assign multiple roles to users
- **Role Inheritance**: Child roles inherit parent permissions
- **Role Templates**: Security Analyst, Compliance Auditor, etc.

### 🔍 Permission System
- **Resource-Based**: Permissions organized by resource (scan, report, user, etc.)
- **Action-Based**: Specific actions (create, read, update, delete, etc.)
- **Conditional**: Time restrictions, IP restrictions, organization-based
- **Wildcard Support**: `*:*` for all permissions, `scan:*` for all scan actions

## Database Schema

### Core Tables

#### Users
```sql
users (
    id, email, username, hashed_password, role, 
    organization_id, is_active, created_at, updated_at
)
```

#### Custom Roles
```sql
custom_roles (
    id, name, description, organization_id, 
    is_active, created_at, updated_at
)
```

#### Permissions
```sql
permissions (
    id, name, description, resource, action, 
    conditions, created_at
)
```

#### Role Hierarchies
```sql
role_hierarchies (
    id, parent_role_id, child_role_id, created_at
)
```

#### Junction Tables
```sql
user_roles (user_id, role_id)
role_permissions (role_id, permission_id)
```

## API Endpoints

### Authentication
```http
POST /api/auth/login
POST /api/auth/register
GET /api/auth/me
```

### RBAC Management

#### Roles
```http
POST /api/rbac/roles                    # Create custom role
GET /api/rbac/roles                     # List all roles
GET /api/rbac/roles/{role_id}          # Get specific role
PUT /api/rbac/roles/{role_id}          # Update role
DELETE /api/rbac/roles/{role_id}       # Delete role
```

#### Role Templates
```http
POST /api/rbac/roles/template          # Create role from template
GET /api/rbac/templates                # Get available templates
```

#### User Role Assignment
```http
POST /api/rbac/users/{user_id}/roles/{role_id}    # Assign role
DELETE /api/rbac/users/{user_id}/roles/{role_id}  # Remove role
GET /api/rbac/users/{user_id}/roles               # Get user roles
```

#### Permissions
```http
GET /api/rbac/permissions              # Get available permissions
GET /api/rbac/permissions/all          # List all permissions
POST /api/rbac/permissions             # Create new permission
```

#### Role Hierarchies
```http
POST /api/rbac/hierarchy               # Create hierarchy
GET /api/rbac/hierarchy                # List hierarchies
DELETE /api/rbac/hierarchy/{id}        # Delete hierarchy
```

#### Permission Checking
```http
POST /api/rbac/check-permission       # Check specific permission
GET /api/rbac/my-permissions          # Get current user permissions
```

#### System Setup
```http
POST /api/rbac/setup-defaults         # Setup default RBAC system
```

## Usage Examples

### 1. Creating a Custom Role

```python
import requests
import json

# Login as admin
response = requests.post("http://localhost:8080/api/auth/login", data={
    "email": "admin@driftbuddy.com",
    "password": "admin123"
})
token = response.json()["access_token"]

# Create Security Analyst role
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(
    "http://localhost:8080/api/rbac/roles",
    data={
        "name": "Security Analyst",
        "description": "Security analyst with comprehensive access",
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

print(response.json())
```

### 2. Creating Role from Template

```python
# Create role from Security Analyst template
response = requests.post(
    "http://localhost:8080/api/rbac/roles/template",
    data={
        "template_name": "security_analyst",
        "organization_id": "1",
        "custom_name": "My Security Analyst",
        "additional_permissions": json.dumps(["user:read"])
    },
    headers=headers
)
```

### 3. Assigning Roles to Users

```python
# Get user ID
users_response = requests.get(
    "http://localhost:8080/api/admin/users",
    headers=headers
)
users = users_response.json()
user_id = next(u["id"] for u in users if u["email"] == "security.analyst@company.com")

# Assign role
role_id = 1  # Security Analyst role ID
response = requests.post(
    f"http://localhost:8080/api/rbac/users/{user_id}/roles/{role_id}",
    headers=headers
)
```

### 4. Checking Permissions

```python
# Check if user has permission
response = requests.post(
    "http://localhost:8080/api/rbac/check-permission",
    data={
        "resource": "scan",
        "action": "create"
    },
    headers=headers
)

result = response.json()
if result["has_permission"]:
    print("User can create scans")
else:
    print("User cannot create scans")
```

### 5. Getting User Permissions

```python
# Get current user's permissions
response = requests.get(
    "http://localhost:8080/api/rbac/my-permissions",
    headers=headers
)

permissions = response.json()
print(f"Built-in role: {permissions['built_in_role']}")
print(f"Custom roles: {len(permissions['custom_roles'])}")
print(f"Total permissions: {len(permissions['permissions'])}")
```

## Default Permissions

### Scan Permissions
- `scan:create` - Create new scans
- `scan:read` - View scan results
- `scan:update` - Update scan configurations
- `scan:delete` - Delete scans
- `scan:run` - Execute scans
- `scan:export` - Export scan data

### Report Permissions
- `report:create` - Generate reports
- `report:read` - View reports
- `report:export` - Export report data
- `report:schedule` - Schedule report generation

### User Permissions
- `user:create` - Create new users
- `user:read` - View user information
- `user:update` - Update user profiles
- `user:delete` - Delete users
- `user:assign_roles` - Assign roles to users

### Organization Permissions
- `organization:read` - View organization information
- `organization:update` - Update organization settings
- `organization:manage_users` - Manage organization users
- `organization:manage_roles` - Manage organization roles

### Cloud Permissions
- `cloud:connect` - Connect cloud accounts
- `cloud:scan` - Scan cloud infrastructure
- `cloud:manage_credentials` - Manage cloud credentials

### Compliance Permissions
- `compliance:read` - View compliance reports
- `compliance:generate` - Generate compliance reports
- `compliance:export` - Export compliance data

### Admin Permissions
- `*:*` - All permissions (admin only)

## Role Templates

### Security Analyst
```json
{
  "name": "Security Analyst",
  "description": "Security analyst with comprehensive access to security features",
  "permissions": [
    "scan:create", "scan:read", "scan:run", "scan:export",
    "report:create", "report:read", "report:export",
    "cloud:connect", "cloud:scan",
    "compliance:read", "compliance:generate", "compliance:export"
  ]
}
```

### Security Manager
```json
{
  "name": "Security Manager",
  "description": "Security manager with team management capabilities",
  "permissions": [
    "scan:create", "scan:read", "scan:update", "scan:delete", "scan:run", "scan:export",
    "user:read", "user:update",
    "report:create", "report:read", "report:export", "report:schedule",
    "cloud:connect", "cloud:scan", "cloud:manage_credentials",
    "compliance:read", "compliance:generate", "compliance:export",
    "organization:read", "organization:manage_users"
  ]
}
```

### Compliance Auditor
```json
{
  "name": "Compliance Auditor",
  "description": "Compliance auditor with focus on reporting and auditing",
  "permissions": [
    "scan:read", "scan:export",
    "report:create", "report:read", "report:export", "report:schedule",
    "compliance:read", "compliance:generate", "compliance:export"
  ]
}
```

### Developer
```json
{
  "name": "Developer",
  "description": "Developer with limited access to security features",
  "permissions": [
    "scan:create", "scan:read", "scan:run", "report:read"
  ]
}
```

### Viewer
```json
{
  "name": "Viewer",
  "description": "Read-only access to security information",
  "permissions": [
    "scan:read", "report:read"
  ]
}
```

## Conditional Permissions

### Time-Based Restrictions
```python
# Permission with time restriction
permission = {
    "name": "scan:create",
    "resource": "scan",
    "action": "create",
    "conditions": {
        "time_restriction": {
            "start": 9,  # 9 AM
            "end": 17    # 5 PM
        }
    }
}
```

### Organization-Based Restrictions
```python
# Permission limited to specific organization
permission = {
    "name": "user:read",
    "resource": "user",
    "action": "read",
    "conditions": {
        "organization_id": 1
    }
}
```

### IP-Based Restrictions
```python
# Permission limited to specific IP ranges
permission = {
    "name": "admin:*",
    "resource": "*",
    "action": "*",
    "conditions": {
        "ip_restriction": {
            "allowed_ips": ["192.168.1.0/24", "10.0.0.0/8"]
        }
    }
}
```

## Role Hierarchy Example

```python
# Create role hierarchy
response = requests.post(
    "http://localhost:8080/api/rbac/hierarchy",
    data={
        "parent_role_id": "1",  # Security Manager
        "child_role_id": "2"    # Security Analyst
    },
    headers=headers
)

# Security Analyst will inherit all Security Manager permissions
```

## Testing the RBAC System

### Run the Test Script
```bash
python test_advanced_rbac.py
```

### Manual Testing
```bash
# Start the server
python -m uvicorn web.api_v3_simple:app --reload --host 0.0.0.0 --port 8080

# Test endpoints
curl -X POST "http://localhost:8080/api/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=admin@driftbuddy.com&password=admin123"

curl -X GET "http://localhost:8080/api/rbac/permissions" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Security Considerations

### Best Practices
1. **Principle of Least Privilege**: Grant minimum necessary permissions
2. **Regular Audits**: Review role assignments and permissions regularly
3. **Role Templates**: Use predefined templates for consistency
4. **Conditional Access**: Implement time and context-based restrictions
5. **Hierarchy Management**: Carefully design role hierarchies to avoid privilege escalation

### Audit Trail
- All role assignments are logged
- Permission checks are recorded
- Role modifications are tracked
- Access attempts are monitored

### Data Protection
- Permissions are stored securely
- Role assignments are encrypted
- Access tokens have expiration
- Session management is secure

## Integration with Existing Features

### Scan Management
- Users can only access scans they have permission for
- Role-based scan creation and execution
- Organization-based scan isolation

### Report Generation
- Role-based report access
- Permission-based report creation
- Organization-specific reporting

### Compliance
- Role-based compliance access
- Permission-based framework management
- Organization-specific compliance data

### Cloud Integration
- Role-based cloud access
- Permission-based cloud scanning
- Organization-based cloud isolation

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Check user's built-in role
   - Verify custom role assignments
   - Review role hierarchy inheritance
   - Check conditional permissions

2. **Role Creation Failed**
   - Verify admin permissions
   - Check organization ID
   - Validate permission names
   - Ensure unique role names

3. **Role Assignment Failed**
   - Verify user exists
   - Check role exists
   - Ensure admin permissions
   - Validate organization membership

### Debug Commands
```python
# Check user permissions
GET /api/rbac/my-permissions

# List all roles
GET /api/rbac/roles

# Check specific permission
POST /api/rbac/check-permission

# Get role details
GET /api/rbac/roles/{role_id}
```

## Future Enhancements

### Planned Features
1. **Dynamic Permissions**: Runtime permission evaluation
2. **Advanced Conditions**: Complex permission conditions
3. **Permission Groups**: Group permissions for easier management
4. **Audit Dashboard**: Visual RBAC audit interface
5. **API Rate Limiting**: Role-based rate limiting
6. **Multi-Factor Authentication**: Role-based MFA requirements

### Integration Roadmap
1. **LDAP Integration**: Enterprise directory integration
2. **SAML Support**: Single sign-on integration
3. **OAuth Integration**: Third-party authentication
4. **API Gateway**: External API access control
5. **Microservices**: Distributed RBAC system

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the API documentation
3. Test with the provided test script
4. Check server logs for detailed error messages

## License

This RBAC implementation is part of DriftBuddy and follows the same licensing terms. 