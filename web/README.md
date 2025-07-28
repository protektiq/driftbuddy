# DriftBuddy Web Interface

A modern web interface for DriftBuddy security scanning with authentication, RBAC, compliance reporting, and real-time scanning capabilities.

## Features

### 🔐 Authentication & RBAC
- **JWT-based authentication** with secure token management
- **Advanced role-based access control** with custom roles and permissions:
  - **Developer**: Can create and view their own scans
  - **AppSec**: Can view all scans in organization and manage settings
  - **Admin**: Full access to all features including user management
  - **Custom Roles**: Create organization-specific roles with granular permissions
- **Secure password hashing** with bcrypt
- **Session management** with automatic token refresh

### 📁 File Upload & KICS Integration
- **Drag-and-drop file upload** for IaC files
- **Supported file types**: `.tf`, `.yaml`, `.yml`, `.json`, `.dockerfile`, `.bicep`, `.hcl`, `.tfvars`
- **Real-time KICS scanning** with progress tracking
- **Automatic file validation** and error handling
- **Secure file storage** with cleanup capabilities

### 📊 Dashboard & Results
- **Real-time scan status** with live updates via WebSockets
- **Findings display** with severity and risk scoring
- **Scan history** with pagination and filtering
- **Detailed scan reports** with business impact analysis
- **Export capabilities** for reports and findings

### 📋 Compliance Reporting
- **SOC2 Framework**: Complete SOC2 Type II compliance reporting
- **PCI DSS**: Payment Card Industry compliance assessment
- **HIPAA**: Healthcare compliance framework support
- **Custom Frameworks**: Create organization-specific compliance frameworks
- **Audit Trails**: Complete audit logging for compliance requirements

### 🔗 External Integrations
- **Jira Integration**: Create issues directly from security findings
- **Slack Notifications**: Real-time security alerts and reports
- **Microsoft Teams**: Enterprise notification integration
- **Webhook Support**: Custom webhook endpoints for any system

### ☁️ Cloud Connector
- **AWS Integration**: Direct AWS account scanning with Steampipe
- **Azure Integration**: Microsoft Azure resource analysis
- **GCP Integration**: Google Cloud Platform security scanning
- **Multi-cloud Support**: Unified view across multiple cloud providers

### 🤖 AI-Powered Analysis
- **Interactive Chat**: AI-powered security analysis and recommendations
- **Finding Analysis**: Detailed AI explanations of security issues
- **Remediation Plans**: AI-generated remediation strategies
- **Risk Assessment**: Business impact analysis with cost estimates

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements-web-v3.txt
```

### 2. Run the Web Interface
```bash
python run_web_v3.py
```

### 3. Access the Application
- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Default Admin**: admin@driftbuddy.com / admin123

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/auth/me` - Get current user info

### RBAC Management
- `POST /api/rbac/roles` - Create custom role
- `POST /api/rbac/roles/template` - Create role from template
- `POST /api/rbac/users/{user_id}/roles/{role_id}` - Assign role to user
- `GET /api/rbac/permissions` - Get available permissions
- `GET /api/rbac/templates` - Get role templates

### Scan Management
- `POST /api/scans` - Create new scan
- `GET /api/scans` - List user's scans
- `GET /api/scans/{id}` - Get scan details
- `POST /api/scans/{id}/upload` - Upload files for scanning
- `POST /api/scans/{id}/run` - Run KICS scan
- `GET /api/scans/{id}/findings` - Get scan findings
- `DELETE /api/scans/{id}` - Delete scan

### Compliance Reporting
- `POST /api/compliance/reports/{framework}` - Generate compliance report
- `GET /api/compliance/frameworks` - Get supported frameworks
- `GET /api/compliance/frameworks/{framework}/controls` - Get framework controls
- `GET /api/compliance/assessments` - List compliance assessments
- `POST /api/compliance/assessments` - Create compliance assessment

### External Integrations
- `POST /api/integrations/{integration_name}/test` - Test integration
- `POST /api/integrations/jira/issues` - Create Jira issue from finding
- `POST /api/integrations/notifications/scan` - Send scan notifications

### Cloud Connector
- `POST /api/cloud/connect/aws` - Connect AWS account
- `POST /api/cloud/connect/azure` - Connect Azure account
- `POST /api/cloud/connect/gcp` - Connect GCP account
- `POST /api/cloud/scan` - Run cloud security scan

### AI Chat
- `POST /api/chat/message` - Send chat message
- `GET /api/chat/history` - Get chat history
- `POST /api/chat/analyze/{scan_id}` - Analyze findings with AI
- `POST /api/chat/remediation-plan/{scan_id}` - Generate remediation plan

### Reporting
- `POST /api/reports/generate/{scan_id}` - Generate scan report
- `POST /api/reports/organization` - Generate organization report
- `POST /api/reports/export/{scan_id}` - Export scan data

### WebSocket Endpoints
- `GET /ws/{user_id}` - User-specific real-time updates
- `GET /ws/scan/{scan_id}` - Scan-specific progress updates

### Admin Endpoints
- `GET /api/admin/users` - List all users (admin only)
- `POST /api/admin/users` - Create new user (admin only)

## Database Schema

### Users
- `id`: Primary key
- `email`: Unique email address
- `username`: Unique username
- `hashed_password`: Bcrypt hashed password
- `role`: User role (developer, appsec, admin)
- `organization_id`: Organization foreign key
- `is_active`: Account status
- `created_at`, `updated_at`: Timestamps

### Organizations
- `id`: Primary key
- `name`: Organization name
- `slug`: Unique organization slug
- `settings`: JSON configuration
- `created_at`, `updated_at`: Timestamps

### Scans
- `id`: Primary key
- `user_id`: User who created the scan
- `organization_id`: Organization the scan belongs to
- `name`: Scan name
- `description`: Optional description
- `status`: Scan status (pending, running, completed, failed)
- `scan_type`: Type of scan (kics, steampipe, combined)
- `results`: JSON scan results
- `metadata`: JSON scan metadata
- `created_at`, `updated_at`, `completed_at`: Timestamps

### Findings
- `id`: Primary key
- `scan_id`: Associated scan
- `query_name`: KICS query name
- `severity`: Finding severity (HIGH, MEDIUM, LOW, INFO)
- `description`: Finding description
- `file_path`: Affected file path
- `line_number`: Affected line number
- `remediation`: Suggested remediation
- `ai_explanation`: AI-generated explanation
- `risk_score`: Calculated risk score (1-25)
- `business_impact`: Business impact analysis
- `created_at`: Timestamp

### Compliance Frameworks
- `id`: Primary key
- `name`: Framework name (SOC2, PCI, HIPAA, etc.)
- `version`: Framework version
- `description`: Framework description
- `controls`: JSON array of compliance controls
- `organization_id`: Organization foreign key
- `created_at`, `updated_at`: Timestamps

### Compliance Assessments
- `id`: Primary key
- `framework_id`: Associated compliance framework
- `scan_id`: Associated security scan
- `status`: Assessment status
- `results`: JSON assessment results
- `created_at`, `updated_at`: Timestamps

## Security Features

### Authentication
- **JWT tokens** with configurable expiration
- **Secure password hashing** using bcrypt
- **Token-based session management**
- **Automatic token refresh**

### Authorization
- **Advanced role-based access control** with hierarchical permissions
- **Organization-based data isolation**
- **Resource-level permission checks**
- **Custom role creation** with granular permissions
- **Admin-only endpoints** for user management

### Data Protection
- **Input validation** for all endpoints
- **SQL injection prevention** with SQLAlchemy ORM
- **File upload security** with type validation
- **Secure file storage** with cleanup
- **Audit logging** for compliance requirements

## Configuration

### Environment Variables
```bash
# Required
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///./driftbuddy.db

# Optional
OPENAI_API_KEY=your-openai-api-key
LOG_LEVEL=INFO
DEBUG=false

# Integration Settings
JIRA_ENABLED=false
SLACK_ENABLED=false
TEAMS_ENABLED=false
LDAP_ENABLED=false
SAML_ENABLED=false
OAUTH_ENABLED=false
```

### Database Setup
The application automatically:
- Creates database tables on startup
- Creates default organization
- Creates default admin user
- Sets up RBAC system
- Sets up compliance frameworks
- Handles database migrations

## Development

### Project Structure
```
web/
├── __init__.py              # Package initialization
├── api_v3_simple.py         # FastAPI application and main routes
├── auth.py                  # Authentication and authorization
├── database.py              # Database connection and models
├── models.py                # SQLAlchemy models and Pydantic schemas
├── services.py              # Business logic and KICS integration
├── rbac_api.py              # RBAC-specific endpoints
├── compliance_api.py        # Compliance reporting endpoints
├── ml_analytics_api.py      # ML analytics endpoints
├── integrations_api.py      # External integrations
├── cloud_connector.py       # Cloud provider integrations
├── ai_chat.py               # AI chat functionality
├── reporting.py             # Report generation
├── websocket.py             # WebSocket handling
└── frontend/                # React frontend application
```

### Adding New Features
1. **Models**: Add new SQLAlchemy models in `models.py`
2. **Services**: Add business logic in `services.py`
3. **API**: Add endpoints in `api_v3_simple.py` or create new router
4. **Frontend**: Update `frontend/` for UI changes

### Testing
```bash
# Run tests
pytest tests/

# Test specific module
pytest tests/test_web_interface.py
```

## Deployment

### Production Setup
1. **Set secure environment variables**
2. **Use production database** (PostgreSQL recommended)
3. **Configure reverse proxy** (nginx)
4. **Set up SSL certificates**
5. **Configure logging and monitoring**

### Docker Deployment
```bash
# Build image
docker build -t driftbuddy-web .

# Run container
docker run -p 8000:8000 driftbuddy-web
```

## Troubleshooting

### Common Issues
1. **Database errors**: Check database URL and permissions
2. **KICS not found**: Ensure KICS is installed and in PATH
3. **File upload errors**: Check file permissions and disk space
4. **Authentication errors**: Verify JWT secret key
5. **Integration errors**: Check API keys and network connectivity

### Logs
- **Application logs**: Check console output
- **Database logs**: Check database connection
- **File system logs**: Check upload directory permissions

## Contributing

1. **Fork the repository**
2. **Create feature branch**
3. **Add tests for new functionality**
4. **Submit pull request**

## License

Same as DriftBuddy main project. 
