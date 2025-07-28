# DriftBuddy Web Interface - Phase 3

Enterprise-ready web interface for DriftBuddy with advanced RBAC, compliance reporting, external integrations, and enhanced security features.

## 🚀 Phase 3 Features

### 👥 Advanced RBAC (Role-Based Access Control)
- **Custom Roles**: Create organization-specific roles with granular permissions
- **Permission Management**: Fine-grained control over resources and actions
- **Role Hierarchies**: Inherit permissions from parent roles
- **Conditional Access**: Context-aware permission checking
- **Role Templates**: Predefined role templates for common use cases
- **User Role Assignment**: Assign multiple roles to users with inheritance

### 📋 Compliance Reporting
- **SOC2 Framework**: Complete SOC2 Type II compliance reporting
- **PCI DSS**: Payment Card Industry Data Security Standard reporting
- **HIPAA**: Health Insurance Portability and Accountability Act reporting
- **Control Mapping**: Automatic mapping of findings to compliance controls
- **Gap Analysis**: Identify missing controls and compliance gaps
- **Audit Trails**: Complete audit trail for compliance requirements

### 🔗 External Integrations
- **Jira Integration**: Create and update issues from security findings
- **Slack Notifications**: Real-time security alerts and scan notifications
- **Microsoft Teams**: Integration with Teams for security communications
- **Webhook Support**: Generic webhook support for custom integrations
- **API Connectors**: RESTful API connectors for external systems

### ☁️ Enhanced Cloud Connector
- **Multi-Cloud Support**: AWS, Azure, and GCP integration
- **Steampipe Integration**: Advanced cloud infrastructure querying
- **Real-time Scanning**: Live cloud infrastructure monitoring
- **Security Queries**: Pre-built security assessment queries
- **Drift Detection**: Identify configuration drift in cloud resources

### 🤖 AI-Powered Analysis
- **LangChain Integration**: Advanced AI capabilities with memory and chains
- **Context-Aware Analysis**: AI responses based on user role and context
- **Remediation Planning**: Generate comprehensive remediation plans
- **Risk Assessment**: AI-powered risk analysis and prioritization
- **Natural Language Queries**: Chat-based security analysis

### 🔌 Real-time Features
- **WebSocket Updates**: Real-time scan progress and findings
- **Live Notifications**: Instant alerts for security events
- **Chat Integration**: Real-time AI chat with context awareness
- **Multi-user Support**: Concurrent user connections and updates

### 📊 Advanced Reporting
- **Multiple Formats**: HTML, JSON, CSV, PDF export capabilities
- **Compliance Reports**: Framework-specific compliance reporting
- **Executive Dashboards**: Business-focused security metrics
- **Custom Templates**: Jinja2-based report customization
- **Data Export**: Comprehensive data export in various formats

## 🏗️ Architecture

### Core Components
```
web/
├── api_v3.py              # Phase 3 FastAPI application
├── advanced_rbac.py       # Advanced RBAC system
├── compliance_reporting.py # Compliance framework reporting
├── integration_apis.py    # External system integrations
├── cloud_connector.py     # Enhanced cloud integration
├── ai_chat.py            # AI chat with LangChain
├── websocket.py          # Real-time WebSocket manager
├── reporting.py          # Advanced reporting service
├── services.py           # Enhanced business logic
├── auth.py              # Authentication & RBAC
├── models.py            # Database models
└── database.py          # Database management
```

### Service Integration
- **Advanced RBAC**: Custom roles, permissions, and hierarchical access control
- **Compliance Service**: SOC2, PCI, HIPAA framework support
- **Integration Service**: Jira, Slack, Teams, and webhook integrations
- **Cloud Connector**: Multi-cloud infrastructure scanning with Steampipe
- **AI Chat Service**: LangChain integration for intelligent analysis
- **WebSocket Service**: Real-time communication and updates
- **Reporting Service**: Comprehensive reporting and export capabilities

## 🚀 Quick Start

### 1. Install Phase 3 Dependencies
```bash
pip install -r requirements-web-v3.txt
```

### 2. Set Up Environment Variables
```bash
# Required
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///./driftbuddy.db

# Optional (for AI features)
OPENAI_API_KEY=your-openai-api-key

# Optional (for cloud features)
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AZURE_TENANT_ID=your-azure-tenant-id
GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

# Optional (for external integrations)
JIRA_ENABLED=true
JIRA_API_URL=https://your-domain.atlassian.net
JIRA_API_KEY=your-jira-api-key
SLACK_ENABLED=true
SLACK_BOT_TOKEN=your-slack-bot-token
TEAMS_ENABLED=true
TEAMS_WEBHOOK_URL=your-teams-webhook-url
```

### 3. Run Phase 3 Web Interface
```bash
python run_web_v3.py
```

### 4. Access the Application
- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Default Admin**: admin@driftbuddy.com / admin123

## 📋 API Endpoints

### Advanced RBAC Endpoints
```http
POST /api/rbac/roles                    # Create custom role
POST /api/rbac/roles/template           # Create role from template
POST /api/rbac/users/{user_id}/roles/{role_id}  # Assign role to user
GET /api/rbac/permissions               # Get available permissions
GET /api/rbac/templates                 # Get role templates
```

### Compliance Reporting Endpoints
```http
POST /api/compliance/reports/{framework}  # Generate compliance report
GET /api/compliance/frameworks           # Get supported frameworks
GET /api/compliance/frameworks/{framework}/controls  # Get framework controls
```

### External Integrations Endpoints
```http
POST /api/integrations/{integration_name}/test  # Test integration
POST /api/integrations/jira/issues             # Create Jira issue
POST /api/integrations/notifications/scan      # Send scan notification
```

### Enhanced Cloud Connector Endpoints
```http
POST /api/cloud/connect/aws              # Connect to AWS
POST /api/cloud/connect/azure            # Connect to Azure
POST /api/cloud/connect/gcp              # Connect to GCP
POST /api/cloud/scan                     # Run cloud scan
```

### Enhanced AI Chat Endpoints
```http
POST /api/chat/message                   # Send chat message
GET /api/chat/history                    # Get chat history
POST /api/chat/analyze/{scan_id}        # Analyze findings with AI
POST /api/chat/remediation-plan/{scan_id}  # Generate remediation plan
```

### Enhanced Reporting Endpoints
```http
POST /api/reports/generate/{scan_id}     # Generate enhanced report
POST /api/reports/organization           # Generate organization report
POST /api/reports/export/{scan_id}      # Export scan data
```

## 🔧 Configuration

### Environment Variables

#### Core Configuration
```bash
# Database
DATABASE_URL=sqlite:///./driftbuddy.db

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key

# AI Configuration
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL=gpt-4o
```

#### External Integrations
```bash
# Jira Integration
JIRA_ENABLED=true
JIRA_API_URL=https://your-domain.atlassian.net
JIRA_API_KEY=your-jira-api-key
JIRA_USERNAME=your-jira-username
JIRA_PROJECT_KEY=SEC

# Slack Integration
SLACK_ENABLED=true
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_CHANNEL=#security-alerts

# Microsoft Teams Integration
TEAMS_ENABLED=true
TEAMS_WEBHOOK_URL=https://your-domain.webhook.office.com/webhookb2/...

# LDAP Integration
LDAP_ENABLED=true
LDAP_SERVER=ldap://your-ldap-server.com
LDAP_BASE_DN=dc=example,dc=com
LDAP_BIND_DN=cn=admin,dc=example,dc=com
LDAP_BIND_PASSWORD=your-ldap-password
```

#### Cloud Configuration
```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_DEFAULT_REGION=us-east-1

# Azure Configuration
AZURE_TENANT_ID=your-azure-tenant-id
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
AZURE_SUBSCRIPTION_ID=your-azure-subscription-id

# GCP Configuration
GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json
GCP_PROJECT_ID=your-gcp-project-id
```

## 🛡️ Security Features

### Advanced RBAC
- **Custom Roles**: Create organization-specific roles
- **Granular Permissions**: Fine-grained access control
- **Role Inheritance**: Hierarchical permission structure
- **Conditional Access**: Context-aware permissions
- **Audit Logging**: Complete access audit trail

### Authentication & Authorization
- **JWT Tokens**: Secure token-based authentication
- **Role-Based Access**: Permission-based authorization
- **Session Management**: Secure session handling
- **Password Security**: Bcrypt password hashing

### Data Protection
- **Input Validation**: Comprehensive input sanitization
- **SQL Injection Protection**: Parameterized queries
- **XSS Protection**: Cross-site scripting prevention
- **CSRF Protection**: Cross-site request forgery protection

## 📊 Compliance Frameworks

### SOC2 Type II
- **Common Criteria (CC)**: Security, availability, processing integrity
- **Trust Services Criteria**: Confidentiality and privacy
- **Control Mapping**: Automatic mapping of findings to SOC2 controls
- **Gap Analysis**: Identify missing SOC2 controls

### PCI DSS
- **Payment Card Security**: PCI DSS v4.0 compliance
- **Control Requirements**: All 12 PCI DSS requirements
- **Data Protection**: Cardholder data protection controls
- **Network Security**: Network and system security controls

### HIPAA
- **Healthcare Privacy**: HIPAA Privacy Rule compliance
- **Security Rule**: HIPAA Security Rule controls
- **Administrative Safeguards**: Administrative security measures
- **Physical Safeguards**: Physical security controls

## 🔗 External Integrations

### Jira Integration
- **Issue Creation**: Automatically create Jira issues from findings
- **Priority Mapping**: Map severity to Jira priority levels
- **Custom Fields**: Support for custom Jira fields
- **Workflow Integration**: Integrate with Jira workflows

### Slack Integration
- **Real-time Alerts**: Instant security notifications
- **Channel Management**: Multiple channel support
- **Rich Messages**: Rich formatting for security alerts
- **Interactive Components**: Interactive message components

### Microsoft Teams Integration
- **Webhook Support**: Teams webhook integration
- **Card Formatting**: Rich card message formatting
- **Channel Notifications**: Direct channel notifications
- **Action Buttons**: Interactive action buttons

## 🚀 Deployment

### Docker Deployment
```bash
# Build Phase 3 image
docker build -t driftbuddy:phase3 .

# Run with environment variables
docker run -p 8000:8000 \
  -e SECRET_KEY=your-secret-key \
  -e DATABASE_URL=sqlite:///./driftbuddy.db \
  -e OPENAI_API_KEY=your-openai-api-key \
  driftbuddy:phase3
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: driftbuddy-phase3
spec:
  replicas: 3
  selector:
    matchLabels:
      app: driftbuddy-phase3
  template:
    metadata:
      labels:
        app: driftbuddy-phase3
    spec:
      containers:
      - name: driftbuddy
        image: driftbuddy:phase3
        ports:
        - containerPort: 8000
        env:
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: driftbuddy-secrets
              key: secret-key
        - name: DATABASE_URL
          value: "postgresql://user:pass@db:5432/driftbuddy"
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: driftbuddy-secrets
              key: openai-api-key
```

## 🧪 Testing

### Run Tests
```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/test_rbac.py
pytest tests/test_compliance.py
pytest tests/test_integrations.py

# Run with coverage
pytest --cov=web --cov-report=html
```

### API Testing
```bash
# Test API endpoints
curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=admin@driftbuddy.com&password=admin123"

# Test RBAC endpoints
curl -X POST "http://localhost:8000/api/rbac/roles" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=security_analyst&description=Security analyst role&organization_id=1&permissions=[\"scan:read\",\"report:create\"]"
```

## 📈 Performance

### Optimization Features
- **Async Processing**: Non-blocking async operations
- **Connection Pooling**: Database connection optimization
- **Caching**: Redis-based caching for performance
- **Background Tasks**: Celery for background processing
- **Load Balancing**: Support for horizontal scaling

### Monitoring
- **Health Checks**: Comprehensive health monitoring
- **Metrics**: Prometheus metrics collection
- **Logging**: Structured logging with correlation IDs
- **Alerting**: Automated alerting for issues

## 🔄 Migration from Phase 2

### Database Migration
```bash
# Run database migrations
alembic upgrade head

# Verify migration
alembic current
```

### Configuration Updates
```bash
# Update environment variables
export JIRA_ENABLED=true
export SLACK_ENABLED=true
export TEAMS_ENABLED=true

# Update dependencies
pip install -r requirements-web-v3.txt
```

### Feature Enablement
```bash
# Enable Phase 3 features
export ENABLE_ADVANCED_RBAC=true
export ENABLE_COMPLIANCE_REPORTING=true
export ENABLE_EXTERNAL_INTEGRATIONS=true
```

## 🆘 Troubleshooting

### Common Issues

#### Database Connection Issues
```bash
# Check database connection
python -c "from web.database import get_db; print('Database OK')"

# Reset database
rm driftbuddy.db
python run_web_v3.py
```

#### External Integration Issues
```bash
# Test Jira connection
curl -X POST "http://localhost:8000/api/integrations/jira/test"

# Test Slack connection
curl -X POST "http://localhost:8000/api/integrations/slack/test"
```

#### RBAC Issues
```bash
# Check user permissions
curl -X GET "http://localhost:8000/api/rbac/users/1/roles" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 📚 Additional Resources

- [Phase 2 Documentation](README_PHASE2.md)
- [API Documentation](http://localhost:8000/docs)
- [Compliance Frameworks](https://www.aicpa.org/soc2)
- [External Integrations](https://api.slack.com/)
- [Cloud Connector](https://steampipe.io/)

## 🤝 Contributing

### Development Setup
```bash
# Clone repository
git clone https://github.com/your-org/driftbuddy.git
cd driftbuddy

# Install development dependencies
pip install -r requirements-web-v3.txt
pip install -r requirements-dev.txt

# Run development server
python run_web_v3.py
```

### Code Standards
- Follow PEP 8 style guidelines
- Use type hints for all functions
- Write comprehensive tests
- Update documentation for new features

### Testing Guidelines
- Write unit tests for all new features
- Include integration tests for external APIs
- Test RBAC functionality thoroughly
- Verify compliance framework mappings 