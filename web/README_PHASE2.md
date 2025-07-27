# DriftBuddy Web Interface - Phase 2

Advanced web interface for DriftBuddy with cloud integration, AI-powered analysis, real-time updates, and comprehensive reporting.

## 🚀 Phase 2 Features

### ☁️ Cloud Connector Integration
- **AWS Integration**: Connect and scan AWS infrastructure using access keys
- **Azure Integration**: Connect and scan Azure resources using service principals
- **GCP Integration**: Connect and scan GCP projects using service accounts
- **Steampipe Integration**: Leverage Steampipe for cloud security queries
- **Real-time Cloud Scanning**: Monitor cloud infrastructure for security misconfigurations

### 🤖 AI Chat with LangChain
- **Intelligent Security Analysis**: AI-powered analysis of scan findings
- **Context-Aware Responses**: AI responses based on user role and scan context
- **Remediation Planning**: Generate comprehensive remediation plans
- **Chat History**: Persistent chat history with metadata
- **Fallback Responses**: Rule-based responses when AI is unavailable

### 🔌 Real-time WebSocket Updates
- **Live Scan Progress**: Real-time updates during scan execution
- **Instant Notifications**: Immediate notifications for scan completion
- **Finding Updates**: Real-time finding discovery and updates
- **Chat Integration**: Real-time AI chat responses
- **Multi-user Support**: Concurrent user connections

### 📊 Advanced Reporting & Export
- **Multiple Formats**: HTML, JSON, CSV, PDF (planned)
- **Organization Reports**: Organization-wide security reports
- **Custom Templates**: Jinja2-based report templates
- **Data Export**: Export scan data in various formats
- **Statistical Analysis**: Comprehensive security metrics

## 🏗️ Architecture

### Core Components
```
web/
├── api_v2.py              # Phase 2 FastAPI application
├── cloud_connector.py     # Cloud integration service
├── ai_chat.py            # AI chat with LangChain
├── websocket.py          # Real-time WebSocket manager
├── reporting.py          # Advanced reporting service
├── services.py           # Enhanced business logic
├── auth.py              # Authentication & RBAC
├── models.py            # Database models
└── database.py          # Database management
```

### Service Integration
- **Cloud Connector**: Integrates with AWS, Azure, GCP via Steampipe
- **AI Chat Service**: LangChain integration for intelligent analysis
- **WebSocket Service**: Real-time communication and updates
- **Reporting Service**: Comprehensive reporting and export capabilities

## 🚀 Quick Start

### 1. Install Phase 2 Dependencies
```bash
pip install -r requirements-web-v2.txt
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
```

### 3. Run Phase 2 Web Interface
```bash
python run_web_v2.py
```

### 4. Access the Application
- **Web Interface**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs
- **Default Admin**: admin@driftbuddy.com / admin123

## 📋 API Endpoints

### Cloud Connector Endpoints
```http
POST /api/cloud/connect/aws
POST /api/cloud/connect/azure
POST /api/cloud/connect/gcp
POST /api/cloud/scan
```

### AI Chat Endpoints
```http
POST /api/chat/message
GET /api/chat/history
POST /api/chat/analyze/{scan_id}
POST /api/chat/remediation-plan/{scan_id}
```

### WebSocket Endpoints
```http
WS /ws/{user_id}
WS /ws/scan/{scan_id}
```

### Advanced Reporting Endpoints
```http
POST /api/reports/generate/{scan_id}
POST /api/reports/organization
POST /api/reports/export/{scan_id}
```

## ☁️ Cloud Integration

### AWS Connection
```bash
curl -X POST "http://localhost:8000/api/cloud/connect/aws" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "access_key=YOUR_ACCESS_KEY" \
  -F "secret_key=YOUR_SECRET_KEY" \
  -F "region=us-east-1"
```

### Azure Connection
```bash
curl -X POST "http://localhost:8000/api/cloud/connect/azure" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "tenant_id=YOUR_TENANT_ID" \
  -F "client_id=YOUR_CLIENT_ID" \
  -F "client_secret=YOUR_CLIENT_SECRET" \
  -F "subscription_id=YOUR_SUBSCRIPTION_ID"
```

### GCP Connection
```bash
curl -X POST "http://localhost:8000/api/cloud/connect/gcp" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "project_id=YOUR_PROJECT_ID" \
  -F "service_account_key=YOUR_SERVICE_ACCOUNT_KEY"
```

## 🤖 AI Chat Features

### Send Chat Message
```bash
curl -X POST "http://localhost:8000/api/chat/message" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Analyze the security findings in my latest scan",
    "scan_id": 123
  }'
```

### Analyze Findings with AI
```bash
curl -X POST "http://localhost:8000/api/chat/analyze/123" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Generate Remediation Plan
```bash
curl -X POST "http://localhost:8000/api/chat/remediation-plan/123" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🔌 WebSocket Integration

### JavaScript WebSocket Client
```javascript
// Connect to user-specific WebSocket
const ws = new WebSocket('ws://localhost:8000/ws/123');

// Connect to scan-specific WebSocket
const scanWs = new WebSocket('ws://localhost:8000/ws/scan/456');

// Handle messages
ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'scan_progress':
            console.log('Scan progress:', data.progress);
            break;
        case 'scan_complete':
            console.log('Scan completed:', data.findings_count);
            break;
        case 'chat_response':
            console.log('AI response:', data.content);
            break;
        case 'notification':
            console.log('Notification:', data.message);
            break;
    }
};

// Send chat message
ws.send(JSON.stringify({
    type: 'chat_message',
    content: 'Help me understand these security findings',
    scan_id: 123
}));
```

## 📊 Reporting Features

### Generate HTML Report
```bash
curl -X POST "http://localhost:8000/api/reports/generate/123?format=html" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Generate JSON Report
```bash
curl -X POST "http://localhost:8000/api/reports/generate/123?format=json" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Export Scan Data
```bash
curl -X POST "http://localhost:8000/api/reports/export/123?format=csv" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Organization Report
```bash
curl -X POST "http://localhost:8000/api/reports/organization" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "date_range": {
      "start": "2024-01-01T00:00:00",
      "end": "2024-12-31T23:59:59"
    }
  }'
```

## 🔧 Configuration

### Environment Variables
```bash
# Security
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=sqlite:///./driftbuddy.db

# AI Integration
OPENAI_API_KEY=your-openai-api-key
OPENAI_MODEL=gpt-4o

# Cloud Integration
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AZURE_TENANT_ID=your-azure-tenant-id
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-client-secret
GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

# Logging
LOG_LEVEL=INFO
DEBUG=false
```

### Database Schema Updates
Phase 2 includes additional tables for:
- **Chat History**: Store AI chat interactions
- **Cloud Connections**: Store cloud provider configurations
- **Report Templates**: Store custom report templates

## 🧪 Testing

### Run Phase 2 Tests
```bash
# Install test dependencies
pip install -r requirements-web-v2.txt

# Run tests
pytest tests/test_web_interface_v2.py -v

# Test specific features
pytest tests/test_cloud_connector.py -v
pytest tests/test_ai_chat.py -v
pytest tests/test_websocket.py -v
pytest tests/test_reporting.py -v
```

### Test Cloud Integration
```bash
# Test AWS connection (requires valid credentials)
python -m pytest tests/test_cloud_connector.py::test_aws_connection -v

# Test Azure connection
python -m pytest tests/test_cloud_connector.py::test_azure_connection -v

# Test GCP connection
python -m pytest tests/test_cloud_connector.py::test_gcp_connection -v
```

## 🚀 Deployment

### Production Setup
1. **Set secure environment variables**
2. **Use production database** (PostgreSQL recommended)
3. **Configure cloud credentials** securely
4. **Set up SSL certificates**
5. **Configure monitoring and logging**

### Docker Deployment
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements-web-v2.txt .
RUN pip install -r requirements-web-v2.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "run_web_v2.py"]
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: driftbuddy-web-v2
spec:
  replicas: 3
  selector:
    matchLabels:
      app: driftbuddy-web-v2
  template:
    metadata:
      labels:
        app: driftbuddy-web-v2
    spec:
      containers:
      - name: driftbuddy-web
        image: driftbuddy/web-v2:latest
        ports:
        - containerPort: 8000
        env:
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: driftbuddy-secrets
              key: secret-key
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: driftbuddy-secrets
              key: database-url
```

## 🔒 Security Considerations

### Authentication & Authorization
- **JWT-based authentication** with secure token management
- **Role-based access control** with hierarchical permissions
- **Cloud credential encryption** and secure storage
- **API rate limiting** and request validation

### Data Protection
- **Input validation** for all endpoints
- **SQL injection prevention** with SQLAlchemy ORM
- **Secure file handling** with type validation
- **Audit logging** for all operations

### Cloud Security
- **Credential rotation** for cloud accounts
- **Least privilege access** for cloud resources
- **Secure credential storage** using environment variables
- **Connection validation** before scanning

## 📈 Performance Optimization

### Database Optimization
- **Connection pooling** for database connections
- **Query optimization** with proper indexing
- **Caching layer** for frequently accessed data
- **Background task processing** for long-running operations

### WebSocket Optimization
- **Connection pooling** for WebSocket connections
- **Message queuing** for high-volume scenarios
- **Graceful degradation** when WebSocket is unavailable
- **Connection monitoring** and cleanup

### AI Integration Optimization
- **Response caching** for common queries
- **Async processing** for AI operations
- **Fallback mechanisms** when AI is unavailable
- **Token usage monitoring** and optimization

## 🔮 Future Enhancements

### Phase 3 Features (Planned)
- **SSO Integration**: SAML, OAuth, LDAP support
- **Advanced RBAC**: Custom roles and permissions
- **Compliance Reporting**: SOC2, PCI, HIPAA reports
- **Integration APIs**: Jira, Slack, Teams integration
- **Advanced Analytics**: Machine learning insights
- **Container Security**: Docker and Kubernetes scanning

### Enterprise Features
- **Multi-tenancy**: Advanced organization management
- **Audit Trail**: Comprehensive activity logging
- **API Rate Limiting**: Advanced throttling
- **Custom Dashboards**: User-defined dashboards
- **Advanced Notifications**: Email, SMS, webhook alerts

## 🤝 Contributing

### Development Setup
1. **Fork the repository**
2. **Create feature branch**
3. **Install development dependencies**
4. **Run tests and linting**
5. **Submit pull request**

### Code Standards
- **Type hints** for all functions
- **Docstrings** for all classes and methods
- **Unit tests** for all new features
- **Integration tests** for API endpoints
- **Performance tests** for critical paths

## 📄 License

Same as DriftBuddy main project.

---

**Phase 2** represents a significant advancement in DriftBuddy's capabilities, providing enterprise-grade features for cloud security analysis, AI-powered insights, and comprehensive reporting. The modular architecture ensures scalability and maintainability for future enhancements. 
