# DriftBuddy Web Interface

A modern web interface for DriftBuddy security scanning with authentication, RBAC, and real-time scanning capabilities.

## Features

### 🔐 Authentication & RBAC
- **JWT-based authentication** with secure token management
- **Role-based access control** with three user roles:
  - **Developer**: Can create and view their own scans
  - **AppSec**: Can view all scans in organization and manage settings
  - **Admin**: Full access to all features including user management
- **Secure password hashing** with bcrypt
- **Session management** with automatic token refresh

### 📁 File Upload & KICS Integration
- **Drag-and-drop file upload** for IaC files
- **Supported file types**: `.tf`, `.yaml`, `.yml`, `.json`, `.dockerfile`, `.bicep`, `.hcl`, `.tfvars`
- **Real-time KICS scanning** with progress tracking
- **Automatic file validation** and error handling
- **Secure file storage** with cleanup capabilities

### 📊 Dashboard & Results
- **Real-time scan status** with live updates
- **Findings display** with severity and risk scoring
- **Scan history** with pagination and filtering
- **Detailed scan reports** with business impact analysis
- **Export capabilities** for reports and findings

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements-web.txt
```

### 2. Run the Web Interface
```bash
python run_web.py
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

### Scan Management
- `POST /api/scans` - Create new scan
- `GET /api/scans` - List user's scans
- `GET /api/scans/{id}` - Get scan details
- `POST /api/scans/{id}/upload` - Upload files for scanning
- `POST /api/scans/{id}/run` - Run KICS scan
- `GET /api/scans/{id}/findings` - Get scan findings
- `DELETE /api/scans/{id}` - Delete scan

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

## Security Features

### Authentication
- **JWT tokens** with configurable expiration
- **Secure password hashing** using bcrypt
- **Token-based session management**
- **Automatic token refresh**

### Authorization
- **Role-based access control** with hierarchical permissions
- **Organization-based data isolation**
- **Resource-level permission checks**
- **Admin-only endpoints** for user management

### Data Protection
- **Input validation** for all endpoints
- **SQL injection prevention** with SQLAlchemy ORM
- **File upload security** with type validation
- **Secure file storage** with cleanup

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
```

### Database Setup
The application automatically:
- Creates database tables on startup
- Creates default organization
- Creates default admin user
- Handles database migrations

## Development

### Project Structure
```
web/
├── __init__.py          # Package initialization
├── api.py              # FastAPI application and routes
├── auth.py             # Authentication and authorization
├── database.py         # Database connection and models
├── models.py           # SQLAlchemy models and Pydantic schemas
├── services.py         # Business logic and KICS integration
└── main.py            # Application entry point

static/
└── index.html         # Web interface frontend
```

### Adding New Features
1. **Models**: Add new SQLAlchemy models in `models.py`
2. **Services**: Add business logic in `services.py`
3. **API**: Add endpoints in `api.py`
4. **Frontend**: Update `static/index.html` for UI changes

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
