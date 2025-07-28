# DriftBuddy Project Structure

This document describes the current structure of the DriftBuddy project after cleanup and optimization.

## Overview

DriftBuddy is organized into several key components:

1. **Core CLI Application** (`src/driftbuddy/`) - Main security scanning functionality
2. **Web Interface** (`web/`) - Modern React-based web application
3. **Scripts** (`scripts/`) - Utility and setup scripts
4. **Tests** (`tests/`) - Test suite
5. **Documentation** (`docs/`) - Project documentation
6. **Assets** (`assets/`) - KICS queries and resources
7. **Examples** (`examples/`) - Usage examples

## Directory Structure

```
driftbuddy/
├── src/driftbuddy/                    # Core application
│   ├── __init__.py                    # Package initialization
│   ├── core.py                        # Main CLI application logic
│   ├── config.py                      # Configuration management
│   ├── risk_assessment.py             # Business risk assessment
│   ├── exceptions.py                  # Error handling
│   ├── kics_integration.py            # KICS scanning integration
│   ├── steampipe_integration.py       # Cloud scanning integration
│   ├── langchain_integration.py       # AI integration
│   ├── kics_explainer.py              # KICS result explanation
│   └── agent/                         # AI agents
│       ├── __init__.py
│       ├── explainer.py               # AI explanation agent
│       └── enhanced_agent.py          # Enhanced AI agent
├── web/                               # Web interface
│   ├── __init__.py                    # Package initialization
│   ├── api_v3_simple.py              # FastAPI application (main)
│   ├── models.py                      # Database models
│   ├── auth.py                        # Authentication
│   ├── database.py                    # Database connection
│   ├── services.py                    # Business logic
│   ├── rbac_api.py                    # RBAC endpoints
│   ├── compliance_api.py              # Compliance endpoints
│   ├── ml_analytics_api.py            # ML analytics endpoints
│   ├── integrations_api.py            # External integrations
│   ├── cloud_connector.py             # Cloud provider integrations
│   ├── ai_chat.py                     # AI chat functionality
│   ├── reporting.py                   # Report generation
│   ├── websocket.py                   # WebSocket handling
│   ├── sso_integration.py             # SSO integration
│   ├── compliance_reporting.py        # Compliance reporting
│   ├── advanced_rbac.py               # Advanced RBAC
│   ├── integration_apis.py            # Integration APIs
│   ├── migrate_integrations.py        # Migration utilities
│   ├── main.py                        # Entry point
│   ├── README.md                      # Web interface documentation
│   └── frontend/                      # React frontend
│       ├── package.json
│       ├── public/
│       └── src/
├── scripts/                           # Utility scripts
│   ├── setup_api_key.py              # API key setup
│   ├── security_scan.py               # Security checks
│   ├── test_performance.py            # Performance testing
│   ├── fix_all_issues.py             # Issue fixing
│   ├── fix_permissions.py             # Permission fixing
│   ├── fix_windows.py                 # Windows-specific fixes
│   ├── setup-github-actions.sh        # GitHub Actions setup
│   ├── test_ci.py                     # CI testing
│   ├── check_version.py               # Version checking
│   └── run_kics.sh                    # KICS runner
├── tests/                             # Test suite
│   ├── __init__.py
│   ├── test_phase3_features.py        # Phase 3 feature tests
│   ├── test_web_interface.py          # Web interface tests
│   ├── test_steampipe_simple.py       # Steampipe tests
│   ├── test_risk_assessment.py        # Risk assessment tests
│   ├── test_kics_fix.py               # KICS fix tests
│   └── test_timestamped_files.py      # File naming tests
├── docs/                              # Documentation
│   ├── PERFORMANCE_OPTIMIZATION.md    # Performance guide
│   ├── GITHUB_ACTIONS_SETUP.md        # CI/CD setup
│   ├── ENTERPRISE_READINESS.md        # Enterprise features
│   ├── PROJECT_STRUCTURE.md           # This file
│   └── STEAMPIPE_SETUP.md             # Steampipe setup
├── assets/                            # KICS queries and resources
│   └── queries/                       # KICS query definitions
│       ├── ansible/                   # Ansible queries
│       ├── azureResourceManager/      # Azure queries
│       ├── buildah/                   # Buildah queries
│       ├── cicd/                      # CI/CD queries
│       ├── cloudFormation/            # CloudFormation queries
│       ├── common/                    # Common queries
│       ├── crossplane/                # Crossplane queries
│       ├── dockerCompose/             # Docker Compose queries
│       ├── dockerfile/                # Dockerfile queries
│       ├── googleDeploymentManager/   # GCP queries
│       ├── grpc/                      # gRPC queries
│       ├── k8s/                       # Kubernetes queries
│       ├── knative/                   # Knative queries
│       ├── openAPI/                   # OpenAPI queries
│       ├── pulumi/                    # Pulumi queries
│       ├── serverlessFW/              # Serverless queries
│       └── terraform/                 # Terraform queries
├── examples/                          # Usage examples
│   ├── steampipe_example.py           # Steampipe usage
│   └── github-actions-example.yml     # GitHub Actions example
├── test_data/                         # Test infrastructure
│   ├── iac_example/                   # Sample IaC files
│   └── output/                        # Test outputs
├── outputs/                           # Generated reports
│   ├── reports/                       # Scan reports
│   └── analysis/                      # Analysis results
├── static/                            # Static web assets
│   └── index.html                     # Main web page
├── uploads/                           # File uploads for web interface
├── aws/                               # AWS-specific resources
│   ├── install                        # AWS installation script
│   ├── README.md                      # AWS documentation
│   └── THIRD_PARTY_LICENSES          # Third-party licenses
├── .github/                           # GitHub configuration
│   └── workflows/                     # GitHub Actions workflows
├── .venv/                             # Virtual environment (gitignored)
├── .mypy_cache/                       # MyPy cache (gitignored)
├── driftbuddy.db                      # SQLite database
├── driftbuddy-cli.py                  # Main CLI entry point
├── run_web_v3.py                      # Web interface runner
├── requirements.txt                    # Main dependencies
├── requirements-web-v3.txt             # Web interface dependencies
├── requirements-dev.txt                # Development dependencies
├── requirements-minimal.txt            # Minimal dependencies
├── pyproject.toml                     # Project configuration
├── setup.py                           # Package setup
├── Dockerfile                         # Docker configuration
├── docker-compose.yml                 # Docker Compose configuration
├── Makefile                           # Build automation
├── README.md                          # Main documentation
├── CONTRIBUTING.md                    # Contributing guide
├── LICENSE                            # License file
├── CHANGELOG.md                       # Version history
├── env.example                        # Environment variables example
├── .gitignore                         # Git ignore rules
├── .flake8                            # Flake8 configuration
├── .bandit                            # Bandit security configuration
├── .pre-commit-config.yaml            # Pre-commit hooks
└── .venv/                             # Virtual environment
```

## Key Components

### Core Application (`src/driftbuddy/`)

The core application provides the main CLI functionality:

- **`core.py`**: Main application logic with CLI interface
- **`config.py`**: Configuration management and environment variables
- **`risk_assessment.py`**: Business risk assessment using Impact × Likelihood methodology
- **`exceptions.py`**: Error handling and custom exceptions
- **`kics_integration.py`**: KICS scanning integration
- **`steampipe_integration.py`**: Cloud scanning with Steampipe
- **`langchain_integration.py`**: AI integration with LangChain
- **`agent/`**: AI agents for enhanced analysis

### Web Interface (`web/`)

The web interface provides a modern React-based UI:

- **`api_v3_simple.py`**: Main FastAPI application with all endpoints
- **`models.py`**: SQLAlchemy models and Pydantic schemas
- **`auth.py`**: JWT-based authentication
- **`database.py`**: Database connection and initialization
- **`services.py`**: Business logic and KICS integration
- **`rbac_api.py`**: Role-based access control endpoints
- **`compliance_api.py`**: Compliance reporting endpoints
- **`integrations_api.py`**: External integrations (Jira, Slack, Teams)
- **`cloud_connector.py`**: Cloud provider integrations
- **`ai_chat.py`**: AI-powered chat functionality
- **`frontend/`**: React-based frontend application

### Scripts (`scripts/`)

Utility scripts for setup and maintenance:

- **`setup_api_key.py`**: Interactive API key setup
- **`security_scan.py`**: Security checks for the codebase
- **`test_performance.py`**: Performance testing
- **`fix_all_issues.py`**: Automated issue fixing
- **`check_version.py`**: Version consistency checking

### Tests (`tests/`)

Comprehensive test suite:

- **`test_phase3_features.py`**: Tests for Phase 3 features
- **`test_web_interface.py`**: Web interface tests
- **`test_steampipe_simple.py`**: Steampipe integration tests
- **`test_risk_assessment.py`**: Risk assessment tests

### Assets (`assets/`)

KICS queries and resources:

- **`queries/`**: KICS query definitions for various platforms
- Organized by platform (Terraform, Kubernetes, Docker, etc.)

## Entry Points

### CLI Application
```bash
# Main CLI entry point
python driftbuddy-cli.py --scan-path ./terraform --enable-ai
```

### Web Interface
```bash
# Web interface runner
python run_web_v3.py
```

### Docker
```bash
# Docker deployment
docker-compose up
```

## Configuration Files

- **`requirements.txt`**: Main Python dependencies
- **`requirements-web-v3.txt`**: Web interface dependencies
- **`requirements-dev.txt`**: Development dependencies
- **`pyproject.toml`**: Project metadata and build configuration
- **`setup.py`**: Package installation configuration
- **`.env`**: Environment variables (create from `env.example`)

## Development Workflow

1. **Setup**: Install dependencies with `pip install -r requirements.txt`
2. **Development**: Use `requirements-dev.txt` for development tools
3. **Testing**: Run tests with `pytest tests/`
4. **Linting**: Use pre-commit hooks for code quality
5. **Documentation**: Update docs in `docs/` directory

## Cleanup Summary

The project has been cleaned up by removing:

- **Redundant files**: Multiple web interface versions, test files in root
- **Unused documentation**: Phase-specific README files
- **Large binaries**: AWS CLI zip file (64MB)
- **Empty directories**: fuzz/, drift/, secrets/, .codesight/
- **Duplicate requirements**: Multiple requirements files consolidated
- **Test files**: Demo and test files moved to appropriate locations

The current structure is optimized for:
- **Maintainability**: Clear separation of concerns
- **Scalability**: Modular architecture
- **Usability**: Simple entry points and clear documentation
- **Performance**: Optimized dependencies and structure
