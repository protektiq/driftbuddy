#!/usr/bin/env python3
"""
Run DriftBuddy Web Interface - Phase 3
Includes advanced RBAC, compliance reporting, external integrations, and enhanced features
"""

import os
import sys
from pathlib import Path

import uvicorn

# Add the src directory to Python path
sys.path.append(str(Path(__file__).parent / "src"))


def main():
    """Run the Phase 3 web interface"""
    print("🚀 Starting DriftBuddy Web Interface - Phase 3...")
    print("📋 Default admin credentials:")
    print("   Email: admin@driftbuddy.com")
    print("   Password: admin123")
    print("🌐 Web interface will be available at: http://localhost:8000")
    print("📚 API documentation: http://localhost:8000/docs")
    print("\n✨ Phase 3 Features:")
    print("   👥 Advanced RBAC with Custom Roles & Permissions")
    print("   📋 Compliance Reporting (SOC2, PCI, HIPAA)")
    print("   🔗 External Integrations (Jira, Slack, Teams)")
    print("   ☁️ Enhanced Cloud Connector with Steampipe")
    print("   🤖 AI-Powered Analysis with LangChain")
    print("   🔌 Real-time WebSocket Updates")
    print("   📊 Comprehensive Reporting & Export")
    print("   🛡️ Enterprise Security Features")

    # Set default environment variables
    os.environ.setdefault("SECRET_KEY", "your-secret-key-change-in-production")
    os.environ.setdefault("DATABASE_URL", "sqlite:///./driftbuddy.db")
    os.environ.setdefault("OPENAI_API_KEY", "your-openai-api-key-here")
    
    # Phase 3 specific environment variables
    os.environ.setdefault("JIRA_ENABLED", "false")
    os.environ.setdefault("SLACK_ENABLED", "false")
    os.environ.setdefault("TEAMS_ENABLED", "false")
    os.environ.setdefault("LDAP_ENABLED", "false")
    os.environ.setdefault("SAML_ENABLED", "false")
    os.environ.setdefault("OAUTH_ENABLED", "false")

    # Run the FastAPI application
    uvicorn.run("web.api_v3:app", host="0.0.0.0", port=8000, reload=True, log_level="info")


if __name__ == "__main__":
    main() 