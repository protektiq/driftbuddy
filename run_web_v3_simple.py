#!/usr/bin/env python3
"""
Run DriftBuddy Web Interface - Phase 3 (Simplified)
Core features without problematic dependencies like LDAP
"""

import os
import sys
from pathlib import Path

import uvicorn

# Add the src directory to Python path
sys.path.append(str(Path(__file__).parent / "src"))


def main():
    """Run the simplified Phase 3 web interface"""
    print("🚀 Starting DriftBuddy Web Interface - Phase 3 (Simplified)...")
    print("📋 Default admin credentials:")
    print("   Email: admin@driftbuddy.com")
    print("   Password: admin123")
    print("🌐 Web interface will be available at: http://localhost:8000")
    print("📚 API documentation: http://localhost:8000/docs")
    print("\n✨ Simplified Phase 3 Features:")
    print("   👥 Basic RBAC with permissions")
    print("   📋 Compliance framework support (SOC2, PCI, HIPAA)")
    print("   🔗 Simulated external integrations (Jira, Slack, Teams)")
    print("   ☁️ Simulated cloud connector (AWS, Azure, GCP)")
    print("   🤖 Simplified AI chat with simulated responses")
    print("   📊 Basic reporting capabilities")

    # Set default environment variables
    os.environ.setdefault("SECRET_KEY", "your-secret-key-change-in-production")
    os.environ.setdefault("DATABASE_URL", "sqlite:///./driftbuddy.db")
    os.environ.setdefault("OPENAI_API_KEY", "your-openai-api-key-here")

    # Run the FastAPI application
    uvicorn.run("web.api_v3_simple:app", host="0.0.0.0", port=8000, reload=True, log_level="info")


if __name__ == "__main__":
    main() 