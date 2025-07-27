#!/usr/bin/env python3
"""
Run DriftBuddy Web Interface - Phase 2
Includes cloud connector, AI chat, WebSocket, and advanced reporting
"""

import os
import sys
from pathlib import Path

import uvicorn

# Add the src directory to Python path
sys.path.append(str(Path(__file__).parent / "src"))


def main():
    """Run the Phase 2 web interface"""
    print("🚀 Starting DriftBuddy Web Interface - Phase 2...")
    print("📋 Default admin credentials:")
    print("   Email: admin@driftbuddy.com")
    print("   Password: admin123")
    print("🌐 Web interface will be available at: http://localhost:8000")
    print("📚 API documentation: http://localhost:8000/docs")
    print("\n✨ Phase 2 Features:")
    print("   ☁️ Cloud Connector (AWS, Azure, GCP)")
    print("   🤖 AI Chat with LangChain")
    print("   🔌 Real-time WebSocket updates")
    print("   📊 Advanced Reporting & Export")

    # Set default environment variables
    os.environ.setdefault("SECRET_KEY", "your-secret-key-change-in-production")
    os.environ.setdefault("DATABASE_URL", "sqlite:///./driftbuddy.db")
    os.environ.setdefault("OPENAI_API_KEY", "your-openai-api-key-here")

    # Run the FastAPI application
    uvicorn.run("web.api_v2:app", host="0.0.0.0", port=8000, reload=True, log_level="info")


if __name__ == "__main__":
    main()
