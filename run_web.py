#!/usr/bin/env python3
"""
Run DriftBuddy Web Interface
"""

import os
import sys
from pathlib import Path

import uvicorn

# Add the src directory to Python path
sys.path.append(str(Path(__file__).parent / "src"))


def main():
    """Run the web interface"""
    print("🚀 Starting DriftBuddy Web Interface...")
    print("📋 Default admin credentials:")
    print("   Email: admin@driftbuddy.com")
    print("   Password: admin123")
    print("🌐 Web interface will be available at: http://localhost:8000")
    print("📚 API documentation: http://localhost:8000/docs")

    # Set default environment variables
    os.environ.setdefault("SECRET_KEY", "your-secret-key-change-in-production")
    os.environ.setdefault("DATABASE_URL", "sqlite:///./driftbuddy.db")

    # Run the FastAPI application
    uvicorn.run("web.api:app", host="0.0.0.0", port=8000, reload=True, log_level="info")


if __name__ == "__main__":
    main()
