#!/usr/bin/env python3
"""
Setup script for DriftBuddy Web Interface
"""

import os
import subprocess
import sys
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")


def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")

    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements-web.txt"])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        sys.exit(1)


def check_kics_installation():
    """Check if KICS is installed"""
    try:
        result = subprocess.run(["kics", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ KICS is installed")
            return True
        else:
            print("⚠️ KICS is not working properly")
            return False
    except FileNotFoundError:
        print("⚠️ KICS is not installed")
        print("💡 Please install KICS from: https://kics.io/")
        return False


def create_directories():
    """Create necessary directories"""
    directories = ["uploads", "static", "logs"]

    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

    print("✅ Directories created")


def setup_environment():
    """Setup environment variables"""
    env_file = Path(".env")

    if not env_file.exists():
        env_content = """# DriftBuddy Web Interface Configuration

# Security
SECRET_KEY=your-secret-key-change-in-production

# Database
DATABASE_URL=sqlite:///./driftbuddy.db

# OpenAI (optional)
OPENAI_API_KEY=your-openai-api-key-here

# Logging
LOG_LEVEL=INFO
DEBUG=false
"""

        with open(env_file, "w") as f:
            f.write(env_content)

        print("✅ Environment file created (.env)")
        print("⚠️ Please update SECRET_KEY in .env for production use")


def run_tests():
    """Run basic tests"""
    print("🧪 Running tests...")

    try:
        subprocess.check_call([sys.executable, "-m", "pytest", "tests/test_web_interface.py", "-v"])
        print("✅ Tests passed")
    except subprocess.CalledProcessError:
        print("❌ Some tests failed")
        print("💡 You can still run the application, but some features may not work")


def main():
    """Main setup function"""
    print("🚀 Setting up DriftBuddy Web Interface...")
    print("=" * 50)

    # Check Python version
    check_python_version()

    # Install dependencies
    install_dependencies()

    # Create directories
    create_directories()

    # Setup environment
    setup_environment()

    # Check KICS installation
    kics_available = check_kics_installation()

    # Run tests
    run_tests()

    print("\n" + "=" * 50)
    print("🎉 Setup completed!")
    print("\n📋 Next steps:")
    print("1. Update .env file with your configuration")
    print("2. Run the web interface: python run_web.py")
    print("3. Access the application at: http://localhost:8000")
    print("4. Login with: admin@driftbuddy.com / admin123")

    if not kics_available:
        print("\n⚠️ KICS is not available - scanning features will not work")
        print("   Install KICS from: https://kics.io/")

    print("\n📚 Documentation: web/README.md")
    print("🔧 API Documentation: http://localhost:8000/docs")


if __name__ == "__main__":
    main()
