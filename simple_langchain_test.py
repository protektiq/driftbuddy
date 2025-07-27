#!/usr/bin/env python3
"""
Simple test to debug LangChain integration
"""

import sys
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))


def test_imports():
    """Test basic imports"""
    try:
        print("Testing imports...")

        # Test basic imports
        from typing import Optional

        print("✅ Optional import successful")

        # Test LangChain imports
        from langchain_openai import ChatOpenAI

        print("✅ LangChain OpenAI import successful")

        from langchain_core.prompts import ChatPromptTemplate

        print("✅ LangChain prompts import successful")

        from langchain.memory import ConversationBufferMemory

        print("✅ LangChain memory import successful")

        # Test DriftBuddy imports
        from driftbuddy.config import get_config

        print("✅ DriftBuddy config import successful")

        from driftbuddy.langchain_integration import DriftBuddyLangChain

        print("✅ DriftBuddy LangChain integration import successful")

        return True

    except Exception as e:
        print(f"❌ Import error: {e}")
        return False


def test_basic_langchain():
    """Test basic LangChain functionality"""
    try:
        print("\nTesting basic LangChain functionality...")

        # Import DriftBuddyLangChain locally
        from driftbuddy.langchain_integration import DriftBuddyLangChain

        # Initialize LangChain integration
        langchain = DriftBuddyLangChain()
        print("✅ LangChain integration initialized")

        # Test simple analysis
        sample_finding = {
            "query_name": "Test Security Issue",
            "severity": "HIGH",
            "description": "Test security finding for demonstration",
            "files": [{"file_name": "test.tf", "line": 10}],
        }

        result = langchain.analyze_with_context(sample_finding)
        print("✅ Analysis completed successfully")

        return True

    except Exception as e:
        print(f"❌ LangChain functionality error: {e}")
        return False


def main():
    """Main test function"""
    print("🔍 Simple LangChain Integration Test")
    print("=" * 40)

    # Test imports
    imports_ok = test_imports()

    if imports_ok:
        # Test functionality
        functionality_ok = test_basic_langchain()

        if functionality_ok:
            print("\n🎉 All tests passed!")
        else:
            print("\n❌ Functionality tests failed")
    else:
        print("\n❌ Import tests failed")


if __name__ == "__main__":
    main()
