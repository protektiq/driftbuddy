#!/usr/bin/env python3
"""
Isolated test to debug the import issue
"""


def test_isolated_import():
    """Test isolated import"""
    try:
        from driftbuddy import SteampipeIntegration

        print("✅ Isolated import works")
        return True
    except Exception as e:
        print(f"❌ Isolated import failed: {e}")
        return False


if __name__ == "__main__":
    print("🧪 Testing Isolated Import")
    print("=" * 30)
    test_isolated_import()
