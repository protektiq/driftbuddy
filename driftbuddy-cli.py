#!/usr/bin/env python3
"""
DriftBuddy - Infrastructure Configuration Analysis Tool
Main entry point script
"""

import sys
from pathlib import Path

if __name__ == "__main__":
    try:
        # Try importing from installed package first
        from driftbuddy.core import main

        main()
    except ImportError:
        # Fallback for development - add src directory to Python path
        src_dir = Path(__file__).parent / "src"
        sys.path.insert(0, str(src_dir))
        from src.driftbuddy.core import main

        main()
