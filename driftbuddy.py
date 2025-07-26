#!/usr/bin/env python3
"""
DriftBuddy - Infrastructure Configuration Analysis Tool
Main entry point script
"""

import sys
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

if __name__ == "__main__":
    from driftbuddy.core import main
    main() 