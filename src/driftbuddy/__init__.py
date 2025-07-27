"""
DriftBuddy core package
"""

__version__ = "1.0.0"

from .core import check_kics_installation, generate_timestamped_filename, main, run_kics

__all__ = [
    "generate_timestamped_filename",
    "check_kics_installation",
    "run_kics",
    "main",
]
