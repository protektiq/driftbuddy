"""
DriftBuddy core package
"""

from .core import (
    generate_timestamped_filename,
    check_kics_installation,
    run_kics,
    main
)

__all__ = [
    'generate_timestamped_filename',
    'check_kics_installation', 
    'run_kics',
    'main'
] 