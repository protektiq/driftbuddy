"""
DriftBuddy core package
"""

__version__ = "1.0.0"


# Lazy imports to avoid circular dependencies
def _import_core_functions():
    """Lazy import of core functions"""
    from .core import (
        check_kics_installation,
        generate_timestamped_filename,
        main,
        run_kics,
    )

    return check_kics_installation, generate_timestamped_filename, main, run_kics


# Import Steampipe integration if available
try:
    from .steampipe_integration import SteampipeIntegration

    STEAMPIPE_AVAILABLE = True
except ImportError:
    STEAMPIPE_AVAILABLE = False

__all__ = [
    "generate_timestamped_filename",
    "check_kics_installation",
    "run_kics",
    "main",
    "SteampipeIntegration",
    "STEAMPIPE_AVAILABLE",
]

# Make SteampipeIntegration available at the top level if it exists
if STEAMPIPE_AVAILABLE:
    globals()["SteampipeIntegration"] = SteampipeIntegration
