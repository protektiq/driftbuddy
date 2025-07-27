# DriftBuddy Project Structure

This document describes the professional directory structure of DriftBuddy and how the codebase is organized.

## Directory Overview

```
driftbuddy/
├── README.md                    # Main project documentation
├── requirements.txt             # Python dependencies
├── requirements-minimal.txt     # Minimal dependencies
├── driftbuddy.py               # Main entry point script
├── .gitignore                  # Git ignore rules
│
├── src/                        # Source code
│   ├── __init__.py
│   ├── driftbuddy/             # Main package
│   │   ├── __init__.py         # Package exports
│   │   ├── core.py             # Core functionality (main logic)
│   │   ├── steampipe_integration.py  # Cloud infrastructure querying
│   │   └── kics_explainer.py   # KICS results explanation
│   └── agent/                  # AI agent for explanations
│       └── explainer.py        # AI-powered explanations
│
├── tests/                      # Test files
│   ├── __init__.py
│   ├── test_steampipe_integration.py
│   ├── test_timestamped_files.py
│   └── test_kics_fix.py
│
├── docs/                       # Documentation
│   ├── PROJECT_STRUCTURE.md    # This file
│   ├── STEAMPIPE_SETUP.md      # Steampipe setup guide
│   └── GITHUB_ACTIONS_SETUP.md # CI/CD setup guide
│
├── outputs/                    # Generated outputs
│   ├── reports/                # HTML/MD security reports
│   └── analysis/               # Analysis outputs and explanations
│
├── examples/                   # Example usage scripts
│   ├── steampipe_example.py    # Steampipe integration examples
│   └── github-actions-example.yml
│
├── scripts/                    # Utility scripts
│   ├── run_kics.sh            # KICS execution script
│   └── setup-github-actions.sh
│
├── test_data/                  # Test data and samples
│   ├── iac_example/           # Sample IaC files
│   └── output/                # Test scan results
│
├── kics/                       # KICS security scanner (submodule)
│
└── .github/                    # GitHub workflows and configs
```

## Key Components

### Main Entry Point
- `driftbuddy.py`: Simple entry point that loads the main functionality from `src/driftbuddy/core.py`

### Source Code (`src/`)
- **`driftbuddy/core.py`**: Main application logic, CLI interface, and scan orchestration
- **`driftbuddy/steampipe_integration.py`**: Cloud infrastructure querying and drift detection
- **`driftbuddy/kics_explainer.py`**: AI-powered explanation of KICS security findings
- **`agent/explainer.py`**: AI agent for generating detailed security explanations

### Tests (`tests/`)
All test files are organized in a dedicated test directory with proper imports.

### Documentation (`docs/`)
- Setup guides for different integrations
- Project structure documentation
- Configuration examples

### Outputs (`outputs/`)
- **`reports/`**: Generated HTML dashboards and markdown reports
- **`analysis/`**: KICS explanations and drift analysis results

## Usage

### Running DriftBuddy
```bash
# Using the main entry point
python driftbuddy.py --help

# Or directly importing
python -c "from src.driftbuddy.core import main; main()"
```

### Running Tests
```bash
# Run individual tests
python tests/test_steampipe_integration.py
python tests/test_timestamped_files.py
```

### Imports in Your Code
```python
# Import main functionality
from src.driftbuddy import generate_timestamped_filename, SteampipeIntegration

# Import specific modules
from src.driftbuddy.core import run_kics_scan
from src.driftbuddy.steampipe_integration import SteampipeIntegration
```

## Benefits of This Structure

1. **Clean Separation**: Source code, tests, docs, and outputs are clearly separated
2. **Professional Layout**: Follows Python packaging best practices
3. **Scalable**: Easy to add new modules and maintain as the project grows
4. **Import Safety**: Proper package structure prevents import conflicts
5. **Clear Organization**: Easy to find files and understand project layout
6. **Output Management**: Generated files are kept organized and separate from source

## Migration Notes

This structure was created by reorganizing the original flat file structure:
- Main Python files moved to `src/driftbuddy/`
- Test files consolidated in `tests/`
- Documentation moved to `docs/`
- Generated outputs moved to `outputs/`
- Import statements updated throughout the codebase
- Default paths updated to use the new structure
