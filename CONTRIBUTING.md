# Contributing to DriftBuddy

Thank you for your interest in contributing to DriftBuddy! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Code of Conduct

This project and its participants are governed by our Code of Conduct. By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Docker (for KICS integration)
- Steampipe (optional, for cloud scanning)

### Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/your-username/driftbuddy.git
   cd driftbuddy
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## Development Setup

### Environment Variables

Create a `.env` file in the root directory:

```bash
# OpenAI API for AI explanations
OPENAI_API_KEY=your_openai_api_key

# Logging configuration
LOG_LEVEL=INFO
LOG_FORMAT=json

# Development settings
DEBUG=false
```

### Running the Application

```bash
# Run with development settings
python driftbuddy.py --help

# Run tests
pytest

# Run linting
black src/ tests/
flake8 src/ tests/
mypy src/
```

## Code Style

We follow these coding standards:

### Python Style Guide

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints for all function parameters and return values
- Maximum line length: 88 characters (Black default)
- Use descriptive variable and function names

### Code Formatting

We use [Black](https://black.readthedocs.io/) for code formatting:

```bash
black src/ tests/
```

### Import Sorting

We use [isort](https://pycqa.github.io/isort/) for import sorting:

```bash
isort src/ tests/
```

### Type Checking

We use [mypy](http://mypy-lang.org/) for static type checking:

```bash
mypy src/
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/driftbuddy

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m "not slow"
```

### Writing Tests

- Write tests for all new functionality
- Use descriptive test names
- Follow the AAA pattern (Arrange, Act, Assert)
- Mock external dependencies
- Use fixtures for common setup

Example test structure:

```python
import pytest
from unittest.mock import Mock, patch

def test_function_name():
    """Test description."""
    # Arrange
    mock_dependency = Mock()

    # Act
    result = function_under_test(mock_dependency)

    # Assert
    assert result == expected_value
```

## Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the code style guidelines
   - Add tests for new functionality
   - Update documentation as needed

3. **Run quality checks**
   ```bash
   # Format code
   black src/ tests/
   isort src/ tests/

   # Run linting
   flake8 src/ tests/
   mypy src/

   # Run tests
   pytest
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

5. **Push and create a pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

### Pull Request Checklist

- [ ] Code follows style guidelines
- [ ] Tests pass
- [ ] Documentation is updated
- [ ] Changelog is updated
- [ ] No security vulnerabilities introduced
- [ ] Performance impact considered

## Release Process

### Version Management

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Steps

1. **Update version in pyproject.toml**
2. **Update CHANGELOG.md**
3. **Create release branch**
4. **Run full test suite**
5. **Create GitHub release**
6. **Deploy to PyPI**

## Security

### Reporting Security Issues

Please report security issues to security@driftbuddy.dev rather than creating a public issue.

### Security Guidelines

- Never commit secrets or API keys
- Use environment variables for sensitive data
- Validate all user inputs
- Follow the principle of least privilege
- Keep dependencies updated

## Getting Help

- **Issues**: Use GitHub Issues for bug reports and feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Documentation**: Check the docs/ directory for detailed guides

## License

By contributing to DriftBuddy, you agree that your contributions will be licensed under the MIT License.
