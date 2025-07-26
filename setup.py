#!/usr/bin/env python3
"""
Setup script for DriftBuddy.
Makes the package installable and resolves import issues.
"""

from setuptools import setup, find_packages

setup(
    name="driftbuddy",
    version="1.0.0",
    description="AI-powered security analysis tool with KICS integration",
    author="DriftBuddy Team",
    packages=find_packages(),
    install_requires=[
        "openai>=1.0.0",
        "python-dotenv>=1.0.0",
        "markdown>=3.4.0",
        "requests>=2.31.0",
        "rich>=13.0.0",
        "structlog>=23.0.0",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "driftbuddy=src.driftbuddy.core:main",
        ],
    },
) 