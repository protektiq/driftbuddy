.PHONY: help install test lint format clean build docker-build docker-run docs

# Default target
help: ## Show this help message
	@echo "DriftBuddy - Enterprise Infrastructure Security Scanner"
	@echo "=================================================="
	@echo ""
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development setup
install: ## Install development dependencies
	pip install -e ".[dev]"
	pre-commit install

install-minimal: ## Install minimal dependencies
	pip install -e "."

# Testing
test: ## Run all tests
	pytest

test-cov: ## Run tests with coverage
	pytest --cov=src/driftbuddy --cov-report=html --cov-report=term-missing

test-unit: ## Run unit tests only
	pytest -m unit

test-integration: ## Run integration tests only
	pytest -m integration

# Code quality
lint: ## Run all linting checks
	flake8 src/ tests/
	mypy src/
	bandit -r src/

format: ## Format code with black and isort
	black src/ tests/
	isort src/ tests/

format-check: ## Check if code is formatted correctly
	black --check src/ tests/
	isort --check-only src/ tests/

# Security
security-scan: ## Run security scan
	python scripts/security_scan.py

# Version management
check-version: ## Check version consistency
	python scripts/check_version.py

# Documentation
docs: ## Build documentation
	cd docs && make html

docs-serve: ## Serve documentation locally
	cd docs && python -m http.server 8000

# Cleaning
clean: ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

# Building
build: ## Build package
	python -m build

# Docker
docker-build: ## Build Docker image
	docker build -t driftbuddy:latest .

docker-run: ## Run Docker container
	docker run --rm -it driftbuddy:latest

docker-compose-up: ## Start services with docker-compose
	docker-compose up -d

docker-compose-down: ## Stop docker-compose services
	docker-compose down

# CI/CD
ci: ## Run CI checks
	make format-check
	make lint
	make test
	make security-scan
	make check-version

# Development workflow
dev-setup: ## Complete development setup
	make install
	make format
	make test

# API Key Setup
setup-api-key: ## Set up OpenAI API key
	python scripts/setup_api_key.py

# Release
release: ## Prepare for release
	make clean
	make test-cov
	make lint
	make security-scan
	make check-version
	make build

# Quick checks
quick-check: ## Quick code quality check
	make format-check
	flake8 src/ --max-line-length=88 --extend-ignore=E203,W503 --count --statistics

# Environment
env-create: ## Create virtual environment
	python -m venv .venv
	@echo "Virtual environment created. Activate with:"
	@echo "  source .venv/bin/activate  # Linux/Mac"
	@echo "  .venv\\Scripts\\activate     # Windows"

env-activate: ## Show activation command
	@echo "Activate virtual environment:"
	@echo "  source .venv/bin/activate  # Linux/Mac"
	@echo "  .venv\\Scripts\\activate     # Windows"

# Helpers
check-deps: ## Check for outdated dependencies
	pip list --outdated

update-deps: ## Update dependencies
	pip install --upgrade -r requirements.txt

# Pre-commit
pre-commit-run: ## Run pre-commit on all files
	pre-commit run --all-files

pre-commit-update: ## Update pre-commit hooks
	pre-commit autoupdate 