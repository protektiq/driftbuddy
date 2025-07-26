# Multi-stage build for DriftBuddy
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create non-root user
RUN groupadd -r driftbuddy && useradd -r -g driftbuddy driftbuddy

# Create application directory
WORKDIR /app

# Copy application code
COPY src/ ./src/
COPY driftbuddy.py .
COPY pyproject.toml .
COPY README.md .
COPY LICENSE .

# Create necessary directories
RUN mkdir -p outputs/reports outputs/analysis test_data/output \
    && chown -R driftbuddy:driftbuddy /app

# Switch to non-root user
USER driftbuddy

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Expose port (if needed for web interface)
# EXPOSE 8000

# Default command
ENTRYPOINT ["python", "driftbuddy.py"]
CMD ["--help"] 