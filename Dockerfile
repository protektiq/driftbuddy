# Multi-stage Dockerfile for DriftBuddy
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Go for KICS
RUN wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz \
    && rm go1.21.0.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin

# Install KICS
RUN git clone https://github.com/Checkmarx/kics.git \
    && cd kics \
    && go mod vendor \
    && go build -o ./bin/kics cmd/console/main.go \
    && mv ./bin/kics /usr/local/bin/ \
    && chmod +x /usr/local/bin/kics \
    && cd .. \
    && rm -rf kics

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt requirements-web-v3-minimal.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -r requirements-web-v3-minimal.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/uploads /app/reports /app/logs

# Create non-root user
RUN useradd --create-home --shell /bin/bash driftbuddy \
    && chown -R driftbuddy:driftbuddy /app

USER driftbuddy

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Default command
CMD ["uvicorn", "web.api_v3_simple:app", "--host", "0.0.0.0", "--port", "8000"]
