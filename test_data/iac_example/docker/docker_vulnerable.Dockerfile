# Purposefully vulnerable Dockerfile for testing
# This file contains multiple security flaws for demonstration

# CRITICAL: Running as root
FROM ubuntu:20.04

# CRITICAL: No non-root user created
# USER nonroot

# CRITICAL: Installing unnecessary packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    telnet \
    netcat \
    curl \
    wget \
    vim \
    nano \
    python3 \
    nodejs \
    npm \
    git \
    && rm -rf /var/lib/apt/lists/*

# CRITICAL: Creating SSH service
RUN mkdir /var/run/sshd
RUN echo 'root:password123' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# CRITICAL: Exposing SSH port
EXPOSE 22

# CRITICAL: Running SSH daemon
CMD ["/usr/sbin/sshd", "-D"]

# HIGH: Setting weak file permissions
RUN chmod 777 /tmp
RUN chmod 777 /var/tmp

# HIGH: Creating world-writable directories
RUN mkdir -p /app/data
RUN chmod 777 /app/data

# HIGH: Installing packages with known vulnerabilities
RUN npm install -g express@4.17.1  # HIGH: Known vulnerable version

# MEDIUM: Copying sensitive files
COPY . /app/
# MEDIUM: No .dockerignore file to exclude sensitive files

# MEDIUM: Setting environment variables with sensitive data
ENV DATABASE_URL="postgresql://admin:password123@db.example.com:5432/mydb"
ENV API_KEY="sk-1234567890abcdef"
ENV SECRET_TOKEN="my-super-secret-token-12345"
ENV DEBUG="true"

# MEDIUM: No health check
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#   CMD curl -f http://localhost/ || exit 1

# MEDIUM: No multi-stage build to reduce attack surface
# FROM node:16-alpine AS builder
# WORKDIR /app
# COPY package*.json ./
# RUN npm ci --only=production
#
# FROM node:16-alpine
# WORKDIR /app
# COPY --from=builder /app/node_modules ./node_modules
# COPY . .

# LOW: No specific user created
# RUN addgroup -g 1001 -S nodejs
# RUN adduser -S nextjs -u 1001
# USER nextjs

# LOW: No resource limits
# No memory or CPU limits specified

# LOW: No security scanning
# No vulnerability scanning in build process

# INFO: No labels for maintainability
# LABEL maintainer="security-team@example.com"
# LABEL version="1.0"
# LABEL description="Vulnerable application for testing"

# INFO: No proper logging configuration
# No structured logging setup

# INFO: No proper signal handling
# No graceful shutdown handling
