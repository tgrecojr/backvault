# ============================================================================
# Multi-stage Alpine-based Dockerfile for BackVault
# ============================================================================
# This multi-stage build reduces the final image size and attack surface by
# separating build-time dependencies from runtime dependencies.
#
# PLATFORM: Linux x86_64 only
# ============================================================================

# ============================================================================
# Stage 1: Builder - Install dependencies and compile packages
# ============================================================================
FROM python:3.14-alpine AS builder

# Install build dependencies for Python packages and Bitwarden CLI download
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust \
    curl \
    unzip

# Create a virtual environment for Python packages
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade "pip>=25.3" && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Install Bitwarden CLI for Linux x86_64
RUN set -eux; \
    # Get latest version from GitHub API
    BW_VERSION=$(curl -s https://api.github.com/repos/bitwarden/clients/releases | \
                 grep -o '"tag_name": "cli-v[^"]*"' | head -1 | \
                 sed 's/.*cli-v\([^"]*\).*/\1/') || BW_VERSION="2024.10.2"; \
    \
    echo "Installing Bitwarden CLI version: ${BW_VERSION} for Linux x86_64"; \
    \
    # Download the x86_64 binary
    curl -fsSL "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-x86_64-${BW_VERSION}.zip" -o /tmp/bw.zip || \
    curl -fsSL "https://vault.bitwarden.com/download/?app=cli&platform=linux" -o /tmp/bw.zip; \
    \
    unzip /tmp/bw.zip -d /tmp; \
    chmod +x /tmp/bw; \
    rm /tmp/bw.zip

# ============================================================================
# Stage 2: Runtime - Minimal final image with only runtime dependencies
# ============================================================================
FROM python:3.14-alpine

# Install only runtime dependencies (no build tools)
RUN apk add --no-cache \
    bash \
    ca-certificates \
    libffi \
    openssl \
    dcron \
    && rm -rf /var/cache/apk/*

# Create non-root user and group with home directory
RUN addgroup -g 1000 backvault && \
    adduser -D -u 1000 -G backvault -h /home/backvault backvault && \
    mkdir -p /app/backups /var/log && \
    chown -R backvault:backvault /app /var/log /home/backvault

WORKDIR /app

# Set HOME environment variable for the backvault user
ENV HOME=/home/backvault

# Copy Python virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Remove system pip to eliminate duplicate CVE detection by security scanners
# The venv pip (25.3+, upgraded in builder stage) in /opt/venv/bin is used via PATH
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip* || true

# Copy Bitwarden CLI from builder
COPY --from=builder /tmp/bw /usr/local/bin/bw

# Copy application files
COPY --chown=backvault:backvault ./src /app/
COPY --chown=backvault:backvault ./entrypoint.sh /app/entrypoint.sh
COPY --chown=backvault:backvault ./cleanup.sh /app/cleanup.sh

# Set execute permissions on scripts
RUN chmod +x /app/entrypoint.sh /app/cleanup.sh

# Switch to non-root user
USER backvault

ENTRYPOINT ["/app/entrypoint.sh"]
