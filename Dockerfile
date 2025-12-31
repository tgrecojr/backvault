# ============================================================================
# Multi-stage Alpine-based Dockerfile for BackVault
# ============================================================================
# This multi-stage build reduces the final image size and attack surface by
# separating build-time dependencies from runtime dependencies.
# ============================================================================

# ============================================================================
# Stage 1: Builder - Install dependencies and compile packages
# ============================================================================
FROM python:3.12-alpine AS builder

# ============================================================================
# Multi-Platform Build Configuration
# ============================================================================
# Docker automatically provides these build arguments when using --platform
# or when building with buildx for multiple architectures.
#
# TARGETPLATFORM: Full platform string (e.g., "linux/amd64", "linux/arm64")
# TARGETARCH: Architecture component (e.g., "amd64", "arm64", "arm")
# TARGETVARIANT: Architecture variant (e.g., "v7" for arm/v7)
#
# These are used to download the correct Bitwarden CLI binary for the
# target platform, not the build host platform.
#
# Example usage:
#   docker build --platform linux/amd64 -t backvault:latest .
#
# See BUILD.md for detailed platform-specific build instructions.
# ============================================================================
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

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

# Install Bitwarden CLI with proper architecture detection
RUN set -eux; \
    echo "Building for platform: ${TARGETPLATFORM:-linux/amd64}"; \
    echo "Target architecture: ${TARGETARCH}"; \
    \
    # Get latest version from GitHub API
    BW_VERSION=$(curl -s https://api.github.com/repos/bitwarden/clients/releases | \
                 grep -o '"tag_name": "cli-v[^"]*"' | head -1 | \
                 sed 's/.*cli-v\([^"]*\).*/\1/') || BW_VERSION="2024.10.2"; \
    \
    echo "Installing Bitwarden CLI version: ${BW_VERSION}"; \
    \
    # Map Docker architecture names to Bitwarden binary names
    case "${TARGETARCH}" in \
        amd64) \
            ARCH_SUFFIX="x86_64" ;; \
        arm64) \
            ARCH_SUFFIX="aarch64" ;; \
        arm) \
            ARCH_SUFFIX="armv7" ;; \
        *) \
            echo "Unsupported architecture: ${TARGETARCH}"; \
            exit 1 ;; \
    esac; \
    \
    echo "Downloading for architecture: ${ARCH_SUFFIX}"; \
    \
    # Download the architecture-specific binary
    curl -fsSL "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-${ARCH_SUFFIX}-${BW_VERSION}.zip" -o /tmp/bw.zip || \
    curl -fsSL "https://vault.bitwarden.com/download/?app=cli&platform=linux&arch=${ARCH_SUFFIX}" -o /tmp/bw.zip; \
    \
    unzip /tmp/bw.zip -d /tmp; \
    chmod +x /tmp/bw; \
    rm /tmp/bw.zip

# ============================================================================
# Stage 2: Runtime - Minimal final image with only runtime dependencies
# ============================================================================
FROM python:3.12-alpine

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
