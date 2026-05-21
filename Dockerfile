# syntax=docker/dockerfile:1.24@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
# Multi-stage Dockerfile for BackVault - Optimized for size
# Platform: Linux x86_64 only

# ============================================
# Builder Stage - Install Python dependencies via uv
# ============================================
FROM python:3.14-slim@sha256:a7185a8e40af01bf891414a4df16ef10fc6000cee460a404a13da9029fe41604 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11@sha256:440fd6477af86a2f1b38080c539f1672cd22acb1b1a47e321dba5158ab08864d /uv /uvx /usr/local/bin/

WORKDIR /app

ENV UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# ============================================
# Runtime Stage - Minimal runtime environment
# ============================================
FROM python:3.14-slim@sha256:a7185a8e40af01bf891414a4df16ef10fc6000cee460a404a13da9029fe41604

# Install only runtime dependencies (no -dev packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    cron \
    curl \
    unzip \
    libffi8 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 1000 backvault && \
    useradd -u 1000 -g backvault -m -d /home/backvault backvault && \
    mkdir -p /app/backups /var/log && \
    chown -R backvault:backvault /app /var/log /home/backvault

WORKDIR /app

# Set HOME for backvault user
ENV HOME=/home/backvault

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Install Bitwarden CLI for Linux x86_64
RUN set -eux; \
    BW_VERSION=$(curl -s https://api.github.com/repos/bitwarden/clients/releases | \
                 grep -o '"tag_name": "cli-v[^"]*"' | head -1 | \
                 sed 's/.*cli-v\([^"]*\).*/\1/') || BW_VERSION="2024.10.2"; \
    echo "Installing Bitwarden CLI version: ${BW_VERSION} for Linux x86_64"; \
    curl -fsSL "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-x86_64-${BW_VERSION}.zip" -o /tmp/bw.zip || \
    curl -fsSL "https://vault.bitwarden.com/download/?app=cli&platform=linux" -o /tmp/bw.zip; \
    unzip /tmp/bw.zip -d /tmp; \
    mv /tmp/bw /usr/local/bin/bw; \
    chmod +x /usr/local/bin/bw; \
    rm -f /tmp/bw.zip

# Remove curl and unzip after bw installation to save space
RUN apt-get purge -y --auto-remove curl unzip && \
    rm -rf /var/lib/apt/lists/*

# Copy application files
COPY --chown=backvault:backvault ./src /app/
COPY --chown=backvault:backvault ./entrypoint.sh /app/entrypoint.sh
COPY --chown=backvault:backvault ./cleanup.sh /app/cleanup.sh

# Set execute permissions
RUN chmod +x /app/entrypoint.sh /app/cleanup.sh

# Switch to non-root user
USER backvault

ENTRYPOINT ["/app/entrypoint.sh"]
