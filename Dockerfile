# Multi-stage Dockerfile for BackVault - Optimized for size
# Platform: Linux x86_64 only

# ============================================
# Builder Stage - Compile dependencies
# ============================================
FROM python:3.14-slim@sha256:486b8092bfb12997e10d4920897213a06563449c951c5506c2a2cfaf591c599f AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    cargo \
    rustc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment and install Python dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade "pip>=25.3" && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# ============================================
# Runtime Stage - Minimal runtime environment
# ============================================
FROM python:3.14-slim@sha256:486b8092bfb12997e10d4920897213a06563449c951c5506c2a2cfaf591c599f

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
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

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
