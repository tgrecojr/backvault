# Simple single-stage Dockerfile for BackVault
# Platform: Linux x86_64 only
FROM python:3.14-alpine

# Install runtime and build dependencies
RUN apk add --no-cache \
    bash \
    ca-certificates \
    libffi \
    openssl \
    dcron \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust \
    curl \
    unzip

# Create non-root user
RUN addgroup -g 1000 backvault && \
    adduser -D -u 1000 -G backvault -h /home/backvault backvault && \
    mkdir -p /app/backups /var/log && \
    chown -R backvault:backvault /app /var/log /home/backvault

WORKDIR /app

# Set HOME for backvault user
ENV HOME=/home/backvault

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade "pip>=25.3" && \
    pip install --no-cache-dir -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

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

# Clean up build dependencies to reduce image size
RUN apk del gcc musl-dev libffi-dev openssl-dev cargo rust unzip && \
    rm -rf /var/cache/apk/*

# Copy application files
COPY --chown=backvault:backvault ./src /app/
COPY --chown=backvault:backvault ./entrypoint.sh /app/entrypoint.sh
COPY --chown=backvault:backvault ./cleanup.sh /app/cleanup.sh

# Set execute permissions
RUN chmod +x /app/entrypoint.sh /app/cleanup.sh

# Switch to non-root user
USER backvault

ENTRYPOINT ["/app/entrypoint.sh"]
