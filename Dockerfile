# syntax=docker/dockerfile:1.25@sha256:0adf442eae370b6087e08edc7c50b552d80ddf261576f4ebd6421006b2461f12
# Multi-stage Dockerfile for BackVault — distroless runtime
# Platform: Linux x86_64 only
#
# Runtime image is Chainguard's distroless Python (Wolfi, glibc, no shell, no
# package manager). The vault CLI is the Bitwarden CLI (`bw`), downloaded in
# the builder stage and copied across as a single binary.
#
# Note: `bw` is a pkg-bundled Node binary; the default Docker seccomp profile
# blocks one of its syscalls. The container must run with
# `security_opt: ["seccomp=unconfined"]`. A future Phase 3 will replace `bw`
# with a direct Python implementation of the Bitwarden API and remove this
# requirement.

# ============================================
# Builder Stage — has apk, shell, curl, unzip
# ============================================
FROM cgr.dev/chainguard/python:latest-dev@sha256:0416c4863f2d0fb0e2e58d125e03b73cf4876cb02efc7927fd4a248a04f78c24 AS builder

USER root
WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.11@sha256:eb2843a1e56fd9e30c7276ce1a52cba86e64c7b385f5e3279a0e08e02dd058fc /uv /uvx /usr/local/bin/

ENV UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Install the Bitwarden CLI (linux/amd64). The Wolfi builder image has apk,
# curl, and unzip; the runtime image has none of these.
RUN apk add --no-cache curl unzip
RUN set -eux; \
    BW_VERSION=$(curl -s https://api.github.com/repos/bitwarden/clients/releases | \
                 grep -o '"tag_name": "cli-v[^"]*"' | head -1 | \
                 sed 's/.*cli-v\([^"]*\).*/\1/') || BW_VERSION="2024.10.2"; \
    echo "Installing Bitwarden CLI version: ${BW_VERSION} for Linux x86_64"; \
    curl -fsSL "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/bw-linux-x86_64-${BW_VERSION}.zip" -o /tmp/bw.zip || \
    curl -fsSL "https://vault.bitwarden.com/download/?app=cli&platform=linux" -o /tmp/bw.zip; \
    unzip /tmp/bw.zip -d /tmp; \
    install -m 0755 /tmp/bw /usr/local/bin/bw; \
    rm -f /tmp/bw.zip

# ============================================
# Runtime Stage — distroless (no shell, no apk)
# ============================================
FROM cgr.dev/chainguard/python:latest@sha256:ce9aaca1f826f7f963cd031e98f8c19f993b1843096d395ea919b646e72cb8de

USER 1000:1000
WORKDIR /app

# Python virtual environment
COPY --from=builder --chown=1000:1000 /app/.venv /app/.venv

# Bitwarden CLI binary
COPY --from=builder /usr/local/bin/bw /usr/local/bin/bw

# Application code
COPY --chown=1000:1000 ./src/ /app/
COPY --chown=1000:1000 ./entrypoint.py /app/entrypoint.py

ENV PATH="/app/.venv/bin:$PATH" \
    HOME=/app

ENTRYPOINT ["python", "/app/entrypoint.py"]
