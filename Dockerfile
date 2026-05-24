# syntax=docker/dockerfile:1.24@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
# Multi-stage Dockerfile for BackVault — distroless runtime
# Platform: Linux x86_64 only
#
# Runtime image is Chainguard's distroless Python (Wolfi, glibc, no shell, no
# package manager). The vault client is rbw (Rust) — installed in the builder
# stage and copied across as a single binary alongside rbw-agent.

# ============================================
# Builder Stage — has apk, shell, curl, unzip
# ============================================
FROM cgr.dev/chainguard/python:latest-dev AS builder

USER root
WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.11@sha256:440fd6477af86a2f1b38080c539f1672cd22acb1b1a47e321dba5158ab08864d /uv /uvx /usr/local/bin/

ENV UV_PROJECT_ENVIRONMENT=/app/.venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Install rbw (Rust Bitwarden client). Wolfi packages rbw; pin via Renovate
# once you confirm a stable upstream version.
# If `apk add rbw` ever fails (package removed/renamed), fallback is:
#   apk add --no-cache cargo rust && cargo install rbw --root /usr/local
RUN apk add --no-cache rbw

# ============================================
# Runtime Stage — distroless (no shell, no apk)
# ============================================
FROM cgr.dev/chainguard/python:latest

USER 1000:1000
WORKDIR /app

# Python virtual environment
COPY --from=builder --chown=1000:1000 /app/.venv /app/.venv

# rbw + rbw-agent binaries (root-owned, world-executable)
COPY --from=builder /usr/bin/rbw /usr/bin/rbw
COPY --from=builder /usr/bin/rbw-agent /usr/bin/rbw-agent

# Application code
COPY --chown=1000:1000 ./src/ /app/
COPY --chown=1000:1000 ./entrypoint.py /app/entrypoint.py
COPY --chown=1000:1000 --chmod=0755 ./pinentry.py /app/pinentry.py

ENV PATH="/app/.venv/bin:$PATH" \
    HOME=/app \
    XDG_CONFIG_HOME=/app/.config \
    XDG_DATA_HOME=/app/.local/share \
    XDG_RUNTIME_DIR=/tmp/rbw-runtime \
    RBW_PINENTRY=/app/pinentry.py

ENTRYPOINT ["python", "/app/entrypoint.py"]
