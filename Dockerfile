# syntax=docker/dockerfile:1.24@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
# Multi-stage Dockerfile for BackVault — distroless runtime
# Platform: Linux x86_64 only
#
# Runtime image is Chainguard's distroless Python (Wolfi, glibc, no shell, no
# package manager). The vault client is rbw (Rust) — Wolfi doesn't package rbw,
# so we cargo-install it in a dedicated Rust builder stage and copy the binary.

# ============================================
# rbw builder — compile rbw from crates.io
# ============================================
FROM cgr.dev/chainguard/rust:latest-dev@sha256:9f165c39de87863b695ec367f76820faa3d93d1f6c7a579131b817bb3d34047b AS rbw-builder

USER root
WORKDIR /build

# rbw depends on OpenSSL via reqwest; pkgconf locates the system OpenSSL
RUN apk add --no-cache openssl-dev pkgconf

# Cache the cargo registry + git index + target dir to keep CI rebuilds fast.
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/build/target \
    CARGO_TARGET_DIR=/build/target \
    cargo install rbw --root /usr/local --locked

# ============================================
# Python + uv builder
# ============================================
FROM cgr.dev/chainguard/python:latest-dev@sha256:c1d503ebc5088bd0143673af0d02f2db31e53acc506ba5a8f4756c337a989d3f AS builder

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

# ============================================
# Runtime Stage — distroless (no shell, no apk)
# ============================================
FROM cgr.dev/chainguard/python:latest@sha256:f960fea6d1fb1c0ad626558d9db323ff84468927ac37cd7fa889b512ba0dc1c9

USER 1000:1000
WORKDIR /app

# Python virtual environment
COPY --from=builder --chown=1000:1000 /app/.venv /app/.venv

# rbw + rbw-agent binaries from the Rust builder
COPY --from=rbw-builder /usr/local/bin/rbw /usr/bin/rbw
COPY --from=rbw-builder /usr/local/bin/rbw-agent /usr/bin/rbw-agent

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
