# syntax=docker/dockerfile:1.29@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Multi-stage Dockerfile for BackVault — one static binary in a distroless static image.
# Platform: linux/amd64 only.
#
# The builder is the official Rust image on Alpine, whose toolchain targets musl natively and
# which ships gcc and musl-dev, so the one C-backed crate in the tree (ring, via rustls) builds
# without a package manager. `--locked` honours Cargo.lock exactly; crates.io is the only
# network access and only for those pinned versions. rust-toolchain.toml is excluded by
# .dockerignore so rustup never downloads a toolchain here (IMAGE-BUILD-008).
#
# The runtime is Chainguard's static image: no shell, no package manager, no interpreter,
# no libc. It holds exactly one file the project built. The restore tool is never copied in.

# ============================================
# Builder stage
# ============================================
FROM docker.io/library/rust:1.100.0-alpine@sha256:de1e0058543a81ed7b046629167db587c67a94bdf37cce14eb27f0ec83baaffb AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p backvault --target x86_64-unknown-linux-musl \
    && cp target/x86_64-unknown-linux-musl/release/backvault /backvault

# ============================================
# Runtime stage — distroless static
# ============================================
FROM cgr.dev/chainguard/static:latest@sha256:8658e9eaeb2294fa0e49b0667f7d66b4e21fa7690b8d2a4c30cd1d013ceb9eb7

USER 1000:1000
WORKDIR /app

COPY --from=builder --chown=1000:1000 /backvault /app/backvault

ENV HOME=/app

ENTRYPOINT ["/app/backvault"]
