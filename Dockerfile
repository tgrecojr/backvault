# syntax=docker/dockerfile:1.28@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
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
FROM docker.io/library/rust:1.99.1-alpine@sha256:7e9e2d068a107a2adafd19930011178d14a78326053cd4c3a9f7ad3fd049557d AS builder

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
FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9

USER 1000:1000
WORKDIR /app

COPY --from=builder --chown=1000:1000 /backvault /app/backvault

ENV HOME=/app

ENTRYPOINT ["/app/backvault"]
