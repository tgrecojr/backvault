# Arrow: image-delivery

Builds, verifies, signs, and publishes the container image, and keeps its inputs pinned and current.

## Status

**MAPPED** — mapped and revised 2026-11-01 (binary-free image, default seccomp, no build-time downloads); not yet audited. 19 of 19 specs implemented. The revised PR workflow smoke test has not yet run in GitHub Actions.

## References

### HLD
- docs/high-level-design.md (System Design → image-delivery; Key Design Decisions 4 and 5)

### LLD
- docs/intent/image-delivery/image-delivery-design.md

### EARS
- docs/intent/image-delivery/image-delivery-specs.md (19 specs)

### Tests
- .github/workflows/test.yml (`docker-build-test`: build, interpreter smoke, module-import smoke under default seccomp)

### Code
- Dockerfile
- docker-compose.yml
- .github/workflows/test.yml
- .github/workflows/docker-publish.yml
- .github/workflows/supply-chain.yml
- .github/workflows/ghcr-retention.yml
- renovate.json
- osv-scanner.toml

## Architecture

**Purpose:** Produce a distroless, non-root, digest-pinned, signed and attested `linux/amd64` image with no third-party executables, so every byte traces to a digest or the lock file.

**Key Components:**
1. Dockerfile — Chainguard `python:latest-dev` builder (uv sync only) → Chainguard `python:latest` distroless runtime, UID 1000.
2. `test.yml` — PR gate: ruff on `src/`, pytest, amd64 build, smoke-run of the interpreter and the application modules.
3. `docker-publish.yml` + `supply-chain.yml` — main-branch pipeline: Socket / OSV / pip-audit → build → push → cosign sign → SPDX SBOM → attestations.
4. `ghcr-retention.yml` — weekly prune.
5. `renovate.json` — digest pinning, grouped automerge, Chainguard lockstep.
6. `docker-compose.yml` — reference deployment with no `security_opt`; `BW_CA_CERT` shown for self-signed servers.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Image build | IMAGE-BUILD-001 to 003, 005 to 008 | 7 | 0 | 0 |
| Reference deployment | IMAGE-RUN-001 to 003 | 3 | 0 | 0 |
| CI pipeline | IMAGE-CI-001 to 006 | 6 | 0 | 0 |
| Dependency policy | IMAGE-DEPS-001 to 003 | 3 | 0 | 0 |

**Summary:** 19 of 19 active specs implemented. These specs are verified by inspection and by CI, not by unit tests.

## Key Findings

1. **Every build input is now pinned or locked.** The `bw` download stage, its GitHub-API version lookup, and its unverified zip are gone; the builder runs `uv sync --frozen` and nothing else.
2. **Default seccomp profile applies.** `security_opt` is removed from compose, the README, BUILD.md, and the CI smoke test.
3. **No `HEALTHCHECK`** — depends on scheduler-retention exposing a heartbeat.
4. **Lint scope** — CI runs ruff on `src/` only; `entrypoint.py` and `tests/` are not linted (both pass locally except two pre-existing `DTZ011` findings in `entrypoint.py`).
5. **Placeholder image name in compose** (`ghcr.io/yourusername/backvault`, renovate-ignored) while CI publishes to `ghcr.io/tgrecojr/backvault`.
6. **SETUP.md still claims multi-arch builds and version tags** that the pipeline does not produce.

## Work Required

### Must Fix
*(none)*

### Should Fix
1. Confirm the revised `docker-build-test` job passes on the first PR.
2. Fix the compose image name; correct SETUP.md's multi-arch and version-tag claims.

### Nice to Have
3. Add a `HEALTHCHECK` once scheduler-retention exposes a heartbeat.
4. Extend ruff to `entrypoint.py` and `tests/`.
5. Decide whether an `arm64` build is wanted now that nothing in the image is platform-specific.
