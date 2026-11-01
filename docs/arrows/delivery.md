# Arrow: delivery

Builds, verifies, signs, and publishes the container image and the restore-tool binaries, and keeps every input pinned and current.

## Status

**PARTIAL** — the Dockerfile, workflows, `deny.toml`, `rust-toolchain.toml`, Renovate policy, and documentation are written; 17 of 26 specs are verified by inspection or a local build. The 9 CI and release specs are verified only by an observed run, which happens on the first pull request and the first `v*` tag.

## References

### HLD
- docs/high-level-design.md (System Design → delivery; Key Design Decisions 5, 6, 7)

### LLD
- docs/intent/delivery/delivery-design.md

### EARS
- docs/intent/delivery/delivery-specs.md (26 specs)

### Tests
- .github/workflows/test.yml (fmt, clippy, workspace tests, amd64 image build, `--version` smoke under default seccomp)
- .github/workflows/release.yml (restore-tool tests on every target before publishing)
- `cargo deny check` locally (advisories, licences, bans, sources)

### Code
- Dockerfile
- docker-compose.yml
- rust-toolchain.toml, deny.toml, .dockerignore
- .github/workflows/test.yml, docker-publish.yml, supply-chain.yml, release.yml, ghcr-retention.yml
- .github/release-notes.md
- renovate.json
- osv-scanner.toml

## Architecture

**Purpose:** Produce a distroless, non-root, digest-pinned, signed and attested `linux/amd64` image holding one static binary, and a signed, attested, tested restore binary for four desktop targets.

**Key Components:**
1. Dockerfile — `rust:alpine` builder (`cargo build --locked`, musl target, gcc and musl-dev already present) → Chainguard `static` runtime, UID 1000, `/app/backvault`.
2. `test.yml` — PR gate: fmt, clippy, tests, amd64 build, `--version` smoke.
3. `docker-publish.yml` + `supply-chain.yml` — main-branch pipeline: Socket / OSV / cargo-deny → build → push → cosign sign → SPDX SBOM → attestations.
4. `release.yml` — tag pipeline: four-target restore-tool matrix, tests per target, checksums, cosign blob signatures, provenance, GitHub Release with `.github/release-notes.md`.
5. `ghcr-retention.yml` — weekly prune.
6. `renovate.json` + `deny.toml` — digest pinning, grouped automerge, toolchain lockstep via a custom manager, advisory and licence policy.
7. `docker-compose.yml` — reference deployment with no `security_opt`; published image name; `BW_CA_CERT` shown for self-signed servers.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Image build | IMAGE-BUILD-001 to 003, 005 to 008 | 7 | 0 | 0 |
| Reference deployment | IMAGE-RUN-001 to 004 | 4 | 0 | 0 |
| CI pipeline | IMAGE-CI-001 to 006 | 0 | 0 | 6 |
| Release pipeline | IMAGE-RELEASE-001 to 005 | 2 | 0 | 3 |
| Dependency policy | IMAGE-DEPS-001, 002, 004, 005 | 4 | 0 | 0 |

**Summary:** 17 of 26 active specs verified; 9 await their first observed CI or release run. These specs are verified by inspection and by CI runs, not by unit tests.

## Key Findings

1. **The image is one file.** No interpreter, venv, or libc; the smoke test can only pass if the binary is truly static.
2. **The restore tool is tested on every platform it ships for** before a release exists.
3. **Toolchain has one version, two carriers** (`rust-toolchain.toml` and the builder image tag), kept in step by one Renovate group; the Dockerfile never lets rustup download.
4. **No `HEALTHCHECK`** — depends on scheduler-retention exposing a heartbeat.

## Work Required

### Must Fix
1. Open the pull request and confirm `test.yml` and the supply-chain scan pass (IMAGE-CI-001, 002, 005); confirm the first publish signs and attests (IMAGE-CI-003, 004).
2. Push the first `v*` tag and confirm four tested, signed, attested assets appear on the release (IMAGE-RELEASE-001 to 003).

### Should Fix
3. Confirm the GHCR retention workflow still prunes as before (IMAGE-CI-006).

### Nice to Have
4. Pin GitHub Actions by digest (LLD Deferred 2).
5. Add a `HEALTHCHECK` once scheduler-retention exposes a heartbeat.
