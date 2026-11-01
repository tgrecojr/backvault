---
parent: high-level-design
prefix: IMAGE
---

# image-delivery

## Context and Design Philosophy

BackVault is consumed as a container image. During a disaster the operator needs to `docker pull` something they can trust and run, so the image has to be small in attack surface, built from pinned inputs, and provably the output of this repository's CI. image-delivery owns the Dockerfile, the reference Compose file, the GitHub Actions workflows, and the Renovate policy that keeps the inputs current without manual drift.

Three commitments shape it:

- **Minimal runtime.** The runtime stage is Chainguard's distroless Python: no shell, no package manager, non-root, and no executable beyond the interpreter and the application's virtual environment. The container runs under Docker's default seccomp profile with no relaxation.
- **Pinned and attested.** Base images and tools are pinned by digest, Python packages by `uv.lock`, nothing else is fetched at build time, and every published image is cosign-signed with an SBOM and build-provenance attestation pushed alongside it.
- **Updates arrive as PRs.** Renovate proposes every change; low-risk ones automerge after a stability window, majors wait for review, and the two Chainguard images move together.

## Image Build

```mermaid
flowchart LR
    subgraph builder [cgr.dev/chainguard/python:latest-dev]
        A[uv sync --frozen --no-dev] --> V[/app/.venv]
    end
    subgraph runtime [cgr.dev/chainguard/python:latest, USER 1000:1000]
        V2[/app/.venv]
        S[/app/*.py from src/ + entrypoint.py]
        E[ENTRYPOINT python /app/entrypoint.py]
    end
    V --> V2
```

The Dockerfile pins the `docker/dockerfile` syntax image, both Chainguard images, and the `ghcr.io/astral-sh/uv` image by digest. Python dependencies come from the committed `uv.lock` via `uv sync --frozen --no-dev --no-install-project` with a cache mount. Source is copied flat from `src/` into `/app`, which is why `entrypoint.py` adds `/app` to `sys.path`. The builder performs no other downloads, so every byte in the runtime image traces to a digest or to the lock file, and two builds of the same commit produce the same contents.

The image is built for `linux/amd64` only.

## Reference Deployment

`docker-compose.yml` is the operator-facing contract: run as `${UID:-1000}:${GID:-1000}`, mount `./backups` at `/app/backups`, pass the five required credentials from the environment, default `BACKUP_INTERVAL_HOURS=12` and `RETAIN_DAYS=7`, and show `BW_CA_CERT` as the commented-out option for self-signed servers (the path must also be mounted). It sets no `security_opt`; the default seccomp profile applies. The image reference is a placeholder (`ghcr.io/yourusername/backvault`), excluded from Renovate.

## CI Pipeline

| Trigger | Workflow | Steps |
|---------|----------|-------|
| pull request | `test.yml` | ruff check + format check on `src/`; pytest; build amd64 image; run the image's Python interpreter under the default seccomp profile as a smoke test |
| push to main | `docker-publish.yml` → `supply-chain.yml` | export `uv.lock` to requirements; Socket scan (skipped when the API-key secret is absent); OSV scan of `uv.lock`; pip-audit |
| push to main (after scan) | `docker-publish.yml` | build and push `latest` and `main-<sha>` to `ghcr.io/tgrecojr/backvault`; cosign keyless sign by digest; SPDX SBOM via anchore; `actions/attest` for the SBOM; `attest-build-provenance`; both pushed to the registry |
| weekly / manual | `ghcr-retention.yml` | keep `latest` plus the 5 most recent tagged versions; delete untagged |

The Socket step is optional by design: bot-authored PRs (Dependabot, Renovate) run without repository secrets, and a required secret would fail the reusable workflow before any scan ran.

## Dependency Policy

`renovate.json` extends `config:recommended` with semantic commits, a dependency dashboard, and a night/weekend schedule. Rules:

- Pin digests for every Docker image reference.
- Group all minor and patch updates into one PR, automerge after a 3-day minimum release age.
- Automerge digest-only updates immediately.
- Never automerge majors; label them `major-update`.
- Group `cgr.dev/chainguard/python` builder and runtime into one PR so the venv built in one always matches the interpreter in the other.
- Ignore the placeholder compose image.
- Lock-file maintenance weekly.

`osv-scanner.toml` exists as an empty allow-list for per-vulnerability ignores.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Runtime base | Chainguard distroless Python (Wolfi, glibc) | `python:slim` (Debian); Alpine; Google distroless | `[inferred]` No shell or package manager in the runtime, frequent rebuilds, small CVE surface; Wolfi is glibc-based so `cryptography` and `argon2-cffi` wheels run unmodified. Cost: no shell for debugging; the supervisor had to become Python. |
| Third-party executables | None; the vault client is Python | Ship the Bitwarden CLI (`bw`), a pkg-bundled Node binary | The binary needed `seccomp=unconfined`, was downloaded unpinned and unverified at build time, and carried a Node CVE surface. With the native client every runtime input is a digest or a lock entry (tenet: *Pinned beats fresh*). |
| Dependency install | `uv sync --frozen` from `uv.lock` | `pip install -r requirements.txt` | `[inferred]` Reproducible resolution; the lock is what OSV and pip-audit scan. |
| Input pinning | Digests for images, lock for Python, no other downloads, Renovate to bump them | Floating tags | `[inferred]` Reproducibility and a reviewable diff for every change. |
| Platform | `linux/amd64` only | Multi-arch with QEMU | BUILD.md: simplifies deployment. Without a platform-specific binary, multi-arch becomes feasible if ever wanted. |
| Publication trust | cosign keyless + SPDX SBOM + provenance attestations | Unsigned push; key-based cosign | `[inferred]` Verifiable origin without managing signing keys. |
| Automerge policy | Minor/patch grouped after 3 days; digests immediate; majors reviewed | Automerge everything; review everything | `[inferred]` Keeps low-risk churn off the maintainer while majors get eyes. |
| Chainguard lockstep | Builder and runtime in one Renovate group | Independent updates | renovate.json description: the venv copied from the builder must match the runtime Python. |
| Non-root | `USER 1000:1000` in the image; `${UID}:${GID}` in compose | Root | `[inferred]` Least privilege; mounted-volume ownership matches the host user. |
| Seccomp | Docker's default profile | `seccomp=unconfined`; a custom profile | Nothing in the image needs a non-default syscall once the Node binary is gone; the default profile is the one operators get without reading documentation. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **No third-party binary in the image.** The `bw` download stage, the `seccomp=unconfined` requirement, and the `bw --version` smoke test are removed together with the CLI.

### Deferred
1. **Health check.** No `HEALTHCHECK`; depends on scheduler-retention exposing a heartbeat.
2. **Lint scope.** Extend ruff to `entrypoint.py` and `tests/`.
3. **Compose hygiene.** Replace the placeholder image name; drop the obsolete `version:` key.
4. **Documentation claims.** README (Trivy/Bandit, SECURITYASSESS.md, seccomp requirement, `NODE_TLS_REJECT_UNAUTHORIZED`), SETUP.md (multi-arch, version tags), and BUILD.md (`/bin/bash` in a distroless image, `bw` verification steps) describe a pipeline that does not exist.
5. **Multi-arch.** With no platform-specific binary, an `arm64` build is a CI change rather than a packaging problem; decide whether it is wanted.
6. **Argon2id memory.** Document compose `deploy.resources` guidance for accounts whose KDF uses large memory settings.

## References

- Chainguard Python images: https://images.chainguard.dev/directory/image/python/overview
- cosign keyless signing: https://docs.sigstore.dev/cosign/signing/overview/
- GitHub artifact attestations: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations
- Renovate configuration: https://docs.renovatebot.com/configuration-options/
- Sibling segments: vault-access (the native client that made the binary-free image possible), scheduler-retention (the entrypoint this image runs), backup-cycle (owns `BW_CA_CERT` intake)
