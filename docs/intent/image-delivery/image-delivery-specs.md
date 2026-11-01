# image-delivery — EARS Specs

Prefix `IMAGE`. Facets: `BUILD` (Dockerfile), `RUN` (reference Compose deployment), `CI` (GitHub Actions), `DEPS` (Renovate policy).

Status: `[x]` implemented and observed working · `[ ]` specified, not yet implemented or unverified · `[D]` deferred.

## Image build

- [x] **IMAGE-BUILD-001**: The image shall be built in two stages: a Chainguard `python:latest-dev` builder stage with package tooling, and a Chainguard `python:latest` distroless runtime stage containing no shell and no package manager.
- [x] **IMAGE-BUILD-002**: The builder stage shall install Python dependencies with `uv sync --frozen --no-dev --no-install-project` from the committed `uv.lock`, and the runtime stage shall receive only the resulting virtual environment at `/app/.venv`.
- [x] **IMAGE-BUILD-003**: Every base image and tool image referenced in the Dockerfile (Dockerfile syntax, both Chainguard images, uv) shall be pinned by digest.
- [x] **IMAGE-BUILD-005**: The runtime stage shall run as UID 1000 and GID 1000 and shall not run as root.
- [x] **IMAGE-BUILD-006**: The runtime stage shall contain the application modules copied flat from `src/` into `/app`, `entrypoint.py` at `/app/entrypoint.py`, and the virtual environment at `/app/.venv`, shall contain no third-party executable outside the Python interpreter and the virtual environment, and shall start with `python /app/entrypoint.py`.
- [x] **IMAGE-BUILD-007**: The image shall be built for `linux/amd64` only.
- [x] **IMAGE-BUILD-008**: The builder stage shall download nothing at build time other than the digest-pinned base and tool images and the lock-file-pinned Python packages.

## Reference deployment (docker-compose.yml)

- [x] **IMAGE-RUN-001**: The reference Compose file shall set no `security_opt`, so that the container runs under Docker's default seccomp profile, and the README shall not instruct operators to relax it.
- [x] **IMAGE-RUN-002**: The reference Compose file shall run the container as `${UID:-1000}:${GID:-1000}` and mount `./backups` at `/app/backups`.
- [x] **IMAGE-RUN-003**: The reference Compose file shall pass `BW_CLIENT_ID`, `BW_CLIENT_SECRET`, `BW_PASSWORD`, `BW_SERVER`, and `BW_FILE_PASSWORD` from the host environment, shall default `BACKUP_INTERVAL_HOURS` to `12` and `RETAIN_DAYS` to `7`, and shall document `BW_CA_CERT` as the optional variable for self-signed servers.

## CI pipeline

- [x] **IMAGE-CI-001**: When a pull request is opened or updated, CI shall run `ruff check` and `ruff format --check` on `src/`, run pytest, build the `linux/amd64` image, and smoke-test the built image by running its Python interpreter under Docker's default seccomp profile.
- [x] **IMAGE-CI-002**: When a commit is pushed to `main`, CI shall run the supply-chain scan (Socket when its API key is present, OSV against `uv.lock`, pip-audit against the exported lock) before any image is built.
- [x] **IMAGE-CI-003**: When the supply-chain scan succeeds on `main`, CI shall build and push the image to `ghcr.io/tgrecojr/backvault` tagged `latest` and `main-<short-sha>`.
- [x] **IMAGE-CI-004**: When an image is pushed, CI shall sign it by digest with cosign keyless, generate an SPDX SBOM, and push attestations for both the SBOM and the build provenance to the registry.
- [x] **IMAGE-CI-005**: If the Socket API-key secret is unavailable (bot-authored pull requests), then CI shall skip the Socket step and still run the remaining scans.
- [x] **IMAGE-CI-006**: Weekly and on manual dispatch, CI shall prune the GHCR package to the `latest` tag plus the 5 most recent tagged versions and delete untagged versions.

## Dependency policy (renovate.json)

- [x] **IMAGE-DEPS-001**: Renovate shall pin digests for every Docker image reference it manages.
- [x] **IMAGE-DEPS-002**: Renovate shall group minor and patch updates into one PR and automerge it after a 3-day minimum release age, automerge digest-only updates immediately, and shall not automerge major updates.
- [x] **IMAGE-DEPS-003**: Renovate shall update the Chainguard `python:latest-dev` builder image and `python:latest` runtime image together in a single PR.
