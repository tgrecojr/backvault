# delivery — EARS Specs

Prefix `IMAGE`. Facets: `BUILD` (Dockerfile), `RUN` (reference Compose deployment), `CI` (GitHub Actions for the image), `RELEASE` (GitHub Actions for the restore tool), `DEPS` (Renovate and cargo-deny policy).

Status: `[x]` implemented and observed working · `[ ]` specified, not yet implemented or unverified · `[D]` deferred.

## Image build

- [x] **IMAGE-BUILD-001**: The image shall be built in two stages: an official Rust-on-Alpine builder stage, and a Chainguard `static` distroless runtime stage containing no shell, no package manager, no interpreter, and no libc.
- [x] **IMAGE-BUILD-002**: The builder stage shall compile the service with `cargo build --release --locked -p backvault --target x86_64-unknown-linux-musl` from the committed `Cargo.lock`, and the runtime stage shall receive only the resulting executable at `/app/backvault`.
- [x] **IMAGE-BUILD-003**: Every base image referenced in the Dockerfile (Dockerfile syntax, the Rust builder, the Chainguard runtime) shall be pinned by digest.
- [x] **IMAGE-BUILD-005**: The runtime stage shall run as UID 1000 and GID 1000 and shall not run as root.
- [x] **IMAGE-BUILD-006**: The runtime stage shall contain exactly one file the project built, the statically linked service executable at `/app/backvault`, shall not contain the restore tool, and shall start with `/app/backvault`.
- [x] **IMAGE-BUILD-007**: The image shall be built for `linux/amd64` only.
- [x] **IMAGE-BUILD-008**: The builder stage shall download nothing at build time other than the digest-pinned base images and the crates pinned in `Cargo.lock`, and shall not copy `rust-toolchain.toml` into the build context.

## Reference deployment (docker-compose.yml)

- [x] **IMAGE-RUN-001**: The reference Compose file shall set no `security_opt`, so that the container runs under Docker's default seccomp profile, and the README shall not instruct operators to relax it.
- [x] **IMAGE-RUN-002**: The reference Compose file shall run the container as `${UID:-1000}:${GID:-1000}` and mount `./backups` at `/app/backups`.
- [x] **IMAGE-RUN-003**: The reference Compose file shall pass `BW_CLIENT_ID`, `BW_CLIENT_SECRET`, `BW_PASSWORD`, `BW_SERVER`, and `BW_FILE_PASSWORD` from the host environment, shall default `BACKUP_INTERVAL_HOURS` to `12` and `RETAIN_DAYS` to `7`, and shall document `BW_CA_CERT` as the optional variable for self-signed servers.
- [x] **IMAGE-RUN-004**: The reference Compose file shall reference the published image `ghcr.io/tgrecojr/backvault:latest`.

## CI pipeline (image)

- [ ] **IMAGE-CI-001**: When a pull request is opened or updated, CI shall run `cargo fmt --check`, `cargo clippy --workspace --all-targets` with warnings denied, and `cargo test --workspace --locked`, build the `linux/amd64` image, and smoke-test the built image by running `/app/backvault --version` under Docker's default seccomp profile.
- [ ] **IMAGE-CI-002**: When a commit is pushed to `main`, CI shall run the supply-chain scan (Socket when its API key is present, OSV against `Cargo.lock`, `cargo-deny` advisories, licences, and bans) before any image is built.
- [ ] **IMAGE-CI-003**: When the supply-chain scan succeeds on `main`, CI shall build and push the image to `ghcr.io/tgrecojr/backvault` tagged `latest` and `main-<short-sha>`.
- [ ] **IMAGE-CI-004**: When an image is pushed, CI shall sign it by digest with cosign keyless, generate an SPDX SBOM, and push attestations for both the SBOM and the build provenance to the registry.
- [ ] **IMAGE-CI-005**: If the Socket API-key secret is unavailable (bot-authored pull requests), then CI shall skip the Socket step and still run the remaining scans.
- [ ] **IMAGE-CI-006**: Weekly and on manual dispatch, CI shall prune the GHCR package to the `latest` tag plus the 5 most recent tagged versions and delete untagged versions.

## Release pipeline (restore tool)

- [ ] **IMAGE-RELEASE-001**: When a tag matching `v*` is pushed, CI shall build `backvault-decrypt` for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-musl`, and `aarch64-unknown-linux-musl`, the Linux builds statically linked.
- [ ] **IMAGE-RELEASE-002**: Before publishing a release asset, CI shall run the restore tool's test suite on the runner that built that target, and if the tests fail for any target, then no release shall be published.
- [ ] **IMAGE-RELEASE-003**: CI shall attach to the GitHub Release, for each target, the binary named `backvault-decrypt-<target>`, its SHA-256 checksum file, a cosign keyless signature bundle, and a GitHub build-provenance attestation.
- [x] **IMAGE-RELEASE-004**: The release notes and the README shall state how to verify a downloaded binary with `cosign verify-blob` and `gh attestation verify`, the `xattr -d com.apple.quarantine` command macOS requires before running it, and the `cargo build --release -p backvault-decrypt` command for building it from source.
- [x] **IMAGE-RELEASE-005**: The repository shall pin the Rust toolchain in `rust-toolchain.toml`, and CI and release builds shall use that pinned toolchain.

## Dependency policy (renovate.json, deny.toml)

- [x] **IMAGE-DEPS-001**: Renovate shall pin digests for every Docker image reference it manages.
- [x] **IMAGE-DEPS-002**: Renovate shall group minor and patch updates, crates included, into one PR and automerge it after a 3-day minimum release age, automerge digest-only updates immediately, and shall not automerge major updates.
- [x] **IMAGE-DEPS-004**: Renovate shall update the Rust builder image tag and the version in `rust-toolchain.toml` together in a single PR.
- [x] **IMAGE-DEPS-005**: `deny.toml` shall fail the build on any crate with a known advisory, restrict licences to a permissive allow-list, and warn on duplicate crate versions.
