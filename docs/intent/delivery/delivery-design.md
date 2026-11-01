---
parent: high-level-design
prefix: IMAGE
---

# delivery

## Context and Design Philosophy

BackVault reaches the operator as two artifacts: the service container image, pulled onto the server, and the `backvault-decrypt` restore binary, downloaded onto whatever laptop is at hand on rebuild day. During a disaster the operator needs to trust both without reading source, so each has to be small in attack surface, built from pinned inputs, and provably the output of this repository's CI. delivery owns the Dockerfile, the reference Compose file, the GitHub Actions workflows, the release pipeline for the restore tool, and the Renovate policy that keeps every input current without manual drift.

Three commitments shape it:

- **Minimal runtime.** The image holds one statically linked executable in a distroless static base: no shell, no package manager, no interpreter, no libc, non-root. The container runs under Docker's default seccomp profile with no relaxation.
- **Pinned and attested.** Base images are pinned by digest, crates by `Cargo.lock`, the toolchain by `rust-toolchain.toml`; nothing else is fetched at build time. Every published image is cosign-signed with an SBOM and build-provenance attestation. Every released binary ships with a checksum, a cosign signature, and a provenance attestation.
- **Updates arrive as PRs.** Renovate proposes every change; low-risk ones automerge after a stability window, majors wait for review.

## Image Build

```mermaid
flowchart LR
    subgraph builder [docker.io/library/rust:alpine, pinned digest]
        A[cargo build --release --locked<br/>-p backvault<br/>--target x86_64-unknown-linux-musl] --> B[/target/.../backvault]
    end
    subgraph runtime [cgr.dev/chainguard/static, pinned digest, USER 1000:1000]
        C[/app/backvault]
        E[ENTRYPOINT /app/backvault]
    end
    B --> C
```

The builder is the official Rust image on Alpine, whose toolchain targets musl natively, so `cargo build` produces a fully static executable without a cross-linker. The image ships gcc and musl-dev, which is what lets `ring` (the C-backed crate `rustls` uses for TLS) compile without a package manager. The build runs with `--locked`, so the resolution in `Cargo.lock` is honoured exactly and the only network access is crates.io for those pinned versions, cached with a BuildKit cache mount. `rust-toolchain.toml` is deliberately not copied into the builder: it would make rustup download a toolchain at build time, so the image build uses the toolchain the pinned Rust image ships, and Renovate keeps that image tag and the toolchain file on the same version.

The runtime stage is Chainguard's `static` image: a CA bundle, timezone data, and a `nonroot` user, and nothing executable. The service binary is copied to `/app/backvault` and is the entrypoint. The restore tool is never copied in. TLS roots are compiled into the binary, so the image's CA bundle is unused and nothing depends on it.

The image is built for `linux/amd64` only.

## Reference Deployment

`docker-compose.yml` is the operator-facing contract: image `ghcr.io/tgrecojr/backvault:latest`, run as `${UID:-1000}:${GID:-1000}`, mount `./backups` at `/app/backups`, pass the five required credentials from the environment, default `BACKUP_INTERVAL_HOURS=12` and `RETAIN_DAYS=7`, and show `BW_CA_CERT` as the commented-out option for self-signed servers (the path must also be mounted). It sets no `security_opt`; the default seccomp profile applies.

## Restore Tool Release

A tag matching `v*` triggers `release.yml`, which builds `backvault-decrypt` for four targets, runs the restore tool's own test suite on each, and attaches the results to a GitHub Release:

| Target | Runner | How |
|--------|--------|-----|
| `aarch64-apple-darwin` | macOS arm64 | native |
| `x86_64-apple-darwin` | macOS arm64 | `--target x86_64-apple-darwin`; Apple's toolchain cross-compiles both architectures |
| `x86_64-unknown-linux-musl` | Ubuntu x86_64 | `musl-tools`, static |
| `aarch64-unknown-linux-musl` | Ubuntu arm64 | `musl-tools`, static |

Each asset is named `backvault-decrypt-<target>` and is accompanied by `backvault-decrypt-<target>.sha256`, a cosign keyless signature bundle (`.sigstore.json`), and a GitHub build-provenance attestation. The release notes carry three operator instructions: how to verify a download (`cosign verify-blob` and `gh attestation verify`), the one-line `xattr -d com.apple.quarantine` command macOS requires before running an unsigned download, and the one-line `cargo build --release -p backvault-decrypt` for operators who would rather build than download. Apple notarization is not used; it would require an Apple Developer account for a tool whose provenance is already attested.

## CI Pipeline

| Trigger | Workflow | Steps |
|---------|----------|-------|
| pull request | `test.yml` | `cargo fmt --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace --locked` (format fixtures and restore-tool subprocess tests included); build the amd64 image; run `backvault --version` from the image under the default seccomp profile |
| push to main | `docker-publish.yml` → `supply-chain.yml` | Socket scan (skipped when the API-key secret is absent); OSV scan of `Cargo.lock`; `cargo-deny` advisories, licences, and bans |
| push to main (after scan) | `docker-publish.yml` | build and push `latest` and `main-<sha>` to `ghcr.io/tgrecojr/backvault`; cosign keyless sign by digest; SPDX SBOM via anchore; `actions/attest` for the SBOM; `attest-build-provenance`; both pushed to the registry |
| tag `v*` | `release.yml` | the restore tool matrix above |
| weekly / manual | `ghcr-retention.yml` | keep `latest` plus the 5 most recent tagged versions; delete untagged |

The Socket step is optional by design: bot-authored PRs (Renovate) run without repository secrets, and a required secret would fail the reusable workflow before any scan ran.

The image smoke test runs `--version` because the service otherwise never exits: with no credentials it logs a failed cycle and sleeps. A successful `--version` from inside the distroless static image proves the binary is static and runs under the default seccomp profile.

## Dependency Policy

`renovate.json` extends `config:recommended` with semantic commits, a dependency dashboard, and a night/weekend schedule. Rules:

- Pin digests for every Docker image reference.
- Group all minor and patch updates into one PR, automerge after a 3-day minimum release age; crates follow this group.
- Automerge digest-only updates immediately.
- Never automerge majors; label them `major-update`.
- Keep the Rust builder image tag and `rust-toolchain.toml` on the same version in one PR, so the image build and the developer toolchain never diverge.
- Lock-file maintenance weekly (`Cargo.lock`).

`deny.toml` holds the `cargo-deny` policy: advisories fail the build, licences are restricted to a permissive allow-list, and duplicate crate versions are warned.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Runtime base | Chainguard `static` (Wolfi) | `scratch`; Chainguard `glibc-dynamic`; Alpine; `python` images | Nothing executable in the image, so a scanner has nothing to find but the project's own binary; unlike `scratch` it still carries a passwd file and CA bundle should either ever be wanted. |
| Builder base | Official `rust:<ver>-alpine` by digest | Chainguard `rust` (glibc, no musl target); `cross`; building on the host and copying in | Musl is the image's native target, so a static binary needs no cross-linker and no extra downloads; the image is digest-pinned like every other. |
| Toolchain file in the image build | Not copied; the builder uses its image's toolchain | Copy it and let rustup fetch the pinned toolchain | A rustup fetch is an unpinned build-time download (tenet: *Pinned beats fresh*); Renovate keeps the image tag and the file on one version instead. |
| Third-party executables | None | — | The image holds exactly one file the project built; the restore tool stays out because the image has no shell to run it from and restoring must not depend on the image. |
| Dependency install | `cargo build --locked` | Vendored crates (`cargo vendor`) | The lock is what OSV and cargo-deny scan; vendoring would bloat the repository for no additional pinning. |
| Platform | `linux/amd64` only | Multi-arch with QEMU or native arm runners | Simplifies deployment; the restore tool, not the service, is what must run everywhere. |
| Publication trust | cosign keyless + SPDX SBOM + provenance attestations for the image; sha256 + cosign blob signature + provenance for each binary | Unsigned; key-based cosign; Apple notarization | Verifiable origin without managing signing keys or an Apple Developer account. |
| Restore tool platforms | macOS arm64 and x86_64, Linux x86_64 and arm64 | Windows; Linux glibc builds | The operator's laptop is a Mac or a Linux box; musl static binaries run on any Linux regardless of libc. |
| Restore tool verification before release | The tool's own subprocess test suite runs on every target in the matrix | Build only | A binary that was never executed on its target platform is not a tested release. |
| Vulnerability scanning | OSV on `Cargo.lock` plus `cargo-deny` | `cargo audit` alone; Trivy on the image | `cargo-deny` adds licence and duplicate checks to the advisory scan; the image has nothing to scan but the binary. |
| Automerge policy | Minor/patch grouped after 3 days; digests immediate; majors reviewed | Automerge everything; review everything | Keeps low-risk churn off the maintainer while majors get eyes. |
| Non-root | `USER 1000:1000` in the image; `${UID}:${GID}` in compose | Root; the image's `nonroot` (65532) | Least privilege; mounted-volume ownership matches the host user. |
| Seccomp | Docker's default profile | `seccomp=unconfined`; a custom profile | Nothing in the image needs a non-default syscall; the default profile is the one operators get without reading documentation. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **Documentation describes what ships.** README, BUILD.md, CONTRIBUTING.md, and the release notes cover the Rust image, the restore-tool download, verification, the macOS quarantine step, and the build-from-source route; the obsolete GitHub Actions setup guide is gone.

### Deferred
1. **Health check.** No `HEALTHCHECK`; depends on scheduler-retention exposing a heartbeat.
2. **Pin GitHub Actions by digest.** Actions are pinned by major tag; the `helpers:pinGitHubActionDigests` preset would pin them by digest at the cost of more Renovate traffic.
3. **Argon2id memory.** Document compose `deploy.resources` guidance for accounts whose KDF uses large memory settings.
4. **Stop grace period.** Whether the Compose reference documents a longer `stop_grace_period` for slow vaults is scheduler-retention's call.

## Cascade Notes

- **backup-encryption**: owns what the restore tool does; this segment only builds, tests, signs, and publishes it.
- **scheduler-retention**: the service binary must answer `--version` so the image can be smoke-tested without credentials.
- **vault-access**: the pure-Rust crypto stack is what lets the musl static build need no C toolchain.

## References

- Chainguard static image: https://images.chainguard.dev/directory/image/static/overview
- Official Rust images: https://hub.docker.com/_/rust
- cosign blob signing: https://docs.sigstore.dev/cosign/signing/signing_with_blobs/
- GitHub artifact attestations: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations
- cargo-deny: https://embarkstudios.github.io/cargo-deny/
- Renovate configuration: https://docs.renovatebot.com/configuration-options/
- Sibling segments: backup-encryption (the restore tool), scheduler-retention (the entrypoint this image runs), backup-cycle (owns `BW_CA_CERT` intake)
