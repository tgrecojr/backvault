# Building BackVault

Two artifacts come out of this repository: the service container image, and the `backvault-decrypt` restore tool.

## The service image

The image is built for **Linux x86_64 (amd64)** only. It contains one statically linked executable in a distroless static base: no shell, no package manager, no interpreter.

```bash
# Linux
docker build -t backvault:local .

# macOS (Apple Silicon or Intel): the image is amd64, so name the platform
docker build --platform linux/amd64 -t backvault:local .
```

On Apple Silicon the build runs under emulation and takes several minutes the first time; later builds reuse the cargo cache mounts.

### Verifying the image

There is no shell inside, so the only thing to run is the binary itself:

```bash
docker run --rm backvault:local --version
# backvault 1.0.0

docker image inspect backvault:local | grep Architecture
# "amd64"
```

`--version` can only succeed if the binary is truly static and runs under Docker's default seccomp profile; CI runs the same command as its smoke test. No `--security-opt` is ever needed.

### What the build downloads

Nothing beyond the two digest-pinned base images and the crates pinned in `Cargo.lock`. The Rust-on-Alpine builder already ships gcc and musl-dev, and `.dockerignore` keeps `rust-toolchain.toml` out of the build so rustup never fetches a toolchain.

## The restore tool

```bash
cargo build --release -p backvault-decrypt
# target/release/backvault-decrypt
```

That is the whole build. With `rustup` installed, `rust-toolchain.toml` selects the pinned toolchain automatically. The result is a self-contained executable for the machine you built it on; for a static Linux binary add `--target x86_64-unknown-linux-musl` (with `musl-tools` installed) or download the release asset instead.

Releases are built by `.github/workflows/release.yml` on every `v*` tag for macOS (arm64, x86_64) and Linux (x86_64, arm64), tested on each target, signed with cosign, and attested with build provenance. See the release notes for verification commands.

## Common issues

**"exec format error" on an Apple Silicon Mac** when running the image: it is amd64. Add `--platform linux/amd64` to `docker run`, or `platform: linux/amd64` under the service in `docker-compose.yml`.

**TLS verification fails against a self-signed server**: mount your CA bundle into the container and set `BW_CA_CERT` to its path. The roots compiled into the binary are Mozilla's; the bundle is trusted in addition to them. There is no option to disable verification.

**Force a rebuild without cache**:

```bash
docker build --no-cache --platform linux/amd64 -t backvault:local .
```

## Production

Use the published image:

```yaml
services:
  backvault:
    image: ghcr.io/tgrecojr/backvault:latest
```

Every push to `main` scans the lock file (OSV, cargo-deny, Socket), builds the amd64 image, signs it with cosign, and publishes it with an SPDX SBOM and build-provenance attestation to `ghcr.io/tgrecojr/backvault`.
