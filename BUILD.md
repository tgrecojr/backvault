# Building BackVault Docker Images

This guide explains how to build BackVault Docker images for Linux x86_64.

## Platform Support

BackVault is built for **Linux x86_64 (amd64)**. The image has no platform-specific binaries, so other architectures are a CI change rather than a packaging problem, but only amd64 is published today.

## Quick Commands

### Building on Linux

```bash
docker build -t backvault:latest .
```

### Building on macOS

```bash
# Specify linux/amd64 platform
docker build --platform linux/amd64 -t backvault:latest .
```

### Using Docker Compose

```bash
docker compose build
```

---

## Verifying Your Build

The runtime image is distroless: there is no shell, so verification runs the Python interpreter directly.

```bash
# Interpreter present
docker run --rm --entrypoint /app/.venv/bin/python backvault:latest --version

# Application modules import
docker run --rm --entrypoint /app/.venv/bin/python backvault:latest \
  -c "import vault_client, backup_crypto, run; print('ok')"

# Image architecture
docker image inspect backvault:latest | grep Architecture
# Should show: "amd64"
```

No `--security-opt` is needed; the container runs under Docker's default seccomp profile.

---

## Common Issues

### Issue: "exec format error" on macOS ARM (M1/M2/M3)

**Cause:** You're running an x86_64 image on ARM architecture without emulation.

**Solution:** Use the `--platform` flag:
```bash
docker run --platform linux/amd64 --rm backvault:latest
```

Or in docker-compose.yml:
```yaml
services:
  backvault:
    platform: linux/amd64
```

### Issue: TLS verification fails against a self-signed server

**Cause:** The server's certificate is not signed by a CA in the image's trust store.

**Solution:** Mount your CA bundle into the container and set `BW_CA_CERT` to its path. There is no option to disable verification.

---

## Best Practices

### Local Development

```bash
docker build -t backvault:dev .
docker compose up
```

### Production Deployment

**Option 1: Use Pre-Built Images (Recommended)**
```yaml
services:
  backvault:
    image: ghcr.io/tgrecojr/backvault:latest
```

**Option 2: Build on Target Server**
```bash
git clone https://github.com/tgrecojr/backvault.git
cd backvault
docker build -t backvault:latest .
```

---

## GitHub Actions Builds

On every push to `main`, GitHub Actions scans the locked dependencies, builds the Linux x86_64 image, signs it with cosign, and publishes it with SBOM and provenance attestations to `ghcr.io/tgrecojr/backvault`.

---

## Troubleshooting

### Force Rebuild Without Cache

```bash
docker build --no-cache -t backvault:latest .
```

---

## Summary

- **Platform**: Linux x86_64 (amd64)
- **Building on Linux**: `docker build -t backvault:latest .`
- **Building on macOS**: `docker build --platform linux/amd64 -t backvault:latest .`
- **Production**: Use pre-built images from GitHub Container Registry
