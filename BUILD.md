# Building BackVault Docker Images

This guide explains how to build BackVault Docker images for Linux x86_64.

## Platform Support

BackVault is designed for **Linux x86_64 (amd64) only**. This simplifies deployment and ensures compatibility with most server environments.

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
docker-compose build
```

---

## Verifying Your Build

### Check the Built Image

During build, you'll see:
```
Installing Bitwarden CLI version: 2024.10.2 for Linux x86_64
```

### Test the Built Image

```bash
# Check the binary architecture
docker run --rm --entrypoint /bin/bash backvault:latest -c "file /usr/local/bin/bw"

# Should show: "ELF 64-bit LSB executable, x86-64"
```

### Run a Quick Test

```bash
docker run --rm \
  --security-opt seccomp=unconfined \
  --entrypoint /usr/local/bin/bw \
  backvault:latest \
  --version
```

---

## Common Issues

### Issue: "exec format error" on macOS ARM (M1/M2/M3)

**Symptom:**
```
exec user process caused: exec format error
```

**Cause:** You're running an x86_64 image on ARM architecture without emulation

**Solution:** Use the `--platform` flag:
```bash
docker run --platform linux/amd64 --rm backvault:latest
```

Or in docker-compose.yml:
```yaml
services:
  backvault:
    platform: linux/amd64
    # ...
```

### Issue: Binary fails at runtime with SIGTRAP

**Cause:** Docker's seccomp security profile

**Solution:** Add to docker-compose.yml:
```yaml
security_opt:
  - seccomp=unconfined
```

---

## Best Practices

### Local Development

```bash
# Build the image
docker build -t backvault:dev .

# Test it
docker-compose up
```

### Production Deployment

**Option 1: Use Pre-Built Images (Recommended)**
```yaml
# docker-compose.yml
services:
  backvault:
    image: ghcr.io/yourusername/backvault:latest
    # ...
```

**Option 2: Build on Target Server**
```bash
# Build directly on the server
ssh user@server
git clone https://github.com/yourusername/backvault.git
cd backvault
docker build -t backvault:latest .
```

---

## GitHub Actions Builds

The repository includes GitHub Actions that automatically build Docker images for Linux x86_64:

**To use:**
1. Push to main branch
2. Wait for build (~5-10 minutes)
3. Pull and use: `docker pull ghcr.io/yourusername/backvault:latest`

---

## Troubleshooting

### Force Rebuild Without Cache

```bash
docker build --no-cache -t backvault:latest .
```

### Check Image Architecture

```bash
docker image inspect backvault:latest | grep Architecture
# Should show: "amd64"
```

---

## Summary

- **Platform**: Linux x86_64 (amd64) only
- **Building on Linux**: `docker build -t backvault:latest .`
- **Building on macOS**: `docker build --platform linux/amd64 -t backvault:latest .`
- **Production**: Use pre-built images from GitHub Container Registry

---

**Need Help?**
- Check the build logs for "Installing Bitwarden CLI version" message
- Verify the binary architecture is x86_64
- Use GitHub Actions for production builds (recommended)
