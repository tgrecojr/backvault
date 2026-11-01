# 🗄️ BackVault

**BackVault** is a lightweight Dockerized service that periodically backs up your **Bitwarden** or **Vaultwarden** vaults into password-protected encrypted files.  
It’s designed for hands-free, secure, and automated backups. BackVault talks to the Bitwarden API directly and decrypts your vault in memory, so the image contains nothing but Python.

---

## 🚀 Features

- 🔒 Securely exports your vault using your Bitwarden credentials
- 🕐 **Interval-based backup scheduling** — configure backup frequency in hours
- 💾 Password-protected backup files using AES encryption
- 🧹 **Automated Cleanup**: Automatically deletes old backups daily at midnight based on configurable retention period
- ✨ **Portable Encryption**: Standard AES-256-GCM with Argon2id, restorable with a small Python script and no Bitwarden tooling
- 🔐 **Security Hardened**: Distroless image with no third-party binaries, non-root execution, default Docker seccomp profile, no secrets on the command line, retry logic with exponential backoff
- 🌐 Works with both Bitwarden Cloud and self-hosted Bitwarden/Vaultwarden
- 🐧 **Linux x86_64 Support**: Optimized for standard Linux servers
- 🐳 Runs fully containerized — no setup or local dependencies required

---

## 📦 Quick Start (Docker)

You can run BackVault directly using the **published Docker image**, no build required.

**Available Images:**
- GitHub Container Registry: `ghcr.io/tgrecojr/backvault:latest`
- Platform: Linux x86_64 (amd64)

```bash
docker run -d \
  --name backvault \
  -e BW_CLIENT_ID="your_client_id" \
  -e BW_CLIENT_SECRET="your_client_secret" \
  -e BW_PASSWORD="your_master_password" \
  -e BW_SERVER="https://vault.yourdomain.com" \
  -e BW_FILE_PASSWORD="backup_encryption_password" \
  -e BACKUP_INTERVAL_HOURS=12 \
  -v /path/to/backup:/app/backups \
  ghcr.io/tgrecojr/backvault:latest
```

> 🔑 **Important**: Your credentials are used only to authenticate to your own server and to decrypt the vault inside the container. They are **never stored** persistently and **never sent** anywhere else. The master password never leaves the process.

---

## 🧩 Docker Compose Example

Here’s how to set it up with Docker Compose for easy management:

```yaml
services:
  backvault:
    image: ghcr.io/tgrecojr/backvault:latest
    container_name: backvault
    restart: unless-stopped

    # Run as current user to avoid permission issues with mounted volumes
    user: "${UID:-1000}:${GID:-1000}"

    environment:
      BW_CLIENT_ID: "your_client_id"
      BW_CLIENT_SECRET: "your_client_secret"
      BW_PASSWORD: "your_master_password"
      BW_SERVER: "https://vault.yourdomain.com"
      BW_FILE_PASSWORD: "backup_encryption_password"
      BACKUP_INTERVAL_HOURS: 12
      RETAIN_DAYS: 7

      # Self-signed server: mount your CA bundle and point at it
      # BW_CA_CERT: /app/ca.pem

    volumes:
      - ./backups:/app/backups
      # - ./ca.pem:/app/ca.pem:ro
```

Then run:

```bash
docker compose up -d
```

BackVault will automatically:

1. Authenticate to your Bitwarden/Vaultwarden instance with your API key
2. Decrypt your vault in memory with your master password and build a Bitwarden-format JSON export
3. Encrypt it using `BW_FILE_PASSWORD`
4. Store the backup in `/app/backups` (mounted to your host directory)
5. Discard every key and token when the cycle ends

---

## ⚙️ Configuration

| Variable                       | Description                                    | Required | Default | Example                     |
| ------------------------------ | ---------------------------------------------- | -------- | ------- | --------------------------- |
| `BW_CLIENT_ID`                 | Bitwarden client ID for API authentication     | ✅        | -       | `xxxx-xxxx-xxxx-xxxx`       |
| `BW_CLIENT_SECRET`             | Bitwarden client secret                        | ✅        | -       | `your_client_secret`        |
| `BW_PASSWORD`                  | Master password for your vault                 | ✅        | -       | `supersecret`               |
| `BW_SERVER`                    | Bitwarden or Vaultwarden server URL            | ✅        | -       | `https://vault.example.com` |
| `BW_FILE_PASSWORD`             | Password to encrypt exported backup file       | ✅        | -       | `strong_backup_password`    |
| `BACKUP_INTERVAL_HOURS`        | Backup frequency in hours                      | ❌        | `12`    | `12`                        |
| `BACKUP_DIR`                   | Directory path for storing backups             | ❌        | `/app/backups` | `/app/backups`         |
| `RETAIN_DAYS`                  | Days to keep backups. Set to `0` to disable cleanup | ❌  | `7`     | `7`                         |
| `BW_CA_CERT`                   | Path to a PEM CA bundle to trust for a self-signed server (mount it into the container) | ❌ | - | `/app/ca.pem` |

---

## 🔒 Security Considerations

### Master Password Storage

**Important**: BackVault requires your Bitwarden master password (`BW_PASSWORD`) because the vault is encrypted with a key derived from it. The password is used inside the container to derive that key; it is never sent to the server.

**Current Implementation:**
- Password is passed via environment variable and read once per backup cycle
- Never logged, never placed on a command line, never stored persistently
- Every derived key and the access token are discarded when the cycle ends

**⚠️ Security Risks:**
- Environment variables are visible in `docker inspect <container>`
- May appear in container orchestration logs
- Stored in plain text in docker-compose.yml files

**Recommendations:**
1. **For production use**, consider using Docker Secrets or Kubernetes Secrets instead of environment variables
2. Store your `docker-compose.yml` and `.env` files securely with appropriate file permissions
3. Use a dedicated backup password (`BW_FILE_PASSWORD`) different from your master password
4. Regularly rotate your API keys and passwords
5. Limit access to the backup directory with proper file system permissions

> 📋 **Note**: There is an open issue to add support for file-based secrets (e.g., `BW_PASSWORD_FILE`) as a more secure alternative. See the GitHub issues for details.

### Additional Security Features

- **Non-root, distroless, binary-free**: Chainguard distroless Python runtime as UID 1000, no shell, no third-party executables, default Docker seccomp profile
- **Pinned supply chain**: base images pinned by digest, Python packages by lock file, images signed with cosign and shipped with SBOM and provenance attestations
- **Short-lived secrets**: keys and tokens exist only for one backup cycle
- **Retry logic**: exponential backoff on transient network and server errors; no retry on rejected credentials
- **Strong encryption**: AES-256-GCM with an Argon2id-derived key for every backup file

---

## 🔐 Decrypting Backups

Backups are plain files encrypted with a standard, portable scheme: **AES-256-GCM** with a key derived from `BW_FILE_PASSWORD` using **Argon2id**. You **do not need the Bitwarden CLI** or network access to decrypt one, which is what makes them useful for disaster recovery. The decrypted content is Bitwarden's standard JSON export, which you restore through the web vault's **Settings → Import data → Bitwarden (json)**.

**File Structure:**
The resulting `.enc` file contains: `[4-byte version][16-byte salt][12-byte nonce][encrypted data + 16-byte auth tag]`

**Version History:**
- **Version 2** (Current): Argon2id key derivation (time_cost=3, memory_cost=64MB, parallelism=4) - Resistant to GPU/ASIC attacks
- **Version 1** (Legacy): PBKDF2-HMAC-SHA256 iterations: 600,000 (OWASP 2023 recommendation)

**How to Decrypt (Python Script):**

Here is a simple Python script to decrypt the file. You only need the `cryptography` and `argon2-cffi` libraries.

1.  Save the code below as `decrypt.py`.
2.  Install the dependencies: `pip install cryptography argon2-cffi`.
3.  Run the script: `python decrypt.py /path/to/backup.enc` (you will be prompted for the password)

The script supports both Version 1 (PBKDF2) and Version 2 (Argon2id) encrypted files automatically.

```python
# decrypt.py
import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from argon2.low_level import Type, hash_secret_raw

SALT_SIZE = 16
KEY_SIZE = 32

# Version 1: PBKDF2-HMAC-SHA256
PBKDF2_ITERATIONS = 600000  # OWASP 2023 recommendation

# Version 2: Argon2id
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB in KiB
ARGON2_PARALLELISM = 4

def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    # Read version header (4 bytes)
    version_num = int.from_bytes(encrypted_data[:4], byteorder="big")
    offset = 4

    salt = encrypted_data[offset:offset+SALT_SIZE]
    nonce = encrypted_data[offset+SALT_SIZE:offset+SALT_SIZE+12]
    ciphertext_with_tag = encrypted_data[offset+SALT_SIZE+12:]

    # Derive key based on version
    if version_num == 1:
        # Legacy PBKDF2 format
        print(f"Decrypting version {version_num} file (PBKDF2-HMAC-SHA256, {PBKDF2_ITERATIONS:,} iterations)", file=sys.stderr)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS
        )
        key = kdf.derive(password.encode("utf-8"))
    elif version_num == 2:
        # Current Argon2id format
        print(f"Decrypting version {version_num} file (Argon2id, {ARGON2_MEMORY_COST // 1024} MB)", file=sys.stderr)
        key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=KEY_SIZE,
            type=Type.ID,
        )
    else:
        raise ValueError(f"Unsupported encryption version: {version_num}")

    # Decrypt using AES-GCM
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <encrypted_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    password = getpass("Enter backup password: ")

    try:
        with open(file_path, "rb") as f:
            encrypted_contents = f.read()

        decrypted_json = decrypt_data(encrypted_contents, password)
        print(decrypted_json.decode("utf-8"))
        print("\nDecryption successful.", file=sys.stderr)
    except InvalidTag:
        print("Decryption failed: Invalid password or corrupted file.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)
```

---

## 🧠 Tips

* **Store `BW_FILE_PASSWORD` securely** — it's required for restoring backups and cannot be recovered if lost
* You can run this container alongside Vaultwarden on the same host or a separate machine
* Combine with tools like `restic` or `rclone` to push backups to cloud storage for offsite protection
* Test your backup restoration process periodically to ensure you can recover your data
* The container performs an initial backup immediately on startup, then follows the configured interval
* Cleanup runs automatically at midnight each day (container time), deleting backups older than `RETAIN_DAYS`

---

## 🐳 Updating

To update to the latest version:

```bash
docker pull ghcr.io/tgrecojr/backvault:latest
```

If using docker compose:
```bash
docker compose pull
docker compose up -d
```

---

## 🔄 CI/CD and Automated Builds

BackVault uses GitHub Actions for automated building and publishing:

### Automated Workflows

- **Docker Publish**: Scans dependencies (Socket, OSV, pip-audit), then builds, signs (cosign), and publishes Linux x86_64 images with SBOM and provenance attestations on merge to main
- **Test**: Runs linting, unit tests, and a Docker build smoke test on all PRs
- **GHCR retention**: Prunes old image versions weekly

### Platform Support

Images are built for:
- `linux/amd64` - Linux x86_64 systems

### Using Specific Versions

```bash
# Use latest version
docker pull ghcr.io/tgrecojr/backvault:latest

# Use specific version (when tagged)
docker pull ghcr.io/tgrecojr/backvault:v1.0.0
```

### Building Locally

**On Linux:**
```bash
docker build -t backvault:local .
```

**On macOS:**
```bash
# Specify linux/amd64 platform for deployment
docker build --platform linux/amd64 -t backvault:local .
```

For comprehensive build documentation including troubleshooting, see **[BUILD.md](BUILD.md)**.

---

## 🪪 License

This project is licensed under the **AGPL-3.0 License**.
See LICENSE for details.

---

## 🧪 Development & Testing

### Running Tests

BackVault uses [uv](https://docs.astral.sh/uv/) for Python environment and dependency management and pytest for testing:

```bash
# Install development dependencies (creates .venv and installs from uv.lock)
uv sync --frozen

# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Run with coverage
uv run pytest --cov=src --cov-report=html
```

### Test Suite

Our comprehensive test suite includes:
- **Encryption/Decryption Tests**: Argon2id implementation and PBKDF2 backward compatibility
- **Security Property Tests**: Random salt/nonce generation, password validation
- **Edge Case Tests**: Empty data, large files (1MB+), unicode passwords

All tests run automatically in CI/CD on every push and pull request.

### Code Quality

```bash
# Run linting
uv run ruff check src/

# Auto-format code
uv run ruff format src/
```

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for detailed development guidelines.

---

## 📚 Additional Documentation

- **[BUILD.md](BUILD.md)** - Platform-specific build instructions and troubleshooting
- **[SECURITYASSESS.md](SECURITYASSESS.md)** - Comprehensive security assessment and audit results
- **[CONTRIBUTING.md](.github/CONTRIBUTING.md)** - Guidelines for contributing to the project

---

## 🤝 Contributing

Pull requests and issue reports are welcome!
Feel free to open a PR or discussion on GitHub.

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for guidelines.

---

**BackVault** — secure, automated, encrypted vault backups.
