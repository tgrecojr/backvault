# 🗄️ BackVault

**BackVault** is a small Dockerized service that periodically backs up your **Bitwarden** or **Vaultwarden** vault into password-protected encrypted files, and a standalone **restore tool** that opens them on whatever machine you have when the vault host is gone.

It is built for disaster recovery: after a Vaultwarden rebuild, you decrypt the newest backup with `backvault-decrypt` and import it through the web vault. Nothing in that path depends on the server you lost.

---

## 🚀 Features

- 🔒 Talks to the Bitwarden API directly with your API key and decrypts the vault in memory; no Bitwarden CLI, no third-party binary
- 🕐 **Interval scheduling**: one backup immediately on start, then every `BACKUP_INTERVAL_HOURS`
- 💾 **Portable encryption**: AES-256-GCM with an Argon2id-derived key, a documented byte layout, restorable with one self-contained binary
- 🧹 **Retention**: prunes backups older than `RETAIN_DAYS` once per UTC day
- 🔐 **Hardened by construction**: one statically linked Rust binary in a distroless static image, non-root, default Docker seccomp profile, every secret in zeroizing memory, nothing on the command line
- 🌐 Works with Bitwarden Cloud and self-hosted Bitwarden or Vaultwarden, including self-signed servers via `BW_CA_CERT`
- 🐧 Linux x86_64 image; restore tool for macOS and Linux

---

## 📦 Quick Start (Docker)

```bash
docker run -d \
  --name backvault \
  -e BW_CLIENT_ID="user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  -e BW_CLIENT_SECRET="your_client_secret" \
  -e BW_PASSWORD="your_master_password" \
  -e BW_SERVER="https://vault.yourdomain.com" \
  -e BW_FILE_PASSWORD="backup_encryption_password" \
  -e BACKUP_INTERVAL_HOURS=12 \
  -v /path/to/backup:/app/backups \
  ghcr.io/tgrecojr/backvault:latest
```

> 🔑 Your credentials authenticate to your own server and derive keys inside the container. The master password never leaves the process, nothing is stored, and every key and token is wiped when the cycle ends.

---

## 🧩 Docker Compose

```yaml
services:
  backvault:
    image: ghcr.io/tgrecojr/backvault:latest
    container_name: backvault
    restart: unless-stopped
    user: "${UID:-1000}:${GID:-1000}"
    environment:
      BW_CLIENT_ID: "${BW_CLIENT_ID}"
      BW_CLIENT_SECRET: "${BW_CLIENT_SECRET}"
      BW_PASSWORD: "${BW_PASSWORD}"
      BW_SERVER: "${BW_SERVER}"
      BW_FILE_PASSWORD: "${BW_FILE_PASSWORD}"
      BACKUP_INTERVAL_HOURS: "${BACKUP_INTERVAL_HOURS:-12}"
      RETAIN_DAYS: "${RETAIN_DAYS:-7}"
      # Self-signed server: mount your CA bundle (see volumes) and point at it.
      # BW_CA_CERT: /app/ca.pem
    volumes:
      - ./backups:/app/backups
      # - ./ca.pem:/app/ca.pem:ro
```

```bash
docker compose up -d
```

Each cycle authenticates with your API key, derives the master key from your password, unwraps the vault key, pulls `/api/sync`, decrypts every item locally, builds a Bitwarden-format JSON export, encrypts it with `BW_FILE_PASSWORD`, and writes `backup_<UTC timestamp>.enc` to `/app/backups`. A file carries the `.enc` name only once it is complete and synced to disk.

---

## ⚙️ Configuration

| Variable | Description | Required | Default |
|---|---|---|---|
| `BW_CLIENT_ID` | User API key client ID (`user.<uuid>`); organization keys cannot unlock a personal vault | ✅ | - |
| `BW_CLIENT_SECRET` | API key client secret | ✅ | - |
| `BW_PASSWORD` | Master password; used only to derive keys locally | ✅ | - |
| `BW_SERVER` | Server URL, `https://` only. `https://vault.bitwarden.com` and `.eu` are recognised as Bitwarden Cloud | ✅ | - |
| `BW_FILE_PASSWORD` | Password that encrypts each backup file | ✅ | - |
| `BACKUP_INTERVAL_HOURS` | Hours between backups, 1 to 8760 | ❌ | `12` |
| `BACKUP_DIR` | Backup directory; must lie under `/app` | ❌ | `/app/backups` |
| `RETAIN_DAYS` | Days to keep backups; `0` disables cleanup | ❌ | `7` |
| `LOG_FILE` | Also append log lines to this file | ❌ | - |
| `BW_CA_CERT` | PEM bundle to trust in addition to Mozilla's roots, for a self-signed server (mount it) | ❌ | - |

Passwords are used as the exact bytes you set, with no trimming or normalisation, because a re-encoded password derives a different key.

---

## 🔐 Restoring a backup

Backups are plain files in a documented format: `[4-byte version][16-byte salt][12-byte nonce][AES-256-GCM ciphertext + 16-byte tag]`, keyed by Argon2id (version 2) or PBKDF2-HMAC-SHA256 (version 1, legacy, still readable). The decrypted content is Bitwarden's standard JSON export.

### 1. Get the restore tool

Download `backvault-decrypt` for your machine from the [latest release](https://github.com/tgrecojr/backvault/releases/latest):

| Machine | Asset |
|---|---|
| macOS, Apple Silicon | `backvault-decrypt-aarch64-apple-darwin` |
| macOS, Intel | `backvault-decrypt-x86_64-apple-darwin` |
| Linux x86_64 | `backvault-decrypt-x86_64-unknown-linux-musl` |
| Linux arm64 | `backvault-decrypt-aarch64-unknown-linux-musl` |

Each asset ships with a `.sha256` checksum, a Sigstore signature bundle, and a GitHub provenance attestation:

```bash
sha256sum -c backvault-decrypt-<target>.sha256     # shasum -a 256 -c on macOS
cosign verify-blob --bundle backvault-decrypt-<target>.sigstore.json \
  --certificate-identity-regexp 'https://github.com/tgrecojr/backvault/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  backvault-decrypt-<target>
gh attestation verify backvault-decrypt-<target> --repo tgrecojr/backvault
```

On macOS, clear the download quarantine flag before the first run (the binary is attested, not Apple-notarized):

```bash
xattr -d com.apple.quarantine backvault-decrypt-<target>
chmod +x backvault-decrypt-<target>
```

Prefer to build it yourself? With a Rust toolchain installed:

```bash
git clone https://github.com/tgrecojr/backvault.git && cd backvault
cargo build --release -p backvault-decrypt      # target/release/backvault-decrypt
```

### 2. Decrypt

```bash
./backvault-decrypt backup_20260101_120000.enc > vault.json
```

You are prompted for `BW_FILE_PASSWORD`. The plaintext goes to stdout and nothing else does, so the redirect yields a byte-exact export. In a script, pipe the password on stdin instead: `echo "$PW" | ./backvault-decrypt file.enc > vault.json`. Exit status is 0 on success, 1 on a wrong password or bad file, 2 on a usage error.

### 3. Import

Web vault → **Settings → Import data → Bitwarden (json)** → choose `vault.json`.

---

## 🔒 Security notes

- **Master password**: required because the vault key is wrapped by a key derived from it. It is read from the environment once per cycle, used in memory, never logged, never sent to the server, and wiped afterwards.
- **Environment variables** are visible to `docker inspect` and to anyone who can read your Compose file. Keep those files private, use a dedicated `BW_FILE_PASSWORD` that differs from your master password, and rotate API keys. File-based secrets are an open request.
- **Image**: Chainguard distroless static base as UID 1000, one static binary, no shell, default seccomp profile, every input pinned by digest or lock file, signed with cosign and shipped with an SBOM and provenance attestation.
- **TLS**: always verified against Mozilla's root store compiled into the binary; `BW_CA_CERT` adds a bundle, nothing disables verification.
- **Failures**: a vault that cannot be reached is retried three times with back-off and then logged; the next interval runs regardless. A field that cannot be decrypted is exported as `[error: cannot decrypt]`, exactly as the Bitwarden CLI does, and counted in the log.

---

## 🧠 Tips

- **Keep `BW_FILE_PASSWORD` somewhere safe**: without it a backup cannot be opened, and it cannot be recovered.
- Cleanup runs after the first backup that completes on a new UTC calendar day, so with a 12-hour interval it lands up to 12 hours after midnight UTC.
- Items with attachments are backed up without the attachments; no Bitwarden export format carries them. The log says how many.
- Combine with `restic` or `rclone` to push the `.enc` files off-site.
- Test a restore now and then. A backup you have never opened is a hope, not a backup.

---

## 🐳 Updating

```bash
docker compose pull && docker compose up -d
```

---

## 🔄 CI/CD

- **Test** on every pull request: `cargo fmt`, `cargo clippy` with warnings denied, `cargo test` for the whole workspace, an amd64 image build, and a `--version` smoke run under the default seccomp profile.
- **Publish** on every merge to `main`: Socket, OSV, and cargo-deny scans of `Cargo.lock`, then build, cosign sign, SBOM, provenance, push to `ghcr.io/tgrecojr/backvault` as `latest` and `main-<sha>`.
- **Release** on every `v*` tag: the restore tool for four targets, tested on each, signed and attested, attached to a GitHub Release.
- **GHCR retention** weekly: keep `latest` plus the five most recent tagged versions.

See **[BUILD.md](BUILD.md)** for building locally and **[CONTRIBUTING.md](.github/CONTRIBUTING.md)** for the development workflow.

---

## 🪪 License

AGPL-3.0. See LICENSE.
