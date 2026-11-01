## backvault-decrypt

The standalone restore tool. Download the binary for the machine in front of you; nothing else needs to be installed.

| Machine | Asset |
|---|---|
| macOS, Apple Silicon | `backvault-decrypt-aarch64-apple-darwin` |
| macOS, Intel | `backvault-decrypt-x86_64-apple-darwin` |
| Linux, x86_64 (any distribution; statically linked) | `backvault-decrypt-x86_64-unknown-linux-musl` |
| Linux, arm64 (any distribution; statically linked) | `backvault-decrypt-aarch64-unknown-linux-musl` |

### Verify the download

Each binary ships with a SHA-256 checksum, a Sigstore signature bundle, and a GitHub build-provenance attestation.

```bash
# checksum
sha256sum -c backvault-decrypt-<target>.sha256        # Linux
shasum -a 256 -c backvault-decrypt-<target>.sha256    # macOS

# signature (cosign)
cosign verify-blob \
  --bundle backvault-decrypt-<target>.sigstore.json \
  --certificate-identity-regexp 'https://github.com/tgrecojr/backvault/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  backvault-decrypt-<target>

# provenance (GitHub CLI)
gh attestation verify backvault-decrypt-<target> --repo tgrecojr/backvault
```

### macOS: clear the quarantine flag

macOS marks downloaded executables as quarantined and refuses to run them until the flag is removed. The binary is not notarized with Apple; its provenance is attested above instead.

```bash
xattr -d com.apple.quarantine backvault-decrypt-<target>
chmod +x backvault-decrypt-<target>
```

### Restore

```bash
./backvault-decrypt-<target> backup_20260101_120000.enc > vault.json
```

You are prompted for the backup file password. Import `vault.json` through the web vault: **Settings → Import data → Bitwarden (json)**.

### Build it yourself instead

With a Rust toolchain installed (`rustup`), the same binary builds from the repository in one command:

```bash
git clone https://github.com/tgrecojr/backvault.git
cd backvault
cargo build --release -p backvault-decrypt
# target/release/backvault-decrypt
```
