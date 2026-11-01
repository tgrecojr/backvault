---
parent: high-level-design
prefix: ENC
---

# backup-encryption

## Context and Design Philosophy

A BackVault backup is only useful if it can be opened after the server it came from is gone. backup-encryption defines the on-disk format of a backup, implements it once in the `backvault-format` library crate, and ships the `backvault-decrypt` binary that opens a backup on the operator's own machine. Three commitments shape it:

- **Portable by construction.** The format uses only standard primitives (Argon2id, AES-256-GCM, and for legacy files PBKDF2-HMAC-SHA256) and a fixed, documented byte layout. Any reader that honours the layout below is a legitimate restore tool; the official one is a convenience, not a dependency (tenet: *The format is the contract, not the tool*).
- **Backwards-readable.** The file begins with a version number. Encryption always writes the current version; decryption reads every version ever written. An old backup stays restorable after the algorithm moves on.
- **Self-contained restore.** `backvault-decrypt` is one executable with no runtime dependencies, released for the operator's laptop rather than for the server. The service image never contains it, because the image has no shell to run it in and restoring must not depend on the thing being recovered (tenet: *Restorable beats hardened*).

The plaintext this segment protects is the Bitwarden-format JSON export that vault-access produces. The segment does not inspect it; it treats it as opaque bytes.

## File Format

```
offset  size  field
0       4     version, unsigned big-endian integer (currently 2)
4       16    salt for the key derivation function
20      12    AES-GCM nonce
32      n+16  AES-256-GCM ciphertext followed by its 16-byte authentication tag
```

No associated data is passed to GCM, so the header is not covered by the authentication tag. Tampering with the version or salt still fails decryption because the derived key changes, which surfaces as an authentication error. A file shorter than 32 bytes cannot carry a complete header and is rejected as truncated before any key derivation.

### Version 2 (current, written by the service)

Key derivation: Argon2id version 1.3, time cost 3, memory cost 65536 KiB (64 MiB), parallelism 4, 32-byte output, secret = the backup file password as the exact bytes supplied (UTF-8 when entered as text), salt = the 16-byte field.

### Version 1 (legacy, read only)

Key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output. Nothing writes version 1 any more.

## The `backvault-format` Crate

A library with no IO and no network. It exposes:

```rust
pub const VERSION: u32 = 2;
pub fn encrypt(plaintext: &[u8], password: &[u8]) -> Result<Vec<u8>, FormatError>;
pub fn decrypt(file: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, FormatError>;
pub enum FormatError { Truncated, UnsupportedVersion(u32), Authentication, Random }
```

**`encrypt`** encodes `VERSION` as 4 big-endian bytes, draws a 16-byte salt and a 12-byte nonce from the operating system's CSPRNG, derives the key with Argon2id as above, seals with AES-256-GCM and no associated data, and returns `version ‖ salt ‖ nonce ‖ ciphertext‖tag`. A failed random source is `Random`, so the service logs a failed cycle instead of panicking. The function is pure: it depends on nothing but its arguments and the OS random source. The caller (backup-cycle) writes the returned bytes to the validated backup path.

**`decrypt`** rejects a file shorter than 32 bytes as `Truncated`, reads the version, returns `UnsupportedVersion(n)` for anything other than 1 or 2 before deriving a key, derives the key for the version found, and opens the ciphertext. A wrong password and any alteration of the salt, nonce, ciphertext, or tag all surface as `Authentication`; the function never returns plaintext in that case. The derived key is held in a `Zeroizing` buffer and the plaintext is returned in one, so both are wiped when the caller drops them.

Both the service and the restore tool link this crate, so the bytes the service writes and the bytes the tool reads are defined by one implementation.

## The `backvault-decrypt` Restore Tool

```
backvault-decrypt <file.enc>     decrypt a backup; plaintext to stdout
backvault-decrypt --version      print the version and exit
backvault-decrypt --help         print usage and exit
```

| Concern | Behaviour |
|---------|-----------|
| Password entry | When stdin is a terminal, prompt `Enter backup password: ` on stderr and read without echo. When stdin is not a terminal, read the first line of stdin as the password: raw bytes, with a trailing `\n` and any `\r` before it removed, so a password file saved with CRLF endings still works and scripts and the CI integration test can drive the binary without placing the password on the command line. |
| Output | Exactly the decrypted plaintext bytes to stdout, with nothing added, so `backvault-decrypt backup.enc > vault.json` yields a byte-exact copy of the export. Everything else goes to stderr: which format version is being opened and with which KDF, and `Decryption successful.` at the end. |
| Exit status | 0 on success. 1 when the file cannot be read, is truncated, has an unsupported version, fails authentication, or when the plaintext cannot be fully written to stdout (a closed pipe, a full disk); the reason is on stderr and `Decryption successful.` is never printed. 2 when the arguments are wrong, with usage on stderr. |
| Secrets | The password, the derived key, and the plaintext live in `Zeroizing` containers and are wiped after the plaintext has been written. |
| Dependencies | A self-contained executable: statically linked against musl on Linux, linked only against system frameworks on macOS. Nothing to install first. An operator who prefers not to trust a download builds the same binary from the repository with one `cargo build` command; delivery documents both routes. |
| Platforms | Released for macOS (arm64, x86_64) and Linux (x86_64, arm64). The release mechanics belong to the delivery segment. |

## Tests

`crates/backvault-format/tests/format.rs` covers the format end to end: v2 round-trip, header layout, wrong password, salt and nonce randomness across calls, empty and 1 MiB inputs, truncated and corrupted inputs, an unsupported version, and unicode, empty, very long, and NUL-containing passwords. Two committed fixtures, `tests/fixtures/v1.enc` and `tests/fixtures/v2.enc`, each encrypt a small Bitwarden-shaped JSON document of invented data (never a real vault) under a password recorded beside them, and are decrypted on every run; a fixture is evidence that the current reader opens what a past writer produced, which a round-trip of the current pair cannot show.

`crates/backvault-decrypt/tests/cli.rs` runs the built binary as a subprocess: password on piped stdin, plaintext compared byte for byte on stdout, exit status and stderr checked for success, wrong password, missing file, unsupported version, `--version`, and bad arguments.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Key derivation (current) | Argon2id, t=3, m=64 MiB, p=4 | PBKDF2-HMAC-SHA256 (used in v1); scrypt | `[inferred]` Memory-hard KDF resists GPU/ASIC brute force; parameters follow common 2023-era guidance. |
| Cipher | AES-256-GCM, no AAD | AES-CBC + HMAC; ChaCha20-Poly1305 | `[inferred]` Single AEAD primitive; wrong password and corruption both surface as one authentication error. |
| Versioned header | 4-byte big-endian version prefix | Unversioned format; JSON envelope | `[inferred]` Allows the KDF to change (as it did from v1 to v2) without orphaning old backups. |
| Randomness per file | Fresh salt and nonce from the OS CSPRNG each call | Fixed salt; counter nonce | `[inferred]` Each file derives a distinct key, so nonce reuse across files is not a concern. |
| Restore tooling | A separate `backvault-decrypt` binary, released for macOS and Linux, never shipped in the image | A Python script with two libraries; a `decrypt` subcommand of the service binary; shipping the tool inside the image | One file for the machine the operator has on rebuild day. The service binary would drag the HTTP and vault code onto the laptop for nothing, and the image has no shell to run a tool from. A second-language reference script is a parity burden with no fallback value once the byte layout is the documented contract. |
| Crate placement | `backvault-format` library (format only, no IO) linked by both binaries; `backvault-decrypt` holds only the CLI | One crate holding everything; the format inside the service crate | Encrypt and decrypt are one code path reviewed in one place; the restore tool links nothing from the service, so its dependency tree stays small (tenet: *Small tree beats convenient crate*). |
| Primitives | RustCrypto `aes-gcm`, `argon2`, `pbkdf2` + `sha2`, OS randomness through `rand_core::OsRng` | `ring`; `aws-lc-rs`; `openssl` | Pure Rust builds statically for musl without a C toolchain; each crate is single-purpose; the same crates serve vault-access. |
| Password prompt | `rpassword` | Hand-written termios handling | Tiny, cross-platform, and restores echo if the prompt is interrupted. |
| Argument parsing | Hand-written: one positional, `--help`, `--version` | `clap` | Three flags do not justify a parser framework's tree in the one binary that must stay small (tenet: *Small tree beats convenient crate*). |
| Non-terminal stdin | Read the password from the first line of stdin | Require a terminal; a password environment variable | Lets CI run the real binary end to end and lets scripts pipe a password without exposing it on argv or in the environment. |
| Output channel | Exact plaintext bytes to stdout; everything else on stderr | Append a newline; write to a named file | A shell redirect produces a byte-exact export file, and stdout stays clean for piping into `jq` or an importer. |
| Exit codes | 0 success, 1 failure, 2 usage | Always 0; a single non-zero code | A script restoring unattended can tell a bad password from a typo in the command. |
| Fixtures | One committed `.enc` per format version | Generate fixtures in the test from the current encryptor | A fixture is evidence that the current reader opens what a past writer wrote; generated data only proves the current pair agree with each other. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **Failed decryption exits non-zero.** Exit 1 for any failure, 2 for usage; previously the tool exited 0 after printing the error.
2. ✅ **No restore script in the README.** The README points at the release download and the format table in this document; there is no second implementation to keep in step.

### Deferred
1. **Authenticate the header.** Passing `version ‖ salt ‖ nonce` as GCM associated data would bind the header explicitly. Would require a format version bump.
2. **Version 1 support horizon.** PBKDF2 decryption is kept for files written before the Argon2id change. Decide whether it is kept indefinitely.

## Cascade Notes

- **backup-cycle**: calls `backvault_format::encrypt` and writes the returned bytes to the validated backup path; drops the plaintext as soon as the call returns.
- **delivery**: builds `backvault-decrypt` for the four release targets, signs and attests each, and attaches them to a tagged GitHub Release; runs the format crate's fixture tests in CI.
- **vault-access**: no obligation in either direction; this segment never inspects the export.

## References

- RustCrypto AEADs (`aes-gcm`): https://github.com/RustCrypto/AEADs
- RustCrypto password hashes (`argon2`, `pbkdf2`): https://github.com/RustCrypto/password-hashes
- `rpassword`: https://github.com/conradkleinespel/rpassword
- Sibling segments: vault-access (produces the plaintext), backup-cycle (validates the path and writes the bytes), delivery (releases the restore tool)
