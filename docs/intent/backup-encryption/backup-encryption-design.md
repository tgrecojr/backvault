---
parent: high-level-design
prefix: ENC
---

# backup-encryption

## Context and Design Philosophy

A BackVault backup is only useful if it can be opened after the server it came from is gone. backup-encryption defines the on-disk format of a raw-mode backup and provides the tool that opens it. The design leans on two commitments:

- **Portable by construction.** The format uses only standard primitives (Argon2id, AES-256-GCM) available from `cryptography` and `argon2-cffi`. Restoring never requires the Bitwarden CLI, a Node runtime, or network access.
- **Backwards-readable.** The file begins with a version number. Encryption always writes the current version; decryption reads every version ever written. An old backup stays restorable after the algorithm moves on.

The plaintext this segment protects is the Bitwarden-format JSON export that vault-access produces. The segment does not inspect it; it treats it as opaque bytes.

## File Format

```
offset  size  field
0       4     version, unsigned big-endian integer (currently 2)
4       16    salt for the key derivation function
20      12    AES-GCM nonce
32      n+16  AES-256-GCM ciphertext followed by its 16-byte authentication tag
```

No associated data is passed to GCM (src/bw_client.py:376), so the header is not covered by the authentication tag. Tampering with the version or salt still fails decryption because the derived key changes, which surfaces as `InvalidTag`.

### Version 2 (current, written by the service)

Key derivation: Argon2id, time cost 3, memory cost 65536 KiB (64 MiB), parallelism 4, 32-byte output, secret = UTF-8 bytes of the backup file password, salt = the 16-byte field (src/bw_client.py:23-26, 362-371).

### Version 1 (legacy, read only)

Key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output (src/decrypt.py:14-15, 39-45). Nothing writes version 1 any more.

## Encryption Path

`encrypt_data(data, password)` in `src/backup_crypto.py`, the module that owns this segment's format constants:

1. Encode `ENCRYPTION_VERSION` (2) as 4 big-endian bytes.
2. Draw a 16-byte salt and a 12-byte nonce from `os.urandom`.
3. Derive the key with Argon2id as above.
4. `AESGCM(key).encrypt(nonce, data, None)`.
5. Return `version ‖ salt ‖ nonce ‖ ciphertext‖tag`.

The caller (backup-cycle) writes the returned bytes to the validated backup path. The function is pure: it depends on nothing but its arguments and the OS random source.

## Decryption Path and Restore Tool

`decrypt_data(encrypted, password)` (src/decrypt.py:23-66) parses the header, derives the key for the version it finds, and calls `AESGCM.decrypt`. An unknown version raises `ValueError("Unsupported encryption version: N")` before any key derivation.

The module doubles as a command-line tool (src/decrypt.py:69-87): `python decrypt.py <file>` prompts for the password with `getpass`, prints the decrypted JSON to stdout, and prints progress and errors to stderr. Both `InvalidTag` and other exceptions are caught and reported, and the process then exits 0. The copy of this script embedded in README.md exits 1 on those paths.

## Tests

`tests/test_encryption.py` covers the format end to end: constant parity between `backup_crypto` and `decrypt`, v2 round-trip, header layout, wrong password, salt/nonce randomness, empty and 1 MiB inputs, v1 compatibility, truncated and corrupted inputs, and unicode/empty/very long/NUL-containing passwords. The encryptor under test is the production `backup_crypto.encrypt_data`.

`tests/conftest.py` redirects any `logging.FileHandler` aimed at `/var/log` to a temp directory for the session (L15-48) and provides `test_password` and `test_data` fixtures.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Key derivation (current) | Argon2id, t=3, m=64 MiB, p=4 | PBKDF2-HMAC-SHA256 (used in v1); scrypt | `[inferred]` Memory-hard KDF resists GPU/ASIC brute force; parameters follow common 2023-era guidance. Code comments cite OWASP for the v1 iteration count. |
| Cipher | AES-256-GCM, no AAD | AES-CBC + HMAC; ChaCha20-Poly1305 | `[inferred]` Single AEAD primitive; wrong password and corruption both surface as one `InvalidTag` error. |
| Versioned header | 4-byte big-endian version prefix | Unversioned format; JSON envelope | `[inferred]` Allows the KDF to change (as it did from v1 to v2) without orphaning old backups. |
| Randomness per file | Fresh salt and nonce from `os.urandom` each call | Fixed salt; counter nonce | `[inferred]` Each file derives a distinct key, so nonce reuse across files is not a concern. |
| Restore tooling | Standalone `decrypt.py` with only two third-party deps, also embedded in README | Require `bw` to decrypt; custom binary | `[inferred]` Disaster recovery must not depend on the thing being recovered. |
| Module placement | `src/backup_crypto.py` holds `encrypt_data` and the format constants; `src/decrypt.py` stays standalone | Keep the encryptor inside the vault client module | The format changes for its own reasons, independent of how the vault is reached; a pure module can be imported by tests without side effects, so the production encryptor is what gets tested. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **The encryptor lives in its own module** (`src/backup_crypto.py`) and the parity tests import it directly.

### Deferred
1. **Exit status on failed decryption.** `src/decrypt.py` exits 0 when the password is wrong; the README copy exits 1. Pick one and make the two agree (ENC-TOOL-002 is tracked as a gap).
2. **Authenticate the header.** Passing `version ‖ salt ‖ nonce` as GCM associated data would bind the header explicitly. Would require a format version bump.
3. **README duplication.** Decide whether the README keeps a verbatim copy of the restore script or links to the file in the repository.
4. **Version 1 support horizon.** PBKDF2 decryption is kept for files written before the Argon2id change. Decide whether it is kept indefinitely.

## References

- `cryptography` AESGCM: https://cryptography.io/en/latest/hazmat/primitives/aead/
- `argon2-cffi` low-level API: https://argon2-cffi.readthedocs.io/en/stable/api.html#argon2.low_level.hash_secret_raw
- Sibling segments: vault-access (produces the plaintext), backup-cycle (validates the path and writes the bytes)
