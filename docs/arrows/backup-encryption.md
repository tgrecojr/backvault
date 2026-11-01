# Arrow: backup-encryption

Defines the portable `.enc` file format for backups and ships the standalone tool that restores it.

## Status

**MAPPED** — mapped 2026-11-01; encryptor relocated to its own module the same day, no format change. 13 of 14 specs implemented; the production encryptor is now under direct test. One gap: the decrypt tool exits 0 on failure.

## References

### HLD
- docs/high-level-design.md (System Design → backup-encryption; Key Design Decision 2)

### LLD
- docs/intent/backup-encryption/backup-encryption-design.md

### EARS
- docs/intent/backup-encryption/backup-encryption-specs.md (14 specs)

### Tests
- tests/conftest.py (fixtures; FileHandler patch)
- tests/test_encryption.py (31 tests; format, round-trip, v1 compatibility, corruption, security properties, restore-tool dependencies)

### Code
- src/backup_crypto.py (format constants, `encrypt_data`)
- src/decrypt.py (`decrypt_data` and the restore CLI)

## Architecture

**Purpose:** Make a vault export unreadable at rest with nothing but a password, in a format that can be opened years later on any machine with Python and two libraries, without the Bitwarden CLI.

**Key Components:**
1. `encrypt_data` — password → Argon2id key → AES-256-GCM; emits `version ‖ salt ‖ nonce ‖ ciphertext‖tag`.
2. `decrypt_data` — reads the version header, selects PBKDF2 (v1) or Argon2id (v2), authenticates and decrypts.
3. `decrypt.py` CLI — `python decrypt.py <file>`; prompts for the password, prints JSON to stdout.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| File format | ENC-FORMAT-001 to 005 | 5 | 0 | 0 |
| Decryption | ENC-DECRYPT-001 to 006 | 6 | 0 | 0 |
| Restore tool | ENC-TOOL-001 to 003 | 2 | 0 | 1 |

**Summary:** 13 of 14 active specs implemented; 1 gap (ENC-TOOL-002, non-zero exit on failure). 12 of 14 specs cited by tests (ENC-TOOL-001/002 are the interactive CLI).

## Key Findings

1. **Parity is now real.** Tests import `backup_crypto` and `decrypt` and compare their constants directly; drift in either module fails the suite.
2. **Decrypt tool exits 0 on failure** — `src/decrypt.py:84-87` prints the error and falls through; the README copy exits 1. A scripted restore cannot detect a wrong password from the exit code.
3. **Format header is not authenticated** — the 4-byte version is outside the GCM-authenticated data. Altering it changes the KDF and yields `InvalidTag`, so there is no known exploit.
4. **Version 1 is read-only** — nothing writes v1; `decrypt_data` keeps PBKDF2 support for older files.
5. **The restore tool is shipped in the image** and duplicated verbatim in README.md.

## Work Required

### Must Fix
*(none)*

### Should Fix
1. Non-zero exit from `decrypt.py` on `InvalidTag` and other errors (ENC-TOOL-002).

### Nice to Have
2. Decide whether README.md should embed the script or link to `src/decrypt.py`.
3. Decide the version 1 support horizon.
