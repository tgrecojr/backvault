# Arrow: backup-encryption

Defines the `.enc` backup format in the `backvault-format` crate and ships the `backvault-decrypt` restore binary that opens it on the operator's machine.

## Status

**MAPPED** — Rust implementation complete; 22 of 22 specs implemented and tested, both format fixtures decrypt on every run. The released binary has not yet been exercised on a bare macOS and Linux machine (that happens with the first tagged release).

## References

### HLD
- docs/high-level-design.md (Approach; System Design → backup-encryption; Key Design Decisions 2, 3, 4, 6)

### LLD
- docs/intent/backup-encryption/backup-encryption-design.md

### EARS
- docs/intent/backup-encryption/backup-encryption-specs.md (22 specs)

### Tests
- crates/backvault-format/tests/format.rs (27 tests; round-trip, layout, failure modes, passwords, fixtures, crate boundary)
- crates/backvault-format/tests/fixtures/ (`v1.enc`, `v2.enc`, `plaintext.json`, README with the fixture password)
- crates/backvault-decrypt/tests/cli.rs (10 subprocess tests of the real binary)
- crates/backvault-decrypt/src/main.rs (3 unit tests: piped password, write failure, argument parsing)

### Code
- crates/backvault-format/src/lib.rs (`encrypt`, `decrypt`, `FormatError`, constants)
- crates/backvault-decrypt/src/main.rs (argument handling, password entry, stdout/stderr, exit codes)

## Architecture

**Purpose:** Turn the plaintext export into a password-protected file that any implementation of the documented layout can open, and provide the official opener as one self-contained executable.

**Key Components:**
1. `backvault_format::encrypt` — version 2: Argon2id key, fresh salt and nonce, AES-256-GCM, no AAD; a failed random source is an error, not a panic.
2. `backvault_format::decrypt` — version-dispatched KDF (v1 PBKDF2, v2 Argon2id), truncation and version checks before key derivation, zeroizing key and plaintext.
3. `backvault-decrypt` — terminal or piped password, exact bytes to stdout, status to stderr, exit 0/1/2.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| File format | ENC-FORMAT-001 to 006 | 6 | 0 | 0 |
| Decryption | ENC-DECRYPT-001 to 009 | 9 | 0 | 0 |
| Restore tool | ENC-TOOL-001 to 007 | 7 | 0 | 0 |

**Summary:** 22 of 22 active specs implemented; every spec cited by a test.

## Key Findings

1. **The format is unchanged.** Every byte of the v1 and v2 layouts is as before, so existing backups stay readable; the fixtures (one written by the previous service implementation) prove it on every CI run.
2. **One implementation for both directions.** The service and the restore tool link the same crate, so the parity between encryptor and decryptor is a structural fact.
3. **The restore tool is the only deliverable that leaves the server.** It is released for the operator's laptop, never placed in the image.

## Work Required

### Must Fix
*(none)*

### Should Fix
1. Open the newest real backup with the first released binary on a macOS and a Linux machine (HLD success metric).
2. Decide the version 1 support horizon (LLD Deferred 2).

### Nice to Have
3. Header authentication via GCM associated data in a future format version (LLD Deferred 1).
