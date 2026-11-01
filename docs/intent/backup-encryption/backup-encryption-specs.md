# backup-encryption — EARS Specs

Prefix `ENC`. Facets: `FORMAT` (what the service writes), `DECRYPT` (how any version is read), `TOOL` (the standalone restore binary).

Status: `[x]` implemented and observed working in the Rust crates · `[ ]` specified, not yet implemented or unverified · `[D]` deferred.

## File format (raw-mode backups)

- [x] **ENC-FORMAT-001**: A raw-mode backup file shall consist of, in order: a 4-byte big-endian version number, a 16-byte salt, a 12-byte nonce, and the AES-256-GCM ciphertext followed by its 16-byte authentication tag.
- [x] **ENC-FORMAT-002**: When the service encrypts a raw-mode backup, it shall write format version 2.
- [x] **ENC-FORMAT-003**: When the service encrypts a raw-mode backup, it shall derive the 32-byte AES key with Argon2id version 1.3 using time cost 3, memory cost 65536 KiB, parallelism 4, the file's salt, and the backup file password as the exact bytes supplied by the caller (UTF-8 when entered as text), with no trimming or normalisation.
- [x] **ENC-FORMAT-004**: When the service encrypts a raw-mode backup, it shall draw a fresh 16-byte salt and a fresh 12-byte nonce from the operating system's CSPRNG for that file.
- [x] **ENC-FORMAT-005**: When the service encrypts a raw-mode backup, it shall use AES-256-GCM with no associated data.
- [x] **ENC-FORMAT-006**: The encrypt and decrypt functions shall live in the `backvault-format` crate, which shall perform no file, network, or terminal IO, and both the service and the restore tool shall link that crate.

## Decryption

- [x] **ENC-DECRYPT-001**: When decrypting a raw-mode backup file, the decryptor shall read the version from the first 4 bytes and select the key derivation function by that version.
- [x] **ENC-DECRYPT-002**: When the file version is 1, the decryptor shall derive the key with PBKDF2-HMAC-SHA256 at 600,000 iterations using the file's salt and a 32-byte output.
- [x] **ENC-DECRYPT-003**: When the file version is 2, the decryptor shall derive the key with Argon2id using the same parameters the service uses to encrypt (version 1.3, time cost 3, memory cost 65536 KiB, parallelism 4, 32-byte output).
- [x] **ENC-DECRYPT-004**: If the file version is neither 1 nor 2, then the decryptor shall return an unsupported-version error naming the version and shall not derive a key or attempt decryption.
- [x] **ENC-DECRYPT-005**: If the password is wrong, or the salt, nonce, ciphertext, or tag has been altered, then decryption shall fail with an authentication error and shall not return plaintext.
- [x] **ENC-DECRYPT-006**: The key-derivation parameters used by the service to encrypt and by the decryptor to decrypt version 2 files shall be identical, so that every file the service writes is readable by the restore tool.
- [x] **ENC-DECRYPT-007**: If the file is shorter than 32 bytes, then the decryptor shall return a truncated-file error before deriving a key.
- [x] **ENC-DECRYPT-008**: The decryptor shall hold the derived key in a zeroizing buffer and shall return the plaintext in a zeroizing buffer.
- [x] **ENC-DECRYPT-009**: The repository shall hold one committed fixture backup file per format version (1 and 2), each encrypting a known plaintext under a known password, and the test suite shall decrypt every fixture with the current decryptor on every run.

## Restore tool

- [x] **ENC-TOOL-001**: When invoked as `backvault-decrypt <file>` with a terminal on stdin, the restore tool shall prompt `Enter backup password: ` on stderr without echoing the input, write exactly the decrypted plaintext bytes to stdout and nothing else, and write status messages to stderr.
- [x] **ENC-TOOL-002**: If the file cannot be read, is truncated, has an unsupported version, or fails authentication, then the restore tool shall report the reason on stderr, write nothing to stdout, and exit with status 1; if the plaintext cannot be fully written to stdout, then the restore tool shall report the reason on stderr and exit with status 1.
- [x] **ENC-TOOL-003**: The restore tool shall be a self-contained executable that depends on nothing beyond the operating system, so that a backup can be restored on a machine with no container runtime, interpreter, Bitwarden CLI, or network access.
- [x] **ENC-TOOL-004**: When stdin is not a terminal, the restore tool shall read the password as the raw bytes of the first line of stdin with a trailing `\n`, and a `\r` immediately before it, removed, and shall not prompt.
- [x] **ENC-TOOL-005**: When invoked with `--version`, the restore tool shall print its version to stdout and exit 0; when invoked with `--help`, it shall print usage to stdout and exit 0.
- [x] **ENC-TOOL-006**: If the restore tool is invoked with no file argument, more than one file argument, or an unrecognised option, then it shall print usage to stderr and exit with status 2.
- [x] **ENC-TOOL-007**: The restore tool shall hold the password, the derived key, and the plaintext in zeroizing containers and shall wipe them after the plaintext has been written.
