# backup-encryption — EARS Specs

Prefix `ENC`. Facets: `FORMAT` (what the service writes), `DECRYPT` (how any version is read), `TOOL` (the standalone restore CLI).

Status: `[x]` observed working in current code · `[ ]` specified but broken, partial, or unverified · `[D]` deferred.

## File format (raw-mode backups)

- [x] **ENC-FORMAT-001**: A raw-mode backup file shall consist of, in order: a 4-byte big-endian version number, a 16-byte salt, a 12-byte nonce, and the AES-256-GCM ciphertext followed by its 16-byte authentication tag.
- [x] **ENC-FORMAT-002**: When the service encrypts a raw-mode backup, it shall write format version 2.
- [x] **ENC-FORMAT-003**: When the service encrypts a raw-mode backup, it shall derive the 32-byte AES key with Argon2id using time cost 3, memory cost 65536 KiB, parallelism 4, the file's salt, and the UTF-8 encoding of the backup file password.
- [x] **ENC-FORMAT-004**: When the service encrypts a raw-mode backup, it shall draw a fresh 16-byte salt and a fresh 12-byte nonce from the operating system's CSPRNG for that file.
- [x] **ENC-FORMAT-005**: When the service encrypts a raw-mode backup, it shall use AES-256-GCM with no associated data.

## Decryption

- [x] **ENC-DECRYPT-001**: When decrypting a raw-mode backup file, the decryptor shall read the version from the first 4 bytes and select the key derivation function by that version.
- [x] **ENC-DECRYPT-002**: When the file version is 1, the decryptor shall derive the key with PBKDF2-HMAC-SHA256 at 600,000 iterations using the file's salt and a 32-byte output.
- [x] **ENC-DECRYPT-003**: When the file version is 2, the decryptor shall derive the key with Argon2id using the same parameters the service uses to encrypt (time cost 3, memory cost 65536 KiB, parallelism 4, 32-byte output).
- [x] **ENC-DECRYPT-004**: If the file version is neither 1 nor 2, then the decryptor shall raise a `ValueError` naming the unsupported version and shall not derive a key or attempt decryption.
- [x] **ENC-DECRYPT-005**: If the password is wrong, or the salt, nonce, or ciphertext has been altered, then decryption shall fail with an authentication error (`InvalidTag`) and shall not return plaintext.
- [x] **ENC-DECRYPT-006**: The key-derivation parameters used by the service to encrypt and by the decryptor to decrypt version 2 files shall be identical, so that every file the service writes is readable by the restore tool.

## Restore tool

- [x] **ENC-TOOL-001**: When invoked as `python decrypt.py <file>`, the restore tool shall prompt for the backup password without echoing it, write the decrypted plaintext to stdout, and write status and error messages to stderr.
- [ ] **ENC-TOOL-002**: If decryption fails for any reason, then the restore tool shall report the failure on stderr and exit with a non-zero status.
- [x] **ENC-TOOL-003**: The restore tool shall depend only on the Python standard library, `cryptography`, and `argon2-cffi`, so that a backup can be restored on a machine without the Bitwarden CLI or network access.
