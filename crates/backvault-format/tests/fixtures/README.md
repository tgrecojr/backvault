# Format fixtures

Synthetic data only; nothing here is a real vault or a real secret.

- `plaintext.json`: the document both fixtures encrypt.
- `v2.enc`: written by the BackVault service encryptor (Argon2id, format version 2).
- `v1.enc`: written with the documented version-1 parameters (PBKDF2-HMAC-SHA256, 600,000 iterations).

Password for both: `fixture-password-2026`

The test suite decrypts every fixture on every run (ENC-DECRYPT-009).
