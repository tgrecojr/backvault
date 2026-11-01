# Arrow: vault-access

Turns Bitwarden/Vaultwarden credentials into a plaintext vault export in memory, then discards every secret it derived.

## Status

**MAPPED** — specs, tests, and code rewritten 2026-11-01 for the native Python client (replacing the `bw` CLI wrapper); not yet audited. 49 of 50 specs implemented and unit-tested. The pre-merge drill (semantic diff against `bw export --format json` of the same vault, then an import into a scratch Vaultwarden) has **not** been run yet; until it is, this segment should not be considered restore-verified.

## References

### HLD
- docs/high-level-design.md (Approach; System Design → vault-access; Key Design Decision 1)

### LLD
- docs/intent/vault-access/vault-access-design.md

### EARS
- docs/intent/vault-access/vault-access-specs.md (50 specs)

### Tests
- tests/test_vault_client.py (78 tests; fake transport, test-side crypto fixtures, SDK stretch vector)

### Code
- src/vault_client.py (`VaultSession`, `export_vault_json`, endpoint resolution, device identity)
- src/vault_crypto.py (master key, HKDF stretch, EncString parsing and decryption, user-key unwrap)
- src/vault_export.py (sync payload validation, item selection, export shape, dates, serialization)
- src/vault_http.py (TLS context, redirect refusal, retry and error shaping)

## Architecture

**Purpose:** Authenticate with the API key, derive the master key from the password, unwrap the user key, fetch `/api/sync`, decrypt locally, and emit the CLI's export JSON shape, with no child process and nothing written to disk.

**Key Components:**
1. `VaultSession` — one cycle: token → keys → sync → export → clear.
2. `RetryingRequester` — three attempts on network/5xx/429, no retry on rejection, redirects refused, server messages surfaced.
3. `vault_crypto` — PBKDF2/Argon2id master key, HKDF `enc`/`mac` stretch, type 0/2 EncStrings, length-checked key unwrap.
4. `build_export` — excludes organization and trashed items, includes archived, counts attachments, applies the `[error: cannot decrypt]` placeholder policy, fails on capability gaps.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Session lifecycle | VAULT-SESSION-001 to 006 | 6 | 0 | 0 |
| Authentication and keys | VAULT-AUTH-001 to 010 | 10 | 0 | 0 |
| EncString decryption | VAULT-CRYPTO-001 to 009 | 9 | 0 | 0 |
| Payload and export shape | VAULT-EXPORT-001, 003 to 014 | 12 | 0 | 1 |
| HTTP transport | VAULT-HTTP-001 to 005 | 5 | 0 | 0 |
| Retry | VAULT-RETRY-001 to 003 | 3 | 0 | 0 |
| Logging | VAULT-LOG-002 to 005 | 4 | 0 | 0 |

**Summary:** 49 of 50 active specs implemented; 1 gap (VAULT-EXPORT-012, empty-collection shape pinned by the drill). Every spec except EXPORT-012 is cited by at least one test. 33 `@spec` annotations in `src/`.

## Key Findings

1. **Restore guarantee rests on the drill.** Unit tests prove the client decrypts correctly constructed data and shapes it as designed; only a diff against the real CLI and a real import prove the shape matches what Bitwarden accepts. `REFERENCE_CLI_VERSION` is set to `2025.1.3` pending that drill.
2. **Field-level failures match the CLI.** An undecryptable field becomes `[error: cannot decrypt]` with an ERROR log naming item and field; the cycle succeeds. Capability gaps (sealed-blob ciphers, EncString types 1/3–7, item types 6–8, missing `Key`/`Kdf`) fail the cycle.
3. **No secrets cross a process boundary.** The master password is used only to derive keys in memory; `bw`'s argv exposure is gone, as is the `seccomp=unconfined` requirement and the Node runtime.
4. **Organization items are excluded by design**, matching the CLI's individual export; the count is logged so the operator sees it.
5. **Bitwarden Cloud is untested live.** Endpoint mapping and the token response field set are confirmed against Vaultwarden source and the SDK; a Cloud account has not been exercised.

## Work Required

### Must Fix
1. Run the pre-merge drill against the maintainer's Vaultwarden: compare the native export with `bw export --format json --raw` of the same vault (parsed, sorted, `null`/`[]`/absent distinct), resolve VAULT-EXPORT-012 by pinning the empty-collection shape to the CLI release used, and import the native export into a scratch Vaultwarden. Record the CLI version in `REFERENCE_CLI_VERSION`.

### Should Fix
2. Add the comparison script used by the drill to the repository so it is repeatable (LLD Deferred 7).
3. Exercise a Bitwarden Cloud account once to confirm the token response shape (LLD Deferred 1).

### Nice to Have
4. Document Argon2id memory headroom for the container (LLD Deferred 3).
