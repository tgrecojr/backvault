# Arrow: vault-access

Turns Bitwarden/Vaultwarden credentials into a plaintext vault export in memory, then discards every secret it derived.

## Status

**MAPPED** — Rust implementation complete; 52 of 53 specs implemented and unit-tested. **Restore verified 2026-11-01:** the maintainer decrypted a backup written by this implementation with a locally built `backvault-decrypt` and imported it into Vaultwarden successfully. The optional diff against `bw export --format json` has not been run, so VAULT-EXPORT-012 (empty-collection shape pinned to the CLI release) stays open as a refinement rather than a risk to restores.

## References

### HLD
- docs/high-level-design.md (Approach; System Design → vault-access; Key Design Decisions 1 and 2)

### LLD
- docs/intent/vault-access/vault-access-design.md

### EARS
- docs/intent/vault-access/vault-access-specs.md (53 specs)

### Tests
- crates/backvault/tests/vault_crypto.rs (32 tests; endpoints, KDFs, EncStrings, dates)
- crates/backvault/tests/vault_export.rs (24 tests; payload validation, shape, key order, placeholders)
- crates/backvault/tests/vault_session.rs (38 tests; the whole cycle over a scripted transport, retry, TLS configuration, logging)
- crates/backvault/tests/common/mod.rs (test-side crypto, payload builders, fake transport, log capture)

### Code
- crates/backvault/src/vault/mod.rs (`VaultError`, `Credentials`, `HttpTransport`/`Sleep` traits, endpoint resolution, device identity, `export_vault_json`)
- crates/backvault/src/vault/session.rs (`VaultSession`: token → keys → sync → export)
- crates/backvault/src/vault/crypto.rs (master key, HKDF stretch, EncString parsing and decryption, user-key unwrap)
- crates/backvault/src/vault/export/ (`shape.rs` output structs, `item.rs` per-item decryption, `mod.rs` validation, dates, assembly, serialization)
- crates/backvault/src/vault/http.rs (`UreqTransport`, retry and error shaping, server message and JWT helpers)

## Architecture

**Purpose:** Authenticate with the API key, derive the master key from the password, unwrap the user key, fetch `/api/sync`, decrypt locally, and emit the CLI's export JSON shape, with no child process and nothing written to disk.

**Key Components:**
1. `VaultSession` — one cycle: token → keys → sync → export; every secret in a `Zeroizing` container.
2. `RetryingRequester` over an `HttpTransport` trait — three attempts on network/timeout/5xx/429, no retry on rejection, redirects refused, server messages surfaced.
3. `vault::crypto` — PBKDF2/Argon2id master key, HKDF `enc`/`mac` stretch, type 0/2 EncStrings, length-checked key unwrap.
4. `vault::export` — validated sync payload, excludes organization and trashed items, includes archived, counts attachments, applies the `[error: cannot decrypt]` placeholder policy, fails on capability gaps, emits typed structs in the CLI's key order.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Session lifecycle | VAULT-SESSION-001 to 006 | 6 | 0 | 0 |
| Authentication and keys | VAULT-AUTH-001 to 010 | 10 | 0 | 0 |
| EncString decryption | VAULT-CRYPTO-001 to 009 | 9 | 0 | 0 |
| Payload and export shape | VAULT-EXPORT-001, 003 to 014 | 12 | 0 | 1 |
| HTTP transport | VAULT-HTTP-001 to 007 | 7 | 0 | 0 |
| Retry | VAULT-RETRY-001 to 003 | 3 | 0 | 0 |
| Logging | VAULT-LOG-002 to 006 | 5 | 0 | 0 |

**Summary:** 52 of 53 active specs implemented; 1 gap (VAULT-EXPORT-012, empty-collection shape pinned by the drill). Every spec except EXPORT-012 is cited by at least one test.

## Key Findings

1. **Restore is proven by a real import.** Unit tests prove the client decrypts correctly constructed data and shapes it as designed; a backup from this implementation has been imported into Vaultwarden. `REFERENCE_CLI_VERSION` is `2025.1.3`; a diff against that CLI release would additionally pin the empty-collection shape.
2. **Field-level failures match the CLI.** An undecryptable field becomes `[error: cannot decrypt]` with an ERROR log naming item and field; the cycle succeeds. Capability gaps (sealed-blob ciphers, EncString types 1/3–7, item types 6–8, missing or wrongly typed `Key`/`Kdf`) fail the cycle.
3. **No secrets cross a process boundary and none survive the call.** Every secret lives in a `Zeroizing` container; the error type's display form carries none.
4. **Organization items are excluded by design**, matching the CLI's individual export; the count is logged so the operator sees it.
5. **Bitwarden Cloud is untested live.** Endpoint mapping and the token response field set are confirmed against Vaultwarden source and the SDK; a Cloud account has not been exercised.

## Work Required

### Must Fix
*(none)*

### Should Fix
1. Exercise a Bitwarden Cloud account once to confirm the token response shape (LLD Deferred 1).

### Nice to Have
2. Diff a native export against `bw export --format json --raw` of the same vault (parsed, sorted, `null`/`[]`/absent distinct) to settle VAULT-EXPORT-012 and pin `REFERENCE_CLI_VERSION` to the CLI release used; add the comparison script to the repository (LLD Deferred 6).
3. Document Argon2id memory headroom for the container (LLD Deferred 3).
