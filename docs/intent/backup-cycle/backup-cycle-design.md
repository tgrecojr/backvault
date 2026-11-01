---
parent: high-level-design
prefix: CYCLE
---

# backup-cycle

## Context and Design Philosophy

backup-cycle is one attempt to produce one backup file. The supervisor (scheduler-retention) calls it on a timer; it reads configuration from the environment, hands credentials to vault-access, receives the vault export in memory, encrypts it through backup-encryption, places the result in the backup directory, and returns the written path. It owns no long-lived state and never retries on its own.

Its guiding principle is **fail loudly, one cycle at a time**. Any problem with configuration, the vault export, or the destination path ends the cycle with a typed error that the supervisor logs and counts as a failed cycle; this segment never degrades into a partial or silently wrong backup. The companion principle is **plaintext never touches disk**: the export is encrypted in memory, dropped the moment it is encrypted, and only ciphertext is written.

## Configuration Intake

All configuration arrives as environment variables, read once per cycle into a `CycleConfig`:

| Variable | Required | Default | Validation | On failure |
|----------|----------|---------|------------|------------|
| `BW_CLIENT_ID` | yes | — | non-empty | fail the cycle naming the variable |
| `BW_CLIENT_SECRET` | yes | — | non-empty | fail the cycle naming the variable |
| `BW_PASSWORD` | yes | — | non-empty | fail the cycle naming the variable |
| `BW_SERVER` | yes | — | non-empty | fail the cycle naming the variable |
| `BW_FILE_PASSWORD` | yes | — | non-empty | fail the cycle naming the variable |
| `BACKUP_DIR` | no | `/app/backups` | canonical path must lie under `/app` | fail the cycle naming the resolved path |
| `BACKUP_ENCRYPTION_MODE` | no | `raw` | lower-cased, trimmed, must be `raw` | fail the cycle explaining that only raw mode exists and how a raw file is restored |
| `BW_CA_CERT` | no | unset | file must exist and be readable | fail the cycle naming the path |
| `NODE_TLS_REJECT_UNAUTHORIZED` | no | unset | none | WARNING that it has no effect and `BW_CA_CERT` is the supported route; continue |

Required-variable checks happen before any network activity. Every variable is read as raw operating-system bytes, not as a Rust `String`: `BW_PASSWORD` and `BW_FILE_PASSWORD` reach the vault client and the encryptor as exactly the bytes the operator set, with no UTF-8 validation, trimming, or normalisation, because a password that is re-encoded derives a different key. The three secrets (`BW_CLIENT_SECRET`, `BW_PASSWORD`, `BW_FILE_PASSWORD`) are held in `Zeroizing` buffers for the life of the cycle. The directory check canonicalises the path (following symlinks) before comparing against `/app`; it is the public function `cycle::confine_to_app`, owned here and reused by scheduler-retention before cleanup deletes anything. After validation the backup directory is created with mode `0700` if absent; an existing directory, such as a mounted volume, keeps whatever mode it has.

`BACKUP_ENCRYPTION_MODE` is accepted for one reason: a deployment that still sets it to `bitwarden` must stop with a clear message rather than silently start writing files in a different format, because the operator's restore procedure changes (from `bw import` to the standalone restore tool). The variable has no other effect.

Log output goes through the `log` facade; where it is delivered (stdout, and `LOG_FILE` when set) is the supervisor's concern, configured once at startup.

## Cycle Flow

```mermaid
sequenceDiagram
    participant S as scheduler-retention
    participant C as backup-cycle (cycle::run)
    participant V as vault-access
    participant E as backup-encryption
    S->>C: run(config, vault, clock)
    C->>C: validate env, dir, mode, CA bundle
    C->>V: export_vault_json(server, client_id, client_secret, master_pw, ca_cert)
    V-->>C: Zeroizing<String> (or VaultError)
    C->>C: build and validate backup path
    C->>E: backvault_format::encrypt(json, file_pw)
    E-->>C: ciphertext bytes
    C->>C: drop plaintext; write .part 0600 (no overwrite); sync; rename to .enc
    C-->>S: Ok(path) or Err(CycleError)
```

`cycle::run` is a library function in the `backvault` crate. It is generic over a `VaultExporter` trait (production: vault-access's `export_vault_json`; tests: a fake that returns a canned export or a canned error) and a `Clock` trait that supplies the timestamp for the filename, so every spec below is testable without a server or a real clock.

The vault client is a single call that encapsulates authentication, key derivation, sync, and decryption; backup-cycle neither sees nor stores the intermediate secrets. A `VaultError` from that call becomes `CycleError::Export` and is returned; encryption and the write follow only on success. There is no logout step: the vault client discards its own token and key material before returning.

`CycleError` is one enum with a variant per failure class (missing variable, directory outside `/app`, unsupported mode, unreadable CA bundle, export failure, invalid backup path, write failure). Its display form names the variable, path, or underlying error and never contains a secret. The supervisor logs it at ERROR and records a failed cycle without terminating the service.

## File Naming and Placement

The filename is `backup_<YYYYMMDD_HHMMSS>.enc` in UTC. Immediately before the write, the path is checked: it must resolve within the backup directory, the filename must match `^[a-zA-Z0-9._-]+$`, and it must end in `.enc`. Any failure returns `CycleError::InvalidPath` and nothing is written. This is a second containment layer below the directory-level `/app` check; it exists so that the write path is validated even if a caller other than `cycle::run` ever supplies a filename.

The ciphertext is written to `<final name>.part`, created with mode `0600` and the create-new flag, synced to disk, and then renamed to the final `.enc` name. A file therefore carries the `.enc` suffix only once it is complete and durable: a process killed mid-write (Docker's stop timeout during a slow vault, a crash) leaves a `.part` file that retention prunes, never a truncated `.enc` that an operator might reach for first on rebuild day. An existing `.part` or final file is never overwritten; two cycles in the same second fail the second rather than clobber the first.

## Decisions & Alternatives

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| Failure model | Return one `CycleError` at the first problem; no in-cycle retry beyond what vault-access does | Partial success; retry the cycle internally; process exit codes | The supervisor already schedules the next attempt; a half-written backup is worse than none. A typed error in-process gives the supervisor one failure shape to log, where a process boundary would give it only a number. |
| Encryption modes | Raw mode only | Keep a Bitwarden-native password-protected export as a second mode | Raw mode is restorable with the standalone restore tool and never depends on Bitwarden tooling, which is the disaster-recovery posture the project exists for (tenet: *Portable beats native*). |
| `BACKUP_ENCRYPTION_MODE` set to `bitwarden` | Fail with an explanatory error | Warn and proceed in raw mode; ignore silently | Proceeding would change the on-disk format, and therefore the restore procedure, without the operator's knowledge. A hard stop forces the one-time acknowledgement. |
| Secret bytes | Read as raw OS bytes into `Zeroizing` buffers; passed unchanged | Read as `String` (UTF-8 validated) | A password the operator typed with a non-UTF-8 locale would otherwise fail to load, or worse, be re-encoded and derive the wrong key. |
| Self-signed servers | `BW_CA_CERT` path, checked for existence and readability before use | A verify-off switch | Trusting a named CA gives the same convenience without exposing the master password hash to an interposed host; checking the file up front turns a typo into a clear error instead of a TLS failure deep in the client. |
| Session cleanup | None in this segment; the vault client discards its own secrets | Explicit logout call | An API-key token has no server-side session; the client's own cleanup is the only thing that matters. |
| Configuration source | Environment variables only | File-based secrets (`*_FILE` variables); config file | Simplest for Docker Compose. Environment variables are visible via `docker inspect`; file-based secrets remain an open request. |
| Directory containment | Canonicalise and require a prefix of `/app` | Trust `BACKUP_DIR` as given | Prevents a misconfigured or malicious `BACKUP_DIR` from writing or (via retention) deleting outside the application tree. |
| Per-file containment and filename rules | Validate again at write time with a strict character class and `.enc` suffix | Rely on the directory check alone | Defence in depth; the write-time check is independent of how the path was built. |
| Filename timestamp | UTC, second resolution | Container local time | A static image carries no timezone database, so local time is UTC in practice; saying so makes filenames sortable and comparable across hosts. |
| File creation | `.part` with mode `0600` and create-new, fsync, rename to `.enc` | Inherit the umask; overwrite; no sync; write the final name directly | The directory is `0700` and the file holds the whole vault; create-new makes a same-second collision a loud failure instead of a silent overwrite; the rename makes the `.enc` suffix a promise of completeness, so the newest `.enc` is always a whole backup. |
| Dependency injection | `VaultExporter` and `Clock` traits | Call vault-access and the system clock directly | Every configuration, flow, and naming spec is testable in isolation, which the previous untested design lacked. |

## Open Questions & Future Decisions

### Resolved
1. ✅ **Raw mode is the only mode.** `BACKUP_ENCRYPTION_MODE` survives solely to reject a stale `bitwarden` setting with an explanation.
2. ✅ **One failure shape.** Every failure is a `CycleError` variant; the supervisor logs them uniformly.
3. ✅ **Logging is configured once**, by the supervisor; this segment only emits.
4. ✅ **Backup files are `0600`** and never overwritten.
5. ✅ **Testable without a server** through the `VaultExporter` trait.

### Deferred
1. **File-based secrets.** Support for `BW_PASSWORD_FILE`-style inputs is referenced in the README as an open issue.
2. **Retire `BACKUP_ENCRYPTION_MODE` entirely** once deployments have had time to drop the setting.

## Cascade Notes

- **scheduler-retention**: calls `cycle::run` once per interval, logs any `CycleError` at ERROR, and counts the cycle as failed; reuses `cycle::confine_to_app` before cleanup; owns `LOG_FILE`, the log backend, and the `Clock` trait the cycle consumes.
- **vault-access**: receives the five connection inputs as raw bytes and the optional CA path; returns a zeroizing export string.
- **backup-encryption**: receives the export bytes and the file password bytes; returns ciphertext.

## References

- Sibling segments: vault-access (produces the export; owns `BW_CA_CERT`'s meaning), backup-encryption (raw-mode ciphertext), scheduler-retention (caller; logs the outcome)
- README.md § Configuration (operator-facing table of the same variables)
