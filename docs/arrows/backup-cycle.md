# Arrow: backup-cycle

Runs one backup: validates configuration in a fixed order, obtains the export from vault-access, encrypts it, places the `.enc` file, and reports success or failure to the supervisor.

## Status

**MAPPED** — mapped and revised 2026-11-01 (raw-only mode, `BW_CA_CERT`, single vault-client call); not yet audited. 14 of 14 specs implemented and tested.

## References

### HLD
- docs/high-level-design.md (System Design → backup-cycle; Key Design Decision 3)

### LLD
- docs/intent/backup-cycle/backup-cycle-design.md

### EARS
- docs/intent/backup-cycle/backup-cycle-specs.md (14 specs)

### Tests
- tests/test_run.py (18 tests; fake vault client, temp allowed base)

### Code
- src/run.py (entire module)

## Architecture

**Purpose:** Be the one place where a backup either happens correctly or fails loudly with exit status 1, so the supervisor can treat each cycle as an atomic attempt.

**Key Components:**
1. `require_env`, `validate_backup_dir`, `validate_encryption_mode`, `validate_ca_cert` — intake in that order; first failure wins.
2. `main` — one `vault_client.export_vault_json` call, then encrypt and write.
3. `validate_backup_path` — per-file containment and filename rules applied immediately before the write.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Configuration | CYCLE-CONFIG-001 to 009 | 9 | 0 | 0 |
| Flow and exit contract | CYCLE-FLOW-001, 003, 004 | 3 | 0 | 0 |
| File naming and placement | CYCLE-FILE-001 to 002 | 2 | 0 | 0 |

**Summary:** 14 of 14 active specs implemented; every spec cited by a test.

## Key Findings

1. **Raw mode is the only mode.** A stale `BACKUP_ENCRYPTION_MODE=bitwarden` stops the cycle with a message explaining the raw format and its restore tool, so the operator acknowledges the restore-procedure change once.
2. **`NODE_TLS_REJECT_UNAUTHORIZED` is inert** and produces a WARNING pointing at `BW_CA_CERT`, whose file is checked for existence before any network activity.
3. **Two failure shapes remain** — a missing required variable raises `RuntimeError`, every other failure calls `sys.exit(1)`. The supervisor treats both as a failed cycle.
4. **Backup file permissions are not set explicitly**; only the directory gets `0o700`, and only if created here.
5. **`logging.basicConfig` is called in two modules** (`entrypoint.py`, `run.py`); the first call wins.

## Work Required

### Must Fix
*(none)*

### Should Fix
1. Align `.env-example` (remove `BACKUP_ENCRYPTION_MODE`, `CRON_EXPRESSION`, `NODE_TLS_REJECT_UNAUTHORIZED`; add `BW_CA_CERT`; fix the `LOG_FILE` example). Blocked in the 2026-11-01 session by a tooling deny rule on `.env*` files.

### Nice to Have
2. Set `0o600` on written backup files.
3. Unify the failure shape (LLD Deferred 1).
4. Retire `BACKUP_ENCRYPTION_MODE` once deployments have dropped it (LLD Deferred 8).
