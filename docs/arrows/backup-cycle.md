# Arrow: backup-cycle

Runs one backup: validates configuration in a fixed order, obtains the export from vault-access, encrypts it, places the `.enc` file, and returns the path or a typed error to the supervisor.

## Status

**MAPPED** — Rust implementation complete; 16 of 16 specs implemented and tested through an injected vault client and clock.

## References

### HLD
- docs/high-level-design.md (System Design → backup-cycle; Key Design Decision 4)

### LLD
- docs/intent/backup-cycle/backup-cycle-design.md

### EARS
- docs/intent/backup-cycle/backup-cycle-specs.md (16 specs)

### Tests
- crates/backvault/tests/cycle.rs (22 tests; fake `VaultExporter`, fixed `Clock`, temp directory as the allowed base)

### Code
- crates/backvault/src/cycle/mod.rs (`CycleConfig::from_env`, `cycle::run`, `CycleError`, durable write)
- crates/backvault/src/cycle/paths.rs (`confine_to_app`, `validate_backup_path`)
- crates/backvault/src/env.rs (`Env` trait: `SystemEnv`, `MapEnv`)

## Architecture

**Purpose:** Be the one place where a backup either happens correctly or fails loudly with a typed error, so the supervisor can treat each cycle as an atomic attempt.

**Key Components:**
1. `CycleConfig::from_env` — intake in the order required variables, `BACKUP_DIR`, mode, `BW_CA_CERT`; first failure wins; secrets as raw bytes in zeroizing buffers.
2. `cycle::run` — one `VaultExporter` call, then encrypt, drop plaintext, write `.part` with mode `0600` and create-new, fsync, rename to `.enc`.
3. `cycle::paths` — `/app` containment (shared with scheduler-retention) and per-file filename rules.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Configuration | CYCLE-CONFIG-001 to 005, 007 to 010 | 9 | 0 | 0 |
| Flow and outcome contract | CYCLE-FLOW-001, 003 to 005 | 4 | 0 | 0 |
| File naming and placement | CYCLE-FILE-001 to 003 | 3 | 0 | 0 |

**Summary:** 16 of 16 active specs implemented; every spec cited by a test.

## Key Findings

1. **Raw mode is the only mode.** A stale `BACKUP_ENCRYPTION_MODE=bitwarden` stops the cycle with a message explaining the raw format and its restore tool.
2. **One failure shape.** Every failure is a `CycleError` variant returned in-process; the supervisor logs it and counts a failed cycle.
3. **Passwords are bytes.** The two passwords are read as raw OS bytes and never re-encoded, so the derived keys match what the operator set.
4. **A file is `.enc` only when complete.** Written as `.part`, synced, then renamed; never overwritten; mode `0600`.

## Work Required

### Must Fix
*(none)*

### Nice to Have
1. Retire `BACKUP_ENCRYPTION_MODE` once deployments have dropped it (LLD Deferred 2).
