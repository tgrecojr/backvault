# Arrow: scheduler-retention

Keeps the service alive: runs backup cycles on an interval, prunes old backups once a day, and shuts down cleanly on signals.

## Status

**MAPPED** — mapped 2026-11-01 from git SHA `a72f283`; not yet audited. Implemented; one gap (cleanup does not apply the `/app` containment check). No tests cite this segment.

## References

### HLD
- docs/high-level-design.md (System Design → scheduler-retention)

### LLD
- docs/intent/scheduler-retention/scheduler-retention-design.md

### EARS
- docs/intent/scheduler-retention/scheduler-retention-specs.md (17 specs)

### Tests
- *(none)*

### Code
- entrypoint.py (entire module)

## Architecture

**Purpose:** Be PID 1 of the container without a shell or cron: supervise repeated backup cycles, tolerate their failures, prune old files, and respond to SIGTERM within a second.

**Key Components:**
1. `main` — validates the interval, runs one backup immediately, then loops: sleep → backup → (cleanup if the calendar day changed).
2. `run_backup` — calls `run.main` and converts its `SystemExit`/exceptions into log lines so the loop survives.
3. `run_cleanup` — deletes `*.enc` regular files older than `RETAIN_DAYS` from `BACKUP_DIR`.
4. `_sleep_interruptible` — sleeps in 1 s slices, watching the shutdown flag set by the signal handler.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Interval loop | SCHED-LOOP-001 to 006 | 6 | 0 | 0 |
| Signals and shutdown | SCHED-SIGNAL-001 to 003 | 3 | 0 | 0 |
| Retention cleanup | SCHED-RETAIN-001 to 008 | 7 | 0 | 1 |

**Summary:** 16 of 17 active specs implemented; 1 gap (SCHED-RETAIN-008, deletion path not confined to `/app`). No `@spec` annotations or tests cite this segment yet.

## Key Findings

1. **Cleanup is not "at midnight"** — it runs after the first backup cycle that completes on a new calendar day (entrypoint.py:131-134). With a 12-hour interval, cleanup lands up to 12 hours after midnight. The README says midnight.
2. **Cleanup deletes from an unchecked `BACKUP_DIR`** — `run_cleanup` reads the variable directly (entrypoint.py:80) with no `/app` containment check, unlike `validate_backup_dir` in the backup cycle (src/run.py:25-45). Deletion is still limited to regular, non-symlink `*.enc` files by mtime.
3. **Validation severity differs by variable** — a bad `BACKUP_INTERVAL_HOURS` is fatal (exit 1, entrypoint.py:36-46); a bad `RETAIN_DAYS` only disables cleanup (entrypoint.py:49-58).
4. **Failed cycles never stop the service** — `run_backup` catches `SystemExit` and `Exception` (entrypoint.py:61-73). There is no failure counter, back-off, or health signal; a permanently broken configuration logs an error every interval forever.
5. **Hardcoded import path** — `sys.path.insert(0, "/app")` (entrypoint.py:17) couples the module to the Dockerfile's flat copy of `src/`; it cannot run from the repository checkout as-is.
6. **No health check surface** — nothing writes a heartbeat file or exposes status; the Dockerfile has no `HEALTHCHECK`.
7. **Lint coverage gap** — CI runs ruff on `src/` only (`.github/workflows/test.yml`), so this module is unlinted.

## Work Required

### Must Fix
*(none)*

### Should Fix
1. Apply the same `/app` containment check to `BACKUP_DIR` before cleanup deletes anything (SCHED-RETAIN-008).
2. Add tests for interval validation, the survive-failure contract, the day-rollover cleanup trigger, deletion rules, and signal handling (time and filesystem can be faked).
3. Correct the README's "midnight" wording or change the trigger to match it.

### Nice to Have
4. Include `entrypoint.py` in CI lint.
5. Consider a heartbeat file or `HEALTHCHECK` so a stuck or always-failing service is observable.
