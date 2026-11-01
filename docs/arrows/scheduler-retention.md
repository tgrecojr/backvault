# Arrow: scheduler-retention

Keeps the service alive: installs logging, runs backup cycles on an interval, prunes old backups once a day inside a confined directory, and shuts down cleanly on signals.

## Status

**MAPPED** — Rust implementation complete; 21 of 21 specs implemented and tested through injected cycle runner, clock, and sleeper. Signal delivery itself is exercised through the shutdown flag the handler sets; the handler registration lives in `main.rs` and is verified by inspection.

## References

### HLD
- docs/high-level-design.md (System Design → scheduler-retention; Key Design Decision 8)

### LLD
- docs/intent/scheduler-retention/scheduler-retention-design.md

### EARS
- docs/intent/scheduler-retention/scheduler-retention-specs.md (21 specs)

### Tests
- crates/backvault/tests/scheduler.rs (21 tests; fake `CycleRunner`, `Clock`, `Sleeper`; shared shutdown flag; temp directories)
- crates/backvault/tests/logging.rs (6 tests; the `log::Log` backend with in-memory sinks and a temp log file)
- crates/backvault/tests/bin_version.rs (1 test; the real binary's `--version`)

### Code
- crates/backvault/src/main.rs (`--version`, logger install, `signal-hook` registration, `Supervisor::run`, exit code)
- crates/backvault/src/scheduler.rs (`Supervisor`, `run_cleanup`, `interval_hours`, `retain_days`, `sleep_interruptible`, the three traits)
- crates/backvault/src/logging.rs (the `log::Log` backend with optional `LOG_FILE`)

## Architecture

**Purpose:** Be PID 1 of the container without a shell or cron: supervise repeated backup cycles, tolerate their failures and panics, prune old files inside `/app`, and respond to SIGTERM within a second.

**Key Components:**
1. `logging::install` — stdout plus optional `LOG_FILE`; failure to open the file is non-fatal.
2. `Supervisor::run` — validates the interval, runs one backup immediately, then loops: sleep → backup → (cleanup if the UTC date changed).
3. `run_backup` — calls the cycle under `catch_unwind` and converts error or panic into an ERROR line so the loop survives.
4. `run_cleanup` — confines `BACKUP_DIR` to `/app` with backup-cycle's function, then deletes `*.enc` and `*.enc.part` regular files older than `RETAIN_DAYS`.
5. `sleep_interruptible` — 1 s slices watching the atomic flag set by `signal-hook`.

## Spec Coverage

| Category | Spec IDs | Implemented | Deferred | Gaps |
|----------|----------|-------------|----------|------|
| Logging | SCHED-LOG-001 to 002 | 2 | 0 | 0 |
| Interval loop | SCHED-LOOP-001 to 008 | 8 | 0 | 0 |
| Signals and shutdown | SCHED-SIGNAL-001 to 003 | 3 | 0 | 0 |
| Retention cleanup | SCHED-RETAIN-001 to 008 | 8 | 0 | 0 |

**Summary:** 21 of 21 active specs implemented; every spec cited by a test.

## Key Findings

1. **Cleanup is not "at midnight"** — it runs after the first backup cycle that completes on a new UTC day. With a 12-hour interval, cleanup lands up to 12 hours after midnight; the README says so.
2. **Cleanup and writing share one containment check**, so the pruning path can never reach outside `/app` while the writing path is confined.
3. **A panic in a cycle is a failed cycle**, not a dead service.
4. **No health check surface** — nothing writes a heartbeat file or exposes status; the Dockerfile has no `HEALTHCHECK`.

## Work Required

### Must Fix
*(none)*

### Nice to Have
1. Document `stop_grace_period` in the Compose reference (LLD Deferred 3; delivery segment).
2. Consider a heartbeat file or `HEALTHCHECK` so a stuck or always-failing service is observable (LLD Deferred 2).
