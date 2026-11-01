# scheduler-retention — EARS Specs

Prefix `SCHED`. Facets: `LOOP` (interval scheduling and failure tolerance), `SIGNAL` (shutdown), `RETAIN` (cleanup).

Status: `[x]` observed working in current code · `[ ]` specified but broken, partial, or unverified · `[D]` deferred.

## Interval loop

- [x] **SCHED-LOOP-001**: When the service starts, it shall run one backup cycle immediately before entering the interval loop.
- [x] **SCHED-LOOP-002**: When `BACKUP_INTERVAL_HOURS` is unset, the service shall use an interval of 12 hours.
- [x] **SCHED-LOOP-003**: If `BACKUP_INTERVAL_HOURS` is not an integer or is outside the range 1 to 8760, then the service shall log an error and exit with status 1 before running any backup cycle.
- [x] **SCHED-LOOP-004**: While no shutdown has been requested, the service shall wait `BACKUP_INTERVAL_HOURS` hours after each backup cycle and then run the next one.
- [x] **SCHED-LOOP-005**: If a backup cycle exits with a non-zero status or raises an exception, then the service shall log the failure and continue the schedule rather than terminating.
- [x] **SCHED-LOOP-006**: When a backup cycle returns normally or exits with status 0, the service shall log that the backup completed successfully.

## Signals and shutdown

- [x] **SCHED-SIGNAL-001**: When the service receives SIGTERM or SIGINT while waiting between cycles, it shall stop waiting within 1 second and exit without starting another backup cycle.
- [x] **SCHED-SIGNAL-002**: When the service receives SIGTERM or SIGINT during a backup cycle, it shall allow that cycle (and any due cleanup) to finish and then exit without starting another cycle.
- [x] **SCHED-SIGNAL-003**: When the service shuts down after a stop request, it shall log `Shutdown complete` and exit with status 0.

## Retention cleanup

- [x] **SCHED-RETAIN-001**: When `RETAIN_DAYS` is unset, the service shall use a retention period of 7 days.
- [x] **SCHED-RETAIN-002**: If `RETAIN_DAYS` is `0` or is not a non-negative integer, then the service shall skip cleanup and log that cleanup is skipped, without exiting.
- [x] **SCHED-RETAIN-003**: If `RETAIN_DAYS` is greater than 3650, then the service shall log an error and skip cleanup, without exiting.
- [x] **SCHED-RETAIN-004**: When a backup cycle completes and the local calendar date differs from the date recorded at the last cleanup check (or at startup), the service shall run cleanup once and record the current date.
- [x] **SCHED-RETAIN-005**: When cleanup runs, the service shall delete every entry in the backup directory that is a regular file, is not a symbolic link, has the suffix `.enc`, and has a modification time older than `RETAIN_DAYS` × 24 hours, and shall leave every other entry untouched.
- [x] **SCHED-RETAIN-006**: If the backup directory does not exist when cleanup runs, then the service shall log a warning and skip cleanup.
- [x] **SCHED-RETAIN-007**: When cleanup finishes, the service shall log the number of files removed.
- [ ] **SCHED-RETAIN-008**: Before cleanup deletes anything, the service shall verify that the backup directory resolves to a path under `/app` (the same containment rule the backup cycle applies before writing), and if it does not, then it shall log an error and skip cleanup.
