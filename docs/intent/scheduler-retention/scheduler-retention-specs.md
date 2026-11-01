# scheduler-retention — EARS Specs

Prefix `SCHED`. Facets: `LOG` (process-wide logging), `LOOP` (interval scheduling and failure tolerance), `SIGNAL` (shutdown), `RETAIN` (cleanup).

Status: `[x]` implemented and observed working in the Rust service · `[ ]` specified, not yet implemented or unverified · `[D]` deferred.

## Logging

- [x] **SCHED-LOG-001**: When the service starts without the `--version` argument, it shall install the process-wide log backend before validating configuration or running any cycle, writing one line per record as `YYYY-MM-DDTHH:MM:SSZ LEVEL message` to stdout.
- [x] **SCHED-LOG-002**: Where `LOG_FILE` is set, the service shall also append every log line to that file, creating it if absent; if the file cannot be opened, then the service shall log the failure to stdout and continue with stdout alone.

## Interval loop

- [x] **SCHED-LOOP-001**: When the service starts, it shall run one backup cycle immediately before entering the interval loop.
- [x] **SCHED-LOOP-002**: When `BACKUP_INTERVAL_HOURS` is unset, the service shall use an interval of 12 hours.
- [x] **SCHED-LOOP-003**: If `BACKUP_INTERVAL_HOURS` is not an integer or is outside the range 1 to 8760, then the service shall log an error and exit with status 1 before running any backup cycle.
- [x] **SCHED-LOOP-004**: While no shutdown has been requested, the service shall wait `BACKUP_INTERVAL_HOURS` hours after each backup cycle and then run the next one.
- [x] **SCHED-LOOP-005**: If a backup cycle returns an error or panics, then the service shall log the error or panic message at ERROR and continue the schedule rather than terminating.
- [x] **SCHED-LOOP-006**: When a backup cycle returns the path of a written backup, the service shall log that the backup completed successfully, naming the path.
- [x] **SCHED-LOOP-007**: The service shall run cycles through a `CycleRunner` trait, take dates and times from a `Clock` trait, and wait through a `Sleeper` trait, so that the loop, cleanup trigger, and shutdown behaviour are testable without real time.
- [x] **SCHED-LOOP-008**: When the service is invoked with `--version` as its only argument, it shall print its name and version to stdout and exit with status 0 without installing logging, reading configuration, or running a cycle.

## Signals and shutdown

- [x] **SCHED-SIGNAL-001**: When the service receives SIGTERM or SIGINT while waiting between cycles, it shall stop waiting within 1 second and exit without starting another backup cycle.
- [x] **SCHED-SIGNAL-002**: When the service receives SIGTERM or SIGINT during a backup cycle, it shall allow that cycle (and any due cleanup) to finish and then exit without starting another cycle.
- [x] **SCHED-SIGNAL-003**: When the service shuts down after a stop request, it shall log `Shutdown complete` and exit with status 0.

## Retention cleanup

- [x] **SCHED-RETAIN-001**: When `RETAIN_DAYS` is unset, the service shall use a retention period of 7 days.
- [x] **SCHED-RETAIN-002**: If `RETAIN_DAYS` is `0` or is not a non-negative integer, then the service shall skip cleanup and log that cleanup is skipped, without exiting.
- [x] **SCHED-RETAIN-003**: If `RETAIN_DAYS` is greater than 3650, then the service shall log an error and skip cleanup, without exiting.
- [x] **SCHED-RETAIN-004**: When a backup cycle completes and the UTC calendar date differs from the date recorded at the last cleanup check (or at startup), the service shall run cleanup once and record the current date.
- [x] **SCHED-RETAIN-005**: When cleanup runs, the service shall delete every entry in the backup directory that is a regular file, is not a symbolic link, has the suffix `.enc` or `.enc.part`, and has a modification time older than `RETAIN_DAYS` × 24 hours, and shall leave every other entry untouched.
- [x] **SCHED-RETAIN-006**: If the backup directory does not exist when cleanup runs, then the service shall log a warning and skip cleanup.
- [x] **SCHED-RETAIN-007**: When cleanup finishes, the service shall log the number of files removed.
- [x] **SCHED-RETAIN-008**: Before cleanup deletes anything, the service shall verify through the same containment function the backup cycle uses that the backup directory canonicalises to a path under `/app`, and if it does not, then it shall log an error and skip cleanup.
