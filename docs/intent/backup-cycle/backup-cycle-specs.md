# backup-cycle — EARS Specs

Prefix `CYCLE`. Facets: `CONFIG` (environment intake and validation), `FLOW` (ordering and exit contract), `FILE` (naming and placement).

Status: `[x]` implemented and observed working · `[ ]` specified, not yet implemented or unverified · `[D]` deferred.

## Configuration

- [x] **CYCLE-CONFIG-001**: When a backup cycle starts, the system shall require `BW_CLIENT_ID`, `BW_CLIENT_SECRET`, `BW_PASSWORD`, `BW_SERVER`, and `BW_FILE_PASSWORD` to be set and non-empty, and if any is missing, then it shall fail the cycle with an error naming that variable before contacting the server.
- [x] **CYCLE-CONFIG-002**: When `BACKUP_DIR` is unset, the backup cycle shall use `/app/backups` as the backup directory.
- [x] **CYCLE-CONFIG-003**: If `BACKUP_DIR` resolves (after following symlinks) to a path outside `/app`, then the backup cycle shall log a critical error and exit with status 1 without contacting the server or writing anything.
- [x] **CYCLE-CONFIG-004**: When `BACKUP_ENCRYPTION_MODE` is unset or equals `raw` (case-insensitively, ignoring surrounding whitespace), the backup cycle shall produce a raw-mode backup (portable AES-256-GCM file).
- [x] **CYCLE-CONFIG-005**: If `BACKUP_ENCRYPTION_MODE` is set to any value other than `raw`, including `bitwarden`, then the backup cycle shall log a critical error explaining that only raw mode exists and how to restore a raw-mode file, and exit with status 1 without contacting the server.
- [x] **CYCLE-CONFIG-006**: Where `LOG_FILE` is set, the backup cycle shall append its log records to that file in addition to stdout.
- [x] **CYCLE-CONFIG-007**: When a backup cycle starts and the backup directory does not exist, the system shall create it with mode `0700`.
- [x] **CYCLE-CONFIG-008**: Where `BW_CA_CERT` is set, the backup cycle shall pass that path to the vault client as the additional CA bundle to trust, and if the file does not exist or is unreadable, then the cycle shall fail with an error naming the path before contacting the server.
- [x] **CYCLE-CONFIG-009**: If `NODE_TLS_REJECT_UNAUTHORIZED` is set, then the backup cycle shall log a WARNING stating that the variable has no effect and that `BW_CA_CERT` is the supported way to trust a self-signed server, and shall continue.

## Flow and exit contract

- [x] **CYCLE-FLOW-001**: A backup cycle shall validate configuration in the order required variables, `BACKUP_DIR`, `BACKUP_ENCRYPTION_MODE`, `BW_CA_CERT` (stopping at the first failure), then request the vault export from the vault client, then encrypt and write it; if the export request fails, then the cycle shall write nothing.
- [x] **CYCLE-FLOW-003**: If the vault export fails, then the backup cycle shall log the failure and exit with status 1; when the export, encryption, and write all succeed, it shall exit with status 0.
- [x] **CYCLE-FLOW-004**: The backup cycle shall encrypt the in-memory export with the backup file password using the backup-encryption format and write only the ciphertext to the backup file; plaintext vault data shall not be written to disk.

## File naming and placement

- [x] **CYCLE-FILE-001**: The backup cycle shall name each backup file `backup_YYYYMMDD_HHMMSS.enc` using the container's local time at the moment the name is generated.
- [x] **CYCLE-FILE-002**: Before writing a backup file, the system shall verify that the resolved path lies within the backup directory, that the filename contains only ASCII letters, digits, `.`, `_`, and `-`, and that it ends with `.enc`; if any check fails, then it shall raise an error and write nothing.
