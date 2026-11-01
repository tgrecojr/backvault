# backup-cycle — EARS Specs

Prefix `CYCLE`. Facets: `CONFIG` (environment intake and validation), `FLOW` (ordering and outcome contract), `FILE` (naming and placement).

Status: `[x]` implemented and observed working in the Rust service · `[ ]` specified, not yet implemented or unverified · `[D]` deferred.

## Configuration

- [x] **CYCLE-CONFIG-001**: When a backup cycle starts, the backup cycle shall require `BW_CLIENT_ID`, `BW_CLIENT_SECRET`, `BW_PASSWORD`, `BW_SERVER`, and `BW_FILE_PASSWORD` to be set and non-empty, and if any is missing, then it shall fail the cycle with an error naming that variable before contacting the server.
- [x] **CYCLE-CONFIG-002**: When `BACKUP_DIR` is unset, the backup cycle shall use `/app/backups` as the backup directory.
- [x] **CYCLE-CONFIG-003**: If `BACKUP_DIR` canonicalises (after following symlinks) to a path outside `/app`, then the backup cycle shall fail the cycle with an error naming the resolved path, without contacting the server or writing anything; the check shall be the public function `cycle::confine_to_app`, which the supervisor reuses before cleanup.
- [x] **CYCLE-CONFIG-004**: When `BACKUP_ENCRYPTION_MODE` is unset or equals `raw` (case-insensitively, ignoring surrounding whitespace), the backup cycle shall produce a raw-mode backup (portable AES-256-GCM file).
- [x] **CYCLE-CONFIG-005**: If `BACKUP_ENCRYPTION_MODE` is set to any value other than `raw`, including `bitwarden`, then the backup cycle shall fail the cycle with an error explaining that only raw mode exists and how to restore a raw-mode file, without contacting the server.
- [x] **CYCLE-CONFIG-007**: When a backup cycle starts and the backup directory does not exist, the backup cycle shall create it with mode `0700`.
- [x] **CYCLE-CONFIG-008**: Where `BW_CA_CERT` is set, the backup cycle shall pass that path to the vault client as the additional CA bundle to trust, and if the file does not exist or is unreadable, then the backup cycle shall fail the cycle with an error naming the path before contacting the server.
- [x] **CYCLE-CONFIG-009**: If `NODE_TLS_REJECT_UNAUTHORIZED` is set, then the backup cycle shall log a WARNING stating that the variable has no effect and that `BW_CA_CERT` is the supported way to trust a self-signed server, and shall continue.
- [x] **CYCLE-CONFIG-010**: The backup cycle shall read `BW_PASSWORD` and `BW_FILE_PASSWORD` as raw operating-system bytes, shall pass them to the vault client and the encryptor unchanged (no UTF-8 validation, trimming, or normalisation), and shall hold them and `BW_CLIENT_SECRET` in zeroizing buffers for the life of the cycle.

## Flow and outcome contract

- [x] **CYCLE-FLOW-001**: A backup cycle shall validate configuration in the order required variables, `BACKUP_DIR`, `BACKUP_ENCRYPTION_MODE`, `BW_CA_CERT` (stopping at the first failure), then request the vault export from the vault client, then encrypt and write it; if the export request fails, then the backup cycle shall write nothing.
- [x] **CYCLE-FLOW-003**: If any step of the backup cycle fails, then the backup cycle shall return a `CycleError` whose display form names the failing variable, path, or underlying error and contains no secret; when the export, encryption, and write all succeed, the backup cycle shall return the path of the written file.
- [x] **CYCLE-FLOW-004**: The backup cycle shall encrypt the in-memory export with the backup file password using the backup-encryption format, shall drop the plaintext as soon as it is encrypted, and shall write only the ciphertext to the backup file; plaintext vault data shall not be written to disk.
- [x] **CYCLE-FLOW-005**: The backup cycle shall obtain the vault export through a `VaultExporter` trait and the filename timestamp through a `Clock` trait, so that every cycle behaviour is testable without a server or the system clock.

## File naming and placement

- [x] **CYCLE-FILE-001**: The backup cycle shall name each backup file `backup_YYYYMMDD_HHMMSS.enc` using UTC at the moment the name is generated.
- [x] **CYCLE-FILE-002**: Before writing a backup file, the backup cycle shall verify that the resolved path lies within the backup directory, that the final filename contains only ASCII letters, digits, `.`, `_`, and `-`, and that it ends with `.enc`; if any check fails, then it shall return an error and write nothing (the temporary name is the validated final name plus `.part`).
- [x] **CYCLE-FILE-003**: The backup cycle shall write the ciphertext to `<final name>.part` in the backup directory, created with mode `0600` and the create-new flag, shall sync it to disk, and shall then rename it to the final `.enc` name; if either the `.part` file or the final name already exists, then the backup cycle shall fail rather than overwrite, and a file shall carry the `.enc` suffix only once its contents are complete and durable.
